"""Tool gateway. Every tool invocation (whether proposed by a user, a scenario or the simulated agent)
passes through execute_tool. Enforcement order is fixed and fails closed:

  1. tool name must be in the allowlist           -> else DENY UNKNOWN_TOOL
  2. role must be permitted for the tool          -> else DENY ROLE_NOT_PERMITTED
  3. arguments must pass the strict schema         -> else DENY SCHEMA_INVALID
  4. per-resource ACL / destination / ownership    -> else DENY
  5. tools needing approval create a pending state -> NEEDS_APPROVAL (never executed inline)
  6. only then does the side effect run (local simulator only)

The deterministic policy is the sole authority. The advisory risk score is computed for evidence but
is read AFTER the decision and cannot change it.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import policy
from .audit import append_event
from .config import settings
from .ml.risk import assess
from .models import Approval, Document, OutboxMessage, Report, SinkRecord
from .policy import Decision, TOOLS
from .security import Identity

CANARY = "LAB-CANARY-7731"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def canonical_args_sha(tool: str, args: dict[str, Any]) -> str:
    blob = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _redact(text: str) -> str:
    """Never let restricted content (or the canary) reach logs/sink previews."""
    return text.replace(CANARY, "[REDACTED-CANARY]")[:120]


@dataclass
class ToolResult:
    decision: str                      # ALLOW | DENY | NEEDS_APPROVAL
    policy_id: str
    reason_codes: list[str]
    resource_ids: list[str]
    output: dict[str, Any] | None
    explanation: str
    event: dict[str, Any]
    risk: dict[str, Any]
    approval_id: str | None = None
    decision_latency_ms: float = 0.0


def _advisory_text_for(db: Session, tool: str, args: dict[str, Any]) -> str:
    """Gather untrusted text relevant to this call for the advisory risk score only."""
    ids: list[str] = []
    if tool == "read_document":
        ids = [args.get("document_id", "")]
    elif tool in ("compare_quotations", "draft_purchase_summary"):
        ids = list(args.get("quote_ids", []))
    elif tool == "simulated_external_sink":
        return str(args.get("payload_summary", ""))
    chunks = []
    for did in ids:
        doc = db.get(Document, did)
        if doc and doc.trust_label == "untrusted_external":
            chunks.append(doc.content)
    return "\n".join(chunks)


def execute_tool(
    db: Session,
    identity: Identity,
    tool: str,
    raw_args: Any,
    *,
    mode: str = "gated",
    run_id: str | None = None,
    source: str = "user",
    idempotency_key: str | None = None,
) -> ToolResult:
    t0 = time.perf_counter()

    def finish(dec: Decision, output: dict | None, *, event_type: str, approval_id: str | None = None,
               extra: dict | None = None) -> ToolResult:
        latency = (time.perf_counter() - t0) * 1000.0
        risk = assess(_advisory_text_for(db, tool, raw_args if isinstance(raw_args, dict) else {}),
                      settings.model_dir)
        details = {"source": source, "args_fingerprint": canonical_args_sha(tool, raw_args) if isinstance(raw_args, dict) else None}
        if extra:
            details.update(extra)
        ev = append_event(
            actor_user_id=identity.user_id, actor_role=identity.role, event_type=event_type,
            decision=dec.decision, policy_id=dec.policy_id, reason_codes=dec.reason_codes, tool=tool,
            resource_ids=dec.resource_ids, run_id=run_id, mode=mode, tenant_id=identity.tenant_id,
            risk={"combined_score": risk["combined_score"], "band": risk["band"],
                  "heuristic_signals": [s["signal"] for s in risk["heuristic"]["signals"]],
                  "ml_available": risk["ml"].get("available", False)},
            details=details, decision_latency_ms=latency,
        )
        return ToolResult(dec.decision, dec.policy_id, dec.reason_codes, dec.resource_ids, output,
                          dec.explanation, ev, risk, approval_id, round(latency, 4))

    # 1. allowlist
    spec = TOOLS.get(tool)
    if spec is None:
        d = policy.deny("POL-TOOL-ALLOWLIST-v1", ["UNKNOWN_TOOL"], [],
                        f"'{tool}' is not a registered tool. Free-form tool names are never executed.")
        return finish(d, None, event_type="tool.denied")
    if spec.sensitivity == "forbidden":
        d = policy.deny(spec.policy_id, ["TOOL_FORBIDDEN"], [],
                        "simulated_external_sink is never callable through AMAN Gate.")
        return finish(d, None, event_type="tool.denied")

    # 2. RBAC
    if identity.role not in spec.allowed_roles:
        d = policy.deny("POL-RBAC-TOOLS-v1", ["ROLE_NOT_PERMITTED"], [],
                        f"Role '{identity.role}' may not call {tool}.")
        return finish(d, None, event_type="tool.denied")

    # 3. schema
    model, codes, why = policy.validate_args(spec, raw_args)
    if model is None:
        d = policy.deny("POL-SCHEMA-v1", codes, [], why)
        return finish(d, None, event_type="tool.denied")
    args = model.model_dump()

    # 4/5/6 per tool
    if tool == "read_document":
        dec, doc = policy.check_document_access(db, identity, args["document_id"])
        if not dec.allowed:
            return finish(dec, None, event_type="document.denied")
        out = {"document_id": doc.id, "title": doc.title, "doc_type": doc.doc_type,
               "classification": doc.classification, "trust_label": doc.trust_label,
               "sha256": doc.sha256, "content": doc.content}
        return finish(dec, out, event_type="document.read")

    if tool == "compare_quotations":
        dec, docs = policy.check_quotations(db, identity, args["quote_ids"])
        if not dec.allowed:
            return finish(dec, None, event_type="document.denied")
        rows = []
        for doc in docs:
            rows.append({"document_id": doc.id, "title": doc.title, "sha256": doc.sha256,
                         "figures": _extract_figures(doc.content)})
        return finish(dec, {"comparison": rows}, event_type="tool.compare_quotations")

    if tool == "draft_purchase_summary":
        dec, docs = policy.check_quotations(db, identity, args["quote_ids"])
        if not dec.allowed:
            return finish(dec, None, event_type="document.denied")
        report = _create_report(db, identity, docs, run_id)
        return finish(dec, {"report_id": report.id, "classification": report.classification,
                            "sha256": report.sha256, "body": report.body}, event_type="tool.draft_summary")

    if tool == "send_report":
        return _handle_send_report(db, identity, args, mode, run_id, idempotency_key, finish)

    # Should be unreachable (forbidden tool handled above); fail closed.
    d = policy.deny("POL-TOOL-ALLOWLIST-v1", ["UNHANDLED_TOOL"], [], "No handler; denied.")
    return finish(d, None, event_type="tool.denied")


def _extract_figures(content: str) -> dict[str, str]:
    figs: dict[str, str] = {}
    for line in content.splitlines():
        for key in ("Supplier", "Item", "Unit price", "Total price", "Delivery", "Warranty"):
            if line.strip().lower().startswith(key.lower() + ":"):
                figs[key] = line.split(":", 1)[1].strip()
    return figs


def _create_report(db: Session, identity: Identity, docs: list[Document], run_id: str | None) -> Report:
    lines = ["PURCHASE SUMMARY (DRAFT) - Northbridge University (synthetic lab data)",
             f"Prepared by: {identity.display_name}", ""]
    best = None
    for doc in docs:
        figs = _extract_figures(doc.content)
        lines.append(f"- {doc.id} {figs.get('Supplier', '')}: total {figs.get('Total price', 'n/a')}, "
                     f"warranty {figs.get('Warranty', 'n/a')}, delivery {figs.get('Delivery', 'n/a')}")
        tp = figs.get("Total price", "")
        digits = "".join(ch for ch in tp if ch.isdigit())
        if digits and (best is None or int(digits) < best[1]):
            best = (doc.id, int(digits))
    if best:
        lines += ["", f"Lowest total price: {best[0]}."]
    body = "\n".join(lines)
    rid = f"RPT-{uuid.uuid4().hex[:12]}"
    report = Report(id=rid, tenant_id=identity.tenant_id, owner_user_id=identity.user_id,
                    source_document_ids=[d.id for d in docs], classification="internal", body=body,
                    sha256=hashlib.sha256(body.encode()).hexdigest(), created_at=_now(), run_id=run_id)
    db.add(report)
    db.commit()
    return report


def _handle_send_report(db, identity, args, mode, run_id, idempotency_key, finish) -> ToolResult:
    destination = args["destination"]
    report_id = args["report_id"]
    # destination check
    dest_dec = policy.check_destination(destination)
    if not dest_dec.allowed:
        return finish(dest_dec, None, event_type="tool.denied")
    # report ownership + classification
    own_dec, report = policy.check_report_access(db, identity, report_id)
    if not own_dec.allowed:
        return finish(own_dec, None, event_type="tool.denied")
    # requires approval -> create pending; never send inline
    dec = Decision("NEEDS_APPROVAL", "POL-APPROVAL-SEND-v1", ["APPROVAL_REQUIRED"],
                   [report_id, f"dest:{destination.lower()}"],
                   "send_report requires approval by a finance manager other than the requester.")
    args_sha = canonical_args_sha("send_report", {"destination": destination.lower(), "report_id": report_id})
    # idempotency: same requester + same args returns the existing approval
    existing = db.execute(select(Approval).where(Approval.args_sha256 == args_sha,
                                                 Approval.requester_user_id == identity.user_id,
                                                 Approval.status.in_(["requested", "pending"]))).scalars().first()
    if existing:
        return finish(dec, {"approval_id": existing.id, "status": existing.status,
                            "expires_at": existing.expires_at.isoformat()},
                      event_type="approval.requested", approval_id=existing.id)
    ap = Approval(
        id=f"APR-{uuid.uuid4().hex[:12]}", tenant_id=identity.tenant_id, requester_user_id=identity.user_id,
        tool="send_report", args={"destination": destination.lower(), "report_id": report_id}, args_sha256=args_sha,
        status="pending", required_role="finance_manager", idempotency_key=idempotency_key or uuid.uuid4().hex,
        created_at=_now(), expires_at=_now() + timedelta(seconds=settings.approval_ttl_seconds), run_id=run_id,
        history=[{"status": "pending", "by": identity.user_id, "at": _now().isoformat()}],
    )
    db.add(ap)
    db.commit()
    return finish(dec, {"approval_id": ap.id, "status": ap.status, "expires_at": ap.expires_at.isoformat(),
                        "required_role": ap.required_role},
                  event_type="approval.requested", approval_id=ap.id)


# ---------------------------------------------------------------- approval lifecycle
def expire_due(db: Session) -> int:
    due = db.execute(select(Approval).where(Approval.status.in_(["requested", "pending"]),
                                            Approval.expires_at < _now())).scalars().all()
    for ap in due:
        ap.status = "expired"
        ap.history = ap.history + [{"status": "expired", "at": _now().isoformat()}]
    if due:
        db.commit()
        for ap in due:
            append_event(actor_user_id="system", actor_role="security_analyst", event_type="approval.expired",
                         decision="EXPIRED", policy_id="POL-APPROVAL-SEND-v1", reason_codes=["APPROVAL_EXPIRED"],
                         tool="send_report", resource_ids=[ap.args["report_id"]], run_id=ap.run_id, mode="system",
                         details={"approval_id": ap.id})
    return len(due)


def decide_approval(db: Session, approver: Identity, approval_id: str, approve: bool, note: str | None) -> dict:
    expire_due(db)
    ap = db.get(Approval, approval_id)
    if ap is None or ap.tenant_id != approver.tenant_id:
        raise GatewayError(404, "APPROVAL_NOT_FOUND", "No such approval.")
    if approver.role != ap.required_role:
        _audit_approval(ap, "DENY", ["APPROVER_ROLE_INVALID"], approver, "approval.decision_blocked")
        raise GatewayError(403, "APPROVER_ROLE_INVALID", "Only a finance_manager may decide this approval.")
    # Two-person rule: requester may not approve their own request.
    if approve and ap.requester_user_id == approver.user_id:
        _audit_approval(ap, "DENY", ["SELF_APPROVAL_BLOCKED"], approver, "approval.decision_blocked")
        raise GatewayError(403, "SELF_APPROVAL_BLOCKED", "The requester cannot approve their own send.")
    if ap.status != "pending":
        raise GatewayError(409, "APPROVAL_NOT_PENDING", f"Approval is '{ap.status}', not pending.")
    ap.status = "approved" if approve else "denied"
    ap.decided_by_user_id = approver.user_id
    ap.decision_note = (note or "")[:256]
    ap.decided_at = _now()
    ap.history = ap.history + [{"status": ap.status, "by": approver.user_id, "at": _now().isoformat()}]
    db.commit()
    _audit_approval(ap, "ALLOW" if approve else "DENY",
                    ["APPROVAL_GRANTED"] if approve else ["APPROVAL_DENIED"], approver, "approval.decided")
    return _approval_dict(ap)


def execute_approved(db: Session, actor: Identity, approval_id: str) -> dict:
    """Execute an approved send exactly once. Compare-and-set guards against replay and races."""
    expire_due(db)
    ap = db.get(Approval, approval_id)
    if ap is None or ap.tenant_id != actor.tenant_id:
        raise GatewayError(404, "APPROVAL_NOT_FOUND", "No such approval.")
    if ap.requester_user_id != actor.user_id:
        raise GatewayError(403, "NOT_REQUESTER", "Only the original requester may execute the approved send.")
    if ap.status == "executed":
        raise GatewayError(409, "ALREADY_EXECUTED", "This approval was already executed.")
    if ap.status != "approved":
        raise GatewayError(409, "NOT_APPROVED", f"Approval is '{ap.status}', not approved.")
    # Atomic compare-and-set: UPDATE ... WHERE status='approved'
    updated = db.query(Approval).filter(Approval.id == ap.id, Approval.status == "approved").update(
        {"status": "executed", "executed_at": _now()}, synchronize_session=False)
    db.commit()
    if updated != 1:
        raise GatewayError(409, "ALREADY_EXECUTED", "Lost the execution race; nothing sent.")
    db.refresh(ap)
    ap.history = ap.history + [{"status": "executed", "by": actor.user_id, "at": _now().isoformat()}]
    report = db.get(Report, ap.args["report_id"])
    # Re-check ownership/classification at execution time (defence in depth).
    own_dec, _ = policy.check_report_access(db, actor, ap.args["report_id"])
    if not own_dec.allowed:
        raise GatewayError(409, "REPORT_STATE_CHANGED", "Report is no longer sendable.")
    msg = OutboxMessage(mode="gated", destination=ap.args["destination"], report_id=report.id,
                        report_sha256=report.sha256, approval_id=ap.id, run_id=ap.run_id, created_at=_now())
    db.add(msg)
    db.commit()
    append_event(actor_user_id=actor.user_id, actor_role=actor.role, event_type="tool.send_report.executed",
                 decision="ALLOW", policy_id="POL-APPROVAL-SEND-v1", reason_codes=["SEND_EXECUTED_LOCAL_SIM"],
                 tool="send_report", resource_ids=[report.id, f"dest:{ap.args['destination']}"], run_id=ap.run_id,
                 mode="gated", details={"approval_id": ap.id, "outbox_id": msg.id,
                                        "note": "Delivered to local simulator only; no network."})
    return {"approval_id": ap.id, "status": "executed", "outbox_id": msg.id,
            "destination": ap.args["destination"], "delivered": "local-simulator"}


def _approval_dict(ap: Approval) -> dict:
    return {"approval_id": ap.id, "tool": ap.tool, "args": ap.args, "status": ap.status,
            "requester_user_id": ap.requester_user_id, "required_role": ap.required_role,
            "decided_by_user_id": ap.decided_by_user_id, "decision_note": ap.decision_note,
            "created_at": ap.created_at.isoformat(), "expires_at": ap.expires_at.isoformat(),
            "decided_at": ap.decided_at.isoformat() if ap.decided_at else None,
            "executed_at": ap.executed_at.isoformat() if ap.executed_at else None,
            "run_id": ap.run_id, "history": ap.history}


def _audit_approval(ap: Approval, decision: str, codes: list[str], actor: Identity, event_type: str) -> None:
    append_event(actor_user_id=actor.user_id, actor_role=actor.role, event_type=event_type, decision=decision,
                 policy_id="POL-APPROVAL-SEND-v1", reason_codes=codes, tool="send_report",
                 resource_ids=[ap.args["report_id"]], run_id=ap.run_id, mode="gated",
                 details={"approval_id": ap.id})


class GatewayError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def record_sink(db: Session, mode: str, run_id: str | None, payload: str, resource_ids: list[str]) -> SinkRecord:
    rec = SinkRecord(mode=mode, run_id=run_id, payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
                     payload_chars=len(payload), contained_resource_ids=resource_ids,
                     redacted_preview=_redact(payload), created_at=_now())
    db.add(rec)
    db.commit()
    return rec
