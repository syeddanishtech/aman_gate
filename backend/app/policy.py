"""Deterministic policy: tool allowlist, strict argument schemas, RBAC, document ACL and destination rules.

Nothing in here consults the language model or the advisory ML risk score. Every function either
returns an explicit Decision or raises; unknown situations resolve to DENY (fail closed).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Document, DocumentACL, Report
from .security import Identity

POLICY_VERSION = "aman-policy-2026.10-v1"

DocId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]{1,15}(-[A-Z0-9]{1,15}){1,4}$", max_length=64)]
ReportId = Annotated[str, StringConstraints(pattern=r"^RPT-[0-9a-f]{12}$")]
Email = Annotated[str, StringConstraints(pattern=r"^[a-z0-9._-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$", max_length=200)]

# Only these local-simulated recipients may ever receive a report. example.test is explicitly unapproved.
ALLOWED_DESTINATIONS: dict[str, str] = {
    "finance-approvals@university.test": "Finance approvals desk (local simulator)",
    "procurement-records@university.test": "Procurement records archive (local simulator)",
}
EXPLICITLY_UNAPPROVED_DOMAINS = ("example.test",)

MAX_JSON_DEPTH = 4
MAX_JSON_BYTES = 8_192


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ReadDocumentArgs(_Strict):
    document_id: DocId


class CompareQuotationsArgs(_Strict):
    quote_ids: list[DocId] = Field(min_length=2, max_length=5)

    @field_validator("quote_ids")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("quote_ids must be unique")
        return v


class DraftPurchaseSummaryArgs(_Strict):
    quote_ids: list[DocId] = Field(min_length=1, max_length=5)

    @field_validator("quote_ids")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("quote_ids must be unique")
        return v


class SendReportArgs(_Strict):
    destination: Email
    report_id: ReportId


class SimulatedExternalSinkArgs(_Strict):
    payload_summary: str = Field(max_length=4000)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    args_model: type[_Strict]
    allowed_roles: frozenset[str]
    requires_approval: bool
    approver_role: str | None
    sensitivity: Literal["low", "medium", "high", "forbidden"]
    description: str
    policy_id: str


TOOLS: dict[str, ToolSpec] = {
    t.name: t
    for t in [
        ToolSpec("read_document", ReadDocumentArgs,
                 frozenset({"procurement_officer", "junior_clerk", "finance_manager", "security_analyst"}),
                 False, None, "low", "Read one document after a per-user ACL check.", "POL-DOC-ACL-v1"),
        ToolSpec("compare_quotations", CompareQuotationsArgs,
                 frozenset({"procurement_officer", "junior_clerk", "finance_manager"}),
                 False, None, "low", "Compare 2-5 supplier quotations (quotation documents only).", "POL-RBAC-TOOLS-v1"),
        ToolSpec("draft_purchase_summary", DraftPurchaseSummaryArgs,
                 frozenset({"procurement_officer", "finance_manager"}),
                 False, None, "medium", "Draft a purchase summary from quotation documents only.", "POL-RBAC-TOOLS-v1"),
        ToolSpec("send_report", SendReportArgs,
                 frozenset({"procurement_officer", "finance_manager"}),
                 True, "finance_manager", "high",
                 "Send an owned report to an allowlisted university.test recipient (local simulator) "
                 "after approval by a different finance manager.", "POL-APPROVAL-SEND-v1"),
        ToolSpec("simulated_external_sink", SimulatedExternalSinkArgs,
                 frozenset(),  # no role may call it through the gateway
                 False, None, "forbidden", "Lab-only exfiltration recorder. Always denied by AMAN Gate.",
                 "POL-SINK-DENY-v1"),
    ]
}


@dataclass
class Decision:
    decision: Literal["ALLOW", "DENY", "NEEDS_APPROVAL"]
    policy_id: str
    reason_codes: list[str]
    resource_ids: list[str] = field(default_factory=list)
    explanation: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


def deny(policy_id: str, codes: list[str], resources: list[str] | None = None, why: str = "") -> Decision:
    return Decision("DENY", policy_id, codes, resources or [], why)


def json_shape_ok(raw: Any) -> tuple[bool, str]:
    """Reject deeply nested / oversized payloads before schema validation."""
    try:
        blob = json.dumps(raw)
    except (TypeError, ValueError):
        return False, "ARGS_NOT_JSON"
    if len(blob.encode()) > MAX_JSON_BYTES:
        return False, "ARGS_TOO_LARGE"

    def depth(o: Any, d: int = 0) -> int:
        if d > MAX_JSON_DEPTH + 1:
            return d
        if isinstance(o, dict):
            return max([depth(v, d + 1) for v in o.values()] or [d + 1])
        if isinstance(o, list):
            return max([depth(v, d + 1) for v in o] or [d + 1])
        return d

    if depth(raw) > MAX_JSON_DEPTH:
        return False, "ARGS_TOO_DEEP"
    return True, ""


def validate_args(spec: ToolSpec, raw: Any) -> tuple[_Strict | None, list[str], str]:
    if not isinstance(raw, dict):
        return None, ["SCHEMA_INVALID", "ARGS_NOT_OBJECT"], "Arguments must be a JSON object."
    ok, code = json_shape_ok(raw)
    if not ok:
        return None, ["SCHEMA_INVALID", code], "Argument payload rejected before parsing."
    try:
        return spec.args_model.model_validate(raw), [], ""
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) or "<root>" for e in exc.errors()})
        return None, ["SCHEMA_INVALID"], f"Invalid fields: {', '.join(fields)}"


# ---------------------------------------------------------------- resource checks
def _principals(identity: Identity) -> list[str]:
    return [f"role:{identity.role}", f"user:{identity.user_id}"]


def check_document_access(db: Session, identity: Identity, doc_id: str) -> tuple[Decision, Document | None]:
    """ACL check against the canonical resource id. Cross-tenant and non-existent ids are indistinguishable."""
    doc = db.get(Document, doc_id)
    if doc is None or doc.tenant_id != identity.tenant_id:
        return deny("POL-DOC-ACL-v1", ["RESOURCE_NOT_ACCESSIBLE"], [doc_id],
                    "Document does not exist in your tenant."), None
    granted = db.execute(
        select(DocumentACL.id).where(
            DocumentACL.document_id == doc.id,
            DocumentACL.permission == "read",
            DocumentACL.principal.in_(_principals(identity)),
        )
    ).first()
    if not granted:
        return deny("POL-DOC-ACL-v1", ["ACL_DENIED"], [doc.id],
                    f"Role '{identity.role}' has no read grant on {doc.id} ({doc.classification})."), doc
    return Decision("ALLOW", "POL-DOC-ACL-v1", ["ACL_GRANTED"], [doc.id]), doc


def check_quotations(db: Session, identity: Identity, quote_ids: list[str]) -> tuple[Decision, list[Document]]:
    docs: list[Document] = []
    denied_codes: list[str] = []
    denied_ids: list[str] = []
    for qid in quote_ids:
        d, doc = check_document_access(db, identity, qid)
        if not d.allowed:
            denied_codes += d.reason_codes
            denied_ids.append(qid)
            continue
        if doc.doc_type != "quotation":
            denied_codes.append("DOC_TYPE_NOT_QUOTATION")
            denied_ids.append(qid)
            continue
        docs.append(doc)
    if denied_ids:
        return deny("POL-DOC-ACL-v1", sorted(set(denied_codes)), denied_ids,
                    "Every referenced document must be a quotation the caller may read."), []
    return Decision("ALLOW", "POL-DOC-ACL-v1", ["ACL_GRANTED"], quote_ids), docs


def check_destination(destination: str) -> Decision:
    dest = destination.strip().lower()
    if dest in ALLOWED_DESTINATIONS:
        return Decision("ALLOW", "POL-DEST-ALLOWLIST-v1", ["DEST_ALLOWLISTED"], [f"dest:{dest}"])
    codes = ["DEST_NOT_ALLOWLISTED"]
    if dest.split("@")[-1].endswith(EXPLICITLY_UNAPPROVED_DOMAINS):
        codes.append("DEST_EXPLICITLY_UNAPPROVED_DOMAIN")
    return deny("POL-DEST-ALLOWLIST-v1", codes, [f"dest:{dest}"],
                "Only allowlisted university.test recipients (local simulator) are permitted.")


def check_report_access(db: Session, identity: Identity, report_id: str) -> tuple[Decision, Report | None]:
    rep = db.get(Report, report_id)
    if rep is None or rep.tenant_id != identity.tenant_id or rep.owner_user_id != identity.user_id:
        return deny("POL-REPORT-OWNER-v1", ["REPORT_NOT_ACCESSIBLE"], [report_id],
                    "Report does not exist or is not owned by the caller."), None
    if rep.classification != "internal":
        return deny("POL-REPORT-OWNER-v1", ["REPORT_CLASSIFICATION_BLOCKED"], [report_id],
                    "Only internal-classification summaries may leave the drafting workspace."), rep
    return Decision("ALLOW", "POL-REPORT-OWNER-v1", ["REPORT_OWNED"], [report_id]), rep


def describe_policies() -> list[dict[str, Any]]:
    return [
        {"policy_id": "POL-TOOL-ALLOWLIST-v1", "title": "Tool allowlist",
         "rule": "Only the five registered tools exist. Any other tool name is denied (UNKNOWN_TOOL).",
         "tools": list(TOOLS)},
        {"policy_id": "POL-SCHEMA-v1", "title": "Strict argument schemas",
         "rule": f"Pydantic strict mode, extra fields forbidden, max depth {MAX_JSON_DEPTH}, "
                 f"max {MAX_JSON_BYTES} bytes, canonical id patterns."},
        {"policy_id": "POL-RBAC-TOOLS-v1", "title": "Role-to-tool permissions",
         "rule": "Role is read from the database for every call; token claims and client headers are ignored.",
         "matrix": {t.name: sorted(t.allowed_roles) for t in TOOLS.values()}},
        {"policy_id": "POL-DOC-ACL-v1", "title": "Per-user document ACL",
         "rule": "Checked before every retrieval, including retrievals requested inside other tools. "
                 "Cross-tenant ids look identical to non-existent ids."},
        {"policy_id": "POL-DEST-ALLOWLIST-v1", "title": "Destination allowlist",
         "rule": "Reports may only go to allowlisted university.test recipients in the local simulator. "
                 "example.test is explicitly unapproved.", "allowed": ALLOWED_DESTINATIONS},
        {"policy_id": "POL-REPORT-OWNER-v1", "title": "Report ownership",
         "rule": "Only the drafting user may send a report; only internal-classification reports may be sent."},
        {"policy_id": "POL-APPROVAL-SEND-v1", "title": "Two-person approval for send_report",
         "rule": "send_report creates a pending approval bound to the exact arguments. A different "
                 "finance_manager must approve before expiry; execution happens once (compare-and-set)."},
        {"policy_id": "POL-SINK-DENY-v1", "title": "External sink forbidden",
         "rule": "simulated_external_sink is never callable through the gateway, for any role."},
        {"policy_id": "ADVISORY-RISK-v1", "title": "Advisory injection risk (non-enforcing)",
         "rule": "ML + heuristic scores are shown to analysts but never change an allow/deny decision."},
    ]
