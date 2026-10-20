"""Append-only audit trail with an HMAC-SHA256 chain over canonicalised records.

The chain is tamper-EVIDENT against ordinary row modification/deletion/reordering by someone who
does not hold the HMAC key. It is not a substitute for external immutable (WORM) storage, an HSM/KMS
protected key, or off-host log shipping. See docs/architecture.md.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .models import AuditEvent

GENESIS = "0" * 64
_chain_lock = threading.Lock()  # single-process serialisation; use pg_advisory_xact_lock on PostgreSQL

SIGNED_FIELDS = (
    "event_id", "ts", "tenant_id", "actor_user_id", "actor_role", "event_type", "mode", "decision",
    "policy_id", "reason_codes", "tool", "resource_ids", "run_id", "risk", "details",
    "decision_latency_ms", "prev_hash",
)


def canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def _mac(record: dict[str, Any], key: str | None = None) -> str:
    k = (key or settings.audit_hmac_key).encode()
    return hmac.new(k, canonical(record), hashlib.sha256).hexdigest()


def _signed_view(ev: AuditEvent) -> dict[str, Any]:
    return {f: getattr(ev, f) for f in SIGNED_FIELDS}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def append_event(
    *,
    actor_user_id: str,
    actor_role: str,
    event_type: str,
    decision: str,
    policy_id: str,
    reason_codes: list[str] | None = None,
    tool: str | None = None,
    resource_ids: list[str] | None = None,
    run_id: str | None = None,
    risk: dict | None = None,
    details: dict | None = None,
    mode: str = "gated",
    tenant_id: str | None = None,
    decision_latency_ms: float | None = None,
) -> dict[str, Any]:
    """Append one event in its own transaction. Raises on failure so callers fail closed."""
    with _chain_lock:
        s: Session = SessionLocal()
        try:
            last = s.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).scalar_one_or_none()
            prev = last.record_hmac if last else GENESIS
            rec = {
                "event_id": f"evt_{uuid.uuid4().hex[:20]}",
                "ts": utcnow_iso(),
                "tenant_id": tenant_id or settings.tenant_id,
                "actor_user_id": actor_user_id,
                "actor_role": actor_role,
                "event_type": event_type,
                "mode": mode,
                "decision": decision,
                "policy_id": policy_id,
                "reason_codes": list(reason_codes or []),
                "tool": tool,
                "resource_ids": list(resource_ids or []),
                "run_id": run_id,
                "risk": risk or {},
                "details": details or {},
                "decision_latency_ms": None if decision_latency_ms is None else round(decision_latency_ms, 4),
                "prev_hash": prev,
            }
            ev = AuditEvent(**rec, record_hmac=_mac(rec))
            s.add(ev)
            s.commit()
            return {**rec, "seq": ev.seq, "record_hmac": ev.record_hmac}
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()


def verify_chain(session: Session, key: str | None = None) -> dict[str, Any]:
    events = session.execute(select(AuditEvent).order_by(AuditEvent.seq.asc())).scalars().all()
    prev = GENESIS
    expected_seq = None
    for ev in events:
        problems = []
        if expected_seq is not None and ev.seq != expected_seq:
            problems.append("SEQUENCE_GAP")
        if ev.prev_hash != prev:
            problems.append("PREV_HASH_MISMATCH")
        if not hmac.compare_digest(_mac(_signed_view(ev), key), ev.record_hmac):
            problems.append("HMAC_MISMATCH")
        if problems:
            return {
                "valid": False,
                "checked": len(events),
                "first_bad_seq": ev.seq,
                "first_bad_event_id": ev.event_id,
                "problems": problems,
                "verified_at": utcnow_iso(),
            }
        prev = ev.record_hmac
        expected_seq = ev.seq + 1
    return {
        "valid": True,
        "checked": len(events),
        "head_hmac": prev,
        "verified_at": utcnow_iso(),
        "scope_note": "Tamper-evident against row edits/deletes without the HMAC key; not WORM storage.",
    }


def event_to_dict(ev: AuditEvent) -> dict[str, Any]:
    return {**_signed_view(ev), "seq": ev.seq, "record_hmac": ev.record_hmac}
