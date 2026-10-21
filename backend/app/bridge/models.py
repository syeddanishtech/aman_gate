"""Persistence for artifacts the bridge may send. Own table on the shared declarative Base; the global
bootstrap is untouched. Call create_bridge_schema() to create it (db.create_schema() also creates it once
this module has been imported, because the table is on the shared Base).

WP1's PrivacyDecision row holds the decision record but not the sanitized text, so the bridge keeps its own
copy of exactly what may be sent. A row is only ever written by register_artifact(), which accepts nothing but
a WP1 SafeArtifact that was exported AND passes the independent verifier again right now. The row is sealed
with an HMAC keyed from the server secret over its identity, owner, digests and decision record, so a row that
was inserted or edited outside register_artifact() is detected when it is loaded and never reaches the guard.

What is stored: sanitized text, its digest, the decision record (no raw values), who owns it. What is never
stored: the original document, the source graph, the rehydration table.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.config import settings
from app.db import Base, engine
from app.privacy.graph import canonical_json
from app.privacy.pipeline import finalize
from app.privacy.policy import DEFAULT_POLICY, EXPORT_ALLOWED
from app.privacy.sanitize import SafeArtifact, sha256_text

from . import codes

SEAL_DOMAIN = b"aman-gate/bridge/artifact-seal/v1"


class BridgeArtifact(Base):
    __tablename__ = "bridge_artifacts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    owner_user_id: Mapped[str] = mapped_column(String(64), index=True)
    privacy_decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # WP1 PrivacyDecision.id
    export_status: Mapped[str] = mapped_column(String(24))
    text: Mapped[str] = mapped_column(Text)  # sanitized text only
    sha256: Mapped[str] = mapped_column(String(64))
    source_sha256: Mapped[str] = mapped_column(String(64))
    destination: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_class: Mapped[str] = mapped_column(String(16))
    policy_id: Mapped[str] = mapped_column(String(64))
    record: Mapped[dict] = mapped_column(JSON)  # versioned decision record, no raw values
    seal: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime)


def create_bridge_schema() -> None:
    """Create only this module's table (idempotent)."""
    Base.metadata.create_all(engine, tables=[BridgeArtifact.__table__])


class ArtifactRefused(Exception):
    """Registration was refused. `reasons` are reason codes, never content."""

    def __init__(self, reasons: list[str] | tuple[str, ...]):
        self.reasons = tuple(reasons)
        super().__init__(", ".join(self.reasons))


class ArtifactIntegrityError(Exception):
    """A stored row does not carry a valid seal: it was not written by register_artifact() or was altered."""

    reasons = (codes.ARTIFACT_SEAL_INVALID,)


@dataclass(frozen=True)
class LoadedArtifact:
    artifact_id: str
    artifact: SafeArtifact  # rebuilt from the row: no source graph, no rehydration table
    owner_user_id: str
    tenant_id: str
    destination_class: str
    created_at: datetime


# ---------------------------------------------------------------------------------------------- seal
def _seal_key() -> bytes:
    return hmac.new(settings.audit_hmac_key.encode(), SEAL_DOMAIN, hashlib.sha256).digest()


def compute_seal(*, artifact_id: str, tenant_id: str, owner_user_id: str, export_status: str, sha256: str,
                 source_sha256: str, destination_class: str, record: dict[str, Any]) -> str:
    body = canonical_json({
        "id": artifact_id, "tenant_id": tenant_id, "owner_user_id": owner_user_id, "export_status": export_status,
        "sha256": sha256, "source_sha256": source_sha256, "destination_class": destination_class,
        "record_sha256": sha256_text(canonical_json(record)),
    })
    return hmac.new(_seal_key(), body.encode("utf-8"), hashlib.sha256).hexdigest()


def _row_seal(row: BridgeArtifact) -> str:
    return compute_seal(artifact_id=row.id, tenant_id=row.tenant_id, owner_user_id=row.owner_user_id,
                        export_status=row.export_status, sha256=row.sha256, source_sha256=row.source_sha256,
                        destination_class=row.destination_class, record=row.record)


# ---------------------------------------------------------------------------------------------- write
def register_artifact(session: Session, artifact: object, *, tenant_id: str, actor_user_id: str,
                      privacy_decision_id: str | None = None) -> BridgeArtifact:
    """Store a sanitized artifact so it can be sent. Fails closed with ArtifactRefused unless `artifact` is a WP1
    SafeArtifact that was exported and that the independent verifier passes HERE, whatever ran before: WP1's
    finalize() runs the verifier again and folds its verdict into the stored record. That needs the in-memory
    source graph which protect_text / protect_document attach; an artifact without it cannot be verified and is
    refused."""
    if not isinstance(artifact, SafeArtifact):
        raise ArtifactRefused([codes.PAYLOAD_NOT_SAFE_ARTIFACT])
    if not artifact.export_allowed:
        raise ArtifactRefused([codes.ARTIFACT_NOT_EXPORTABLE])
    try:
        artifact = finalize(artifact, DEFAULT_POLICY)
    except Exception:  # a malformed artifact is never stored
        raise ArtifactRefused([codes.ARTIFACT_NOT_VERIFIED])
    if not artifact.export_allowed:  # the verifier failed: finalize() turns that into EXPORT_BLOCKED
        raise ArtifactRefused([codes.ARTIFACT_NOT_VERIFIED])
    record = artifact.decision_record
    try:
        digest_ok = sha256_text(artifact.text) == artifact.sha256 == record["artifact"]["sha256"]
        request = record["request"]
        dest_class = request["destination_class"]
        source_sha = record["source"]["sha256"]
        policy_id = record["policy"]["policy_id"]
        destination = request.get("destination")
        record_ok = record.get("export_status") == EXPORT_ALLOWED and dest_class in ("LOCAL", "EXTERNAL")
    except (KeyError, TypeError, AttributeError):
        raise ArtifactRefused([codes.ARTIFACT_RECORD_INVALID])
    if not record_ok:
        raise ArtifactRefused([codes.ARTIFACT_RECORD_INVALID])
    if not digest_ok:
        raise ArtifactRefused([codes.ARTIFACT_DIGEST_MISMATCH])

    artifact_id = f"SA-{uuid.uuid4().hex[:16]}"
    row = BridgeArtifact(
        id=artifact_id, tenant_id=tenant_id, owner_user_id=actor_user_id, privacy_decision_id=privacy_decision_id,
        export_status=artifact.export_status, text=artifact.text, sha256=artifact.sha256, source_sha256=source_sha,
        destination=destination if isinstance(destination, str) else None, destination_class=dest_class,
        policy_id=policy_id, record=record,
        seal=compute_seal(artifact_id=artifact_id, tenant_id=tenant_id, owner_user_id=actor_user_id,
                          export_status=artifact.export_status, sha256=artifact.sha256, source_sha256=source_sha,
                          destination_class=dest_class, record=record),
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    session.add(row)
    session.commit()
    return row


# ---------------------------------------------------------------------------------------------- read
def load_artifact(session: Session, artifact_id: str, *, tenant_id: str, owner_user_id: str) -> LoadedArtifact | None:
    """The caller's own artifact, or None. A row that belongs to someone else (another tenant or another user)
    is indistinguishable from a missing one. Raises ArtifactIntegrityError if the row's seal does not hold."""
    row = session.get(BridgeArtifact, artifact_id)
    if row is None or row.tenant_id != tenant_id or row.owner_user_id != owner_user_id:
        return None
    if not hmac.compare_digest(_row_seal(row), row.seal):
        raise ArtifactIntegrityError()
    artifact = SafeArtifact(row.export_status, row.text, row.sha256, row.record)
    return LoadedArtifact(row.id, artifact, row.owner_user_id, row.tenant_id, row.destination_class, row.created_at)
