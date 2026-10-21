"""Persistence for privacy decision records. Own table on the shared declarative Base; the global
bootstrap is untouched. Call create_privacy_schema() to create it. A stored row holds the versioned
decision record (no raw values) and digests, never the original document or a rehydration table."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import Base, engine

from .sanitize import SafeArtifact


class PrivacyDecision(Base):
    __tablename__ = "privacy_decisions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    actor_user_id: Mapped[str] = mapped_column(String(64))
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    task: Mapped[str | None] = mapped_column(String(256), nullable=True)
    destination: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_class: Mapped[str] = mapped_column(String(16))
    policy_id: Mapped[str] = mapped_column(String(64))
    record_version: Mapped[str] = mapped_column(String(48))
    export_status: Mapped[str] = mapped_column(String(24), index=True)
    source_sha256: Mapped[str] = mapped_column(String(64))
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    element_count: Mapped[int] = mapped_column(Integer)
    max_sensitivity: Mapped[str] = mapped_column(String(16))
    record: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime)


def create_privacy_schema() -> None:
    """Create only this module's table (idempotent)."""
    Base.metadata.create_all(engine, tables=[PrivacyDecision.__table__])


def store_decision(session: Session, artifact: SafeArtifact, *, tenant_id: str, actor_user_id: str) -> PrivacyDecision:
    rec = artifact.decision_record
    row = PrivacyDecision(
        id=f"PD-{uuid.uuid4().hex[:16]}", tenant_id=tenant_id, actor_user_id=actor_user_id,
        role=rec["request"]["role"], task=(rec["request"]["task"] or "")[:256] or None,
        destination=rec["request"]["destination"], destination_class=rec["request"]["destination_class"],
        policy_id=rec["policy"]["policy_id"], record_version=rec["record_version"],
        export_status=artifact.export_status, source_sha256=rec["source"]["sha256"],
        artifact_sha256=artifact.sha256, element_count=rec["summary"]["elements_found"],
        max_sensitivity=rec["summary"]["max_sensitivity"], record=rec,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    session.add(row)
    session.commit()
    return row
