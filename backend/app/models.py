"""ORM models. ACLs live in their own table and are never populated from user-supplied metadata."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    password_hash: Mapped[str] = mapped_column(String(256))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # canonical resource id
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    title: Mapped[str] = mapped_column(String(256))
    doc_type: Mapped[str] = mapped_column(String(32))  # quotation | budget | policy | upload
    classification: Mapped[str] = mapped_column(String(32))  # internal | restricted | supplier
    trust_label: Mapped[str] = mapped_column(String(32))  # untrusted_external | trusted_internal
    content: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32), default="seed")  # seed | upload
    owner_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    lab_fixture: Mapped[bool] = mapped_column(Boolean, default=False)


class DocumentACL(Base):
    """Server-side ACL. principal is either 'role:<role>' or 'user:<user_id>'."""

    __tablename__ = "document_acl"
    __table_args__ = (UniqueConstraint("document_id", "principal", "permission"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    principal: Mapped[str] = mapped_column(String(96))
    permission: Mapped[str] = mapped_column(String(16), default="read")


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64))
    owner_user_id: Mapped[str] = mapped_column(String(64))
    source_document_ids: Mapped[list] = mapped_column(JSON)
    classification: Mapped[str] = mapped_column(String(32))
    body: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64))
    requester_user_id: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(64))
    args: Mapped[dict] = mapped_column(JSON)  # canonical, validated args bound to this approval
    args_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), index=True)  # requested|pending|approved|denied|expired|executed
    required_role: Mapped[str] = mapped_column(String(32))
    decided_by_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(String(256), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    history: Mapped[list] = mapped_column(JSON, default=list)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency"
    key: Mapped[str] = mapped_column(String(160), primary_key=True)  # user_id + client key
    request_sha256: Mapped[str] = mapped_column(String(64))
    response: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class OutboxMessage(Base):
    """Local-only simulated mail outbox. Nothing is ever transmitted."""

    __tablename__ = "sim_outbox"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mode: Mapped[str] = mapped_column(String(16))  # gated | baseline
    destination: Mapped[str] = mapped_column(String(256))
    report_id: Mapped[str] = mapped_column(String(64))
    report_sha256: Mapped[str] = mapped_column(String(64))
    approval_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class SinkRecord(Base):
    """Local-only simulated 'external sink' recorder used to show what an exfiltration *would* carry."""

    __tablename__ = "sim_sink"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mode: Mapped[str] = mapped_column(String(16))
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    payload_chars: Mapped[int] = mapped_column(Integer)
    contained_resource_ids: Mapped[list] = mapped_column(JSON)
    redacted_preview: Mapped[str] = mapped_column(String(160))
    created_at: Mapped[datetime] = mapped_column(DateTime)


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pair_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # baseline + gated share a pair id
    mode: Mapped[str] = mapped_column(String(16))
    actor_user_id: Mapped[str] = mapped_column(String(64))
    input_sha256: Mapped[str] = mapped_column(String(64))
    input: Mapped[dict] = mapped_column(JSON)
    snapshot: Mapped[dict] = mapped_column(JSON)
    summary: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    duration_ms: Mapped[float] = mapped_column(Float)


class AuditEvent(Base):
    """Append-only, HMAC-chained. Never stores full protected document content."""

    __tablename__ = "audit_events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True)
    ts: Mapped[str] = mapped_column(String(40))  # ISO-8601 UTC, part of the signed record
    tenant_id: Mapped[str] = mapped_column(String(64))
    actor_user_id: Mapped[str] = mapped_column(String(64))
    actor_role: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    mode: Mapped[str] = mapped_column(String(16))  # gated | baseline | system
    decision: Mapped[str] = mapped_column(String(24), index=True)  # ALLOW | DENY | NEEDS_APPROVAL | INFO | ...
    policy_id: Mapped[str] = mapped_column(String(64))
    reason_codes: Mapped[list] = mapped_column(JSON)
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_ids: Mapped[list] = mapped_column(JSON)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    risk: Mapped[dict] = mapped_column(JSON)
    details: Mapped[dict] = mapped_column(JSON)
    decision_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    record_hmac: Mapped[str] = mapped_column(String(64))
