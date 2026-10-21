"""Persistence for the local token vault (WP3). Two tables on the shared declarative Base; the global
bootstrap is untouched, so call create_vault_schema() (the assurance router does this lazily).

A row never holds an original value in the clear: `vault_entries.ciphertext` is AES-256-GCM output (see
vault.py). The session row carries the per-session HKDF salt (not secret) and the list of placeholders
that were issued for the artifact (content-free by construction: [PERSON_01], [REDACTED:BUDGET_FIGURE]).
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, engine


class VaultSession(Base):
    """One vaulted artifact: who it was issued to, for which purpose, and which placeholders exist."""

    __tablename__ = "vault_sessions"
    session_id: Mapped[str] = mapped_column(String(40), primary_key=True)  # "VS-" + 128 random bits
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    owner_user_id: Mapped[str] = mapped_column(String(64))
    owner_role: Mapped[str] = mapped_column(String(32))
    purpose: Mapped[str] = mapped_column(String(64))  # the session's default purpose
    artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)  # caller's handle
    artifact_sha256: Mapped[str] = mapped_column(String(64))  # digest of the safe text the AI was shown
    policy_id: Mapped[str] = mapped_column(String(64))
    issued_tokens: Mapped[list] = mapped_column(JSON)  # every placeholder present in the artifact text
    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary(32))  # HKDF salt: unique per session, not secret
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)

    __table_args__ = (UniqueConstraint("tenant_id", "artifact_id", name="uq_vault_session_artifact"),)


class VaultEntry(Base):
    """One encrypted original, scoped to (session, token, role, purpose)."""

    __tablename__ = "vault_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("vault_sessions.session_id", ondelete="CASCADE"), index=True)
    token: Mapped[str] = mapped_column(String(64))  # e.g. "[PERSON_01]"
    token_class: Mapped[str] = mapped_column(String(24))  # e.g. "PERSON": lets policy run without decrypting
    role: Mapped[str] = mapped_column(String(32))  # the role this copy is encrypted for
    purpose: Mapped[str] = mapped_column(String(64))
    alg: Mapped[str] = mapped_column(String(48))  # "AES-256-GCM/HKDF-SHA256/v1"
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)  # ciphertext || 16-byte GCM tag
    created_at: Mapped[datetime] = mapped_column(DateTime)

    __table_args__ = (
        UniqueConstraint("session_id", "token", "role", "purpose", name="uq_vault_entry_scope"),
        # GCM breaks catastrophically if a (key, nonce) pair repeats. Keys are per (session, purpose), so a
        # repeat within a session is refused by the database instead of silently accepted.
        UniqueConstraint("session_id", "nonce", name="uq_vault_entry_nonce"),
    )


def create_vault_schema() -> None:
    """Create only the vault tables (idempotent)."""
    Base.metadata.create_all(engine, tables=[VaultSession.__table__, VaultEntry.__table__])
