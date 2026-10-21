"""Shared builders for the WP3 vault and assurance tests. Synthetic data only; nothing here touches the network."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select

from app.db import SessionLocal, engine
from app.privacy.pipeline import protect_text
from app.privacy.policy import EXPORT_ALLOWED
from app.privacy.sanitize import SafeArtifact, sha256_text
from app.privacy.vault import (DEFAULT_PURPOSE, VaultSessionInfo, build_aad, derive_key, load_master_secret, seal,
                               store_artifact)
from app.privacy.vault_models import VaultEntry, VaultSession, create_vault_schema

TENANT = "northbridge"
CANARY = "LAB-CANARY-7731"

QUOTE_TEXT = (
    "Supplier contact: Ayesha Khan, ayesha.khan@northbridge.example, for Northbridge University.\n"
    "Quote ID: QUOTE-101\nTotal price: PKR 7,280,000\nDelivery: 6 weeks\n"
)
# What the vault must hand back for QUOTE_TEXT (asserted when the artifact is built, so drift fails loudly).
ORIGINALS = {
    "[PERSON_01]": "Ayesha Khan",
    "[EMAIL_01]": "ayesha.khan@northbridge.example",
    "[ORG_01]": "Northbridge University",
}


def wipe_vault() -> None:
    create_vault_schema()
    with engine.begin() as conn:
        conn.execute(delete(VaultEntry))
        conn.execute(delete(VaultSession))


def make_artifact(text: str = QUOTE_TEXT, role: str = "procurement_officer") -> SafeArtifact:
    art = protect_text(text, task="summarize quotation", role=role, destination="local_simulator")
    assert art.export_allowed, art.decision_record["block_reasons"]
    if text == QUOTE_TEXT:
        assert dict(art.rehydration_table) == ORIGINALS
    return art


def fake_artifact(text: str, table: dict[str, str]) -> SafeArtifact:
    """An EXPORT_ALLOWED artifact with a hand-written text and table, for tests that need a table the
    real sanitizer would never produce (compositions, poisoned values)."""
    return SafeArtifact(EXPORT_ALLOWED, text, sha256_text(text), {"record_version": "test"},
                        rehydration_table=dict(table))


def vault(art: SafeArtifact, *, role: str = "procurement_officer", user: str = "u-po-01",
          grant_roles: list[str] | None = None, artifact_id: str | None = None, purpose: str = DEFAULT_PURPOSE,
          tenant: str = TENANT, now: datetime | None = None) -> VaultSessionInfo:
    with SessionLocal() as db:
        return store_artifact(db, art, tenant_id=tenant, owner_user_id=user, owner_role=role, purpose=purpose,
                              grant_roles=grant_roles, artifact_id=artifact_id, now=now)


def plant_entry(session_id: str, token: str, plaintext: str, *, role: str = "procurement_officer",
                purpose: str = DEFAULT_PURPOSE) -> None:
    """Overwrite an existing entry with a correctly encrypted, correctly bound, but different plaintext.
    This simulates a buggy writer or an attacker holding the master secret: the record authenticates, so
    only the read-side screening and re-scan can stop what it carries."""
    with SessionLocal() as db:
        sess = db.get(VaultSession, session_id)
        key = derive_key(load_master_secret(), salt=sess.kdf_salt, purpose=purpose)
        aad = build_aad(tenant_id=sess.tenant_id, session_id=session_id, token=token, role=role, purpose=purpose)
        nonce, ct = seal(plaintext.encode("utf-8"), key=key, aad=aad)
        row = db.execute(select(VaultEntry).where(
            VaultEntry.session_id == session_id, VaultEntry.token == token, VaultEntry.role == role,
            VaultEntry.purpose == purpose)).scalar_one()
        row.nonce, row.ciphertext = nonce, ct
        db.commit()
