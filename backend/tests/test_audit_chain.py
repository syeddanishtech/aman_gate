"""Audit chain: verifies on a clean DB, detects row mutation, deletion and wrong-key verification."""
from __future__ import annotations

from conftest import auth, login


def generate_events(client):
    tok = login(client, "ayesha.po")
    client.get("/api/documents/BUDGET-SECRET-01", headers=auth(tok))  # DENY event
    client.get("/api/documents/QUOTE-101", headers=auth(tok))  # ALLOW event
    client.post("/api/scenarios/run", headers=auth(tok), json={"scenario_id": "S2-indirect-injection"})
    return tok


def test_chain_valid_on_clean_db(client):
    tok = generate_events(client)
    v = client.get("/api/audit/verify", headers=auth(tok)).json()
    assert v["valid"] is True
    assert v["checked"] > 0


def test_mutation_detected(client):
    tok = generate_events(client)
    db_mod = client._modules["db"]
    models = client._modules["models"]
    # Tamper: flip a decision on one row via raw SQL (bypassing the ORM append-only trigger would
    # require DISABLEing it; here we prove verification catches a key-less edit).
    from sqlalchemy import text, select
    with db_mod.engine.begin() as conn:
        conn.execute(text("DROP TRIGGER IF EXISTS audit_no_update"))
        conn.execute(text("UPDATE audit_events SET decision='ALLOW' WHERE decision='DENY'"))
    v = client.get("/api/audit/verify", headers=auth(tok)).json()
    assert v["valid"] is False
    assert "HMAC_MISMATCH" in v["problems"]


def test_deletion_detected(client):
    tok = generate_events(client)
    db_mod = client._modules["db"]
    from sqlalchemy import text
    with db_mod.engine.begin() as conn:
        conn.execute(text("DROP TRIGGER IF EXISTS audit_no_delete"))
        conn.execute(text("DELETE FROM audit_events WHERE seq = (SELECT MIN(seq)+1 FROM audit_events)"))
    v = client.get("/api/audit/verify", headers=auth(tok)).json()
    assert v["valid"] is False


def test_wrong_key_fails_verification(client):
    generate_events(client)
    db_mod = client._modules["db"]
    audit = client._modules["audit"]
    s = db_mod.SessionLocal()
    try:
        good = audit.verify_chain(s)
        bad = audit.verify_chain(s, key="totally-wrong-key-of-sufficient-length-0001")
        assert good["valid"] is True
        assert bad["valid"] is False
    finally:
        s.close()


def test_append_only_trigger_blocks_update(client):
    """The SQLite trigger itself refuses an ordinary UPDATE/DELETE on audit_events."""
    generate_events(client)
    db_mod = client._modules["db"]
    from sqlalchemy import text
    import pytest
    with pytest.raises(Exception):
        with db_mod.engine.begin() as conn:
            conn.execute(text("UPDATE audit_events SET decision='ALLOW'"))


def test_no_restricted_content_in_audit(client):
    """The budget canary must never appear in any audit record (no content leakage)."""
    tok = login(client, "fatima.fm")
    client.get("/api/documents/BUDGET-SECRET-01", headers=auth(tok))  # allowed read of restricted doc
    export = client.get("/api/audit/export", headers=auth(tok)).json()
    blob = str(export)
    assert "LAB-CANARY-7731" not in blob
    assert "6,950,000" not in blob  # the secret ceiling value
