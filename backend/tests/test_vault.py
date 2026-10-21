"""WP3 vault: AES-256-GCM at rest, HKDF-SHA256 purpose-scoped keys, unique nonces, role+purpose scoping.

Covers: standards conformance of the key derivation, round trip, wrong key / tampered / truncated ciphertext,
moved, replayed and edited rows, plaintext absent from the database file, scope and policy ceilings, expiry,
purge, atomic stores, and refusal to vault anything RESTRICTED or placeholder-shaped."""
from __future__ import annotations

import ast
import hashlib
import hmac
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from vault_helpers import CANARY, ORIGINALS, QUOTE_TEXT, TENANT, fake_artifact, make_artifact, vault, wipe_vault

import app.privacy.vault as vault_mod
from app.db import SessionLocal, engine
from app.privacy.pipeline import protect_text
from app.privacy.policy import KNOWN_ROLES, PSEUDONYM_CLASS
from app.privacy.vault import (DEFAULT_PURPOSE, DEMO_VAULT_MASTER_SECRET, ROLE_CLASS_GRANTS, VAULT_SECRET_ENV,
                               Reveal, VaultAccessError, VaultAuthError, VaultConfigError, VaultError, build_aad,
                               decrypt_lookup, derive_key, encrypt_store, load_master_secret, open_context,
                               purge_expired, purge_session, seal, store_artifact, unseal)
from app.privacy.vault_models import VaultEntry, VaultSession

PO, FM, JC, SA = "procurement_officer", "finance_manager", "junior_clerk", "security_analyst"
ALT_SECRET = "another-high-entropy-secret-for-tests-0002-xxxx"


@pytest.fixture(autouse=True)
def _clean_vault():
    wipe_vault()
    yield
    wipe_vault()


@pytest.fixture()
def db():
    with SessionLocal() as s:
        yield s


def lookup(db, info, token, *, role=PO, purpose=DEFAULT_PURPOSE, tenant=TENANT):
    return decrypt_lookup(db, session_id=info.session_id, token=token, tenant_id=tenant, role=role, purpose=purpose)


def code_of(db, info, token, **kw) -> str:
    with pytest.raises(VaultError) as ei:
        lookup(db, info, token, **kw)
    return ei.value.code


# ------------------------------------------------------------------ master secret
def test_default_master_secret_is_labelled_nonproduction_and_long_enough(monkeypatch):
    monkeypatch.delenv(VAULT_SECRET_ENV, raising=False)
    monkeypatch.setenv("AMAN_ENV", "demo")
    assert "nonproduction" in DEMO_VAULT_MASTER_SECRET
    assert len(DEMO_VAULT_MASTER_SECRET) >= 32
    assert load_master_secret() == DEMO_VAULT_MASTER_SECRET.encode()


def test_production_refuses_the_demo_secret_but_accepts_a_real_one(monkeypatch):
    monkeypatch.setenv("AMAN_ENV", "production")
    monkeypatch.delenv(VAULT_SECRET_ENV, raising=False)
    with pytest.raises(VaultConfigError) as ei:
        load_master_secret()
    assert ei.value.code == "DEMO_SECRET_IN_PRODUCTION"
    monkeypatch.setenv(VAULT_SECRET_ENV, DEMO_VAULT_MASTER_SECRET)  # setting the demo value explicitly is no better
    with pytest.raises(VaultConfigError):
        load_master_secret()
    monkeypatch.setenv(VAULT_SECRET_ENV, ALT_SECRET)
    assert load_master_secret() == ALT_SECRET.encode()


def test_short_master_secret_is_refused(monkeypatch):
    monkeypatch.setenv(VAULT_SECRET_ENV, "too-short")
    with pytest.raises(VaultConfigError) as ei:
        load_master_secret()
    assert ei.value.code == "SECRET_TOO_SHORT"


# ------------------------------------------------------------------ HKDF-SHA256
def _rfc5869_hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, i = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def test_derive_key_is_standard_hkdf_sha256():
    master, salt = b"m" * 40, bytes(range(32))
    info = vault_mod._pack(vault_mod._KDF_LABEL, b"display_to_requester")
    assert derive_key(master, salt=salt, purpose="display_to_requester") == _rfc5869_hkdf_sha256(master, salt, info, 32)


def test_keys_are_256_bit_deterministic_and_separated_by_purpose_salt_and_master():
    master, salt = b"m" * 40, b"s" * 32
    k = derive_key(master, salt=salt, purpose="display_to_requester")
    assert len(k) == 32
    assert k == derive_key(master, salt=salt, purpose="display_to_requester")
    assert k != derive_key(master, salt=salt, purpose="export_external")
    assert k != derive_key(master, salt=b"t" * 32, purpose="display_to_requester")
    assert k != derive_key(b"n" * 40, salt=salt, purpose="display_to_requester")


@pytest.mark.parametrize("salt,purpose", [(b"short", "display_to_requester"), (b"s" * 32, "Bad Purpose!"),
                                          (b"s" * 32, ""), (b"s" * 32, "x")])
def test_derive_key_rejects_malformed_salt_or_purpose(salt, purpose):
    with pytest.raises(VaultError):
        derive_key(b"m" * 40, salt=salt, purpose=purpose)


# ------------------------------------------------------------------ AES-256-GCM
KEY, AAD = b"k" * 32, b"aad"


def test_seal_unseal_round_trip_and_sizes():
    nonce, ct = seal(b"Ayesha Khan", key=KEY, aad=AAD)
    assert len(nonce) == 12
    assert len(ct) == len(b"Ayesha Khan") + 16  # ciphertext || 128-bit tag
    assert b"Ayesha" not in ct
    assert unseal(nonce, ct, key=KEY, aad=AAD) == b"Ayesha Khan"


def test_every_single_bit_flip_in_a_record_fails_authentication():
    nonce, ct = seal(b"Ayesha Khan", key=KEY, aad=AAD)
    for i in range(len(ct)):
        for bit in (0x01, 0x80):
            bad = bytearray(ct)
            bad[i] ^= bit
            with pytest.raises(VaultAuthError):
                unseal(nonce, bytes(bad), key=KEY, aad=AAD)
    for i in range(len(nonce)):
        bad_nonce = bytearray(nonce)
        bad_nonce[i] ^= 0x01
        with pytest.raises(VaultAuthError):
            unseal(bytes(bad_nonce), ct, key=KEY, aad=AAD)


def test_wrong_key_wrong_aad_truncation_and_garbage_fail():
    nonce, ct = seal(b"Ayesha Khan", key=KEY, aad=AAD)
    for kwargs in ({"key": b"x" * 32, "aad": AAD}, {"key": KEY, "aad": b"other"}):
        with pytest.raises(VaultAuthError):
            unseal(nonce, ct, **kwargs)
    for bad_ct in (ct[:-1], ct[:15], b"", ct + b"\x00"):
        with pytest.raises(VaultAuthError):
            unseal(nonce, bad_ct, key=KEY, aad=AAD)
    with pytest.raises(VaultAuthError):
        unseal(b"short", ct, key=KEY, aad=AAD)


def test_nonces_and_ciphertexts_are_unique_across_many_seals():
    seen_nonces, seen_cts = set(), set()
    for _ in range(5000):
        nonce, ct = seal(b"same plaintext every time", key=KEY, aad=AAD)
        seen_nonces.add(nonce)
        seen_cts.add(ct)
    assert len(seen_nonces) == 5000  # a repeat would be a ~2^-77 event
    assert len(seen_cts) == 5000


# ------------------------------------------------------------------ store / lookup
def test_store_and_lookup_round_trip(db):
    info = vault(make_artifact(), artifact_id="PD-rt1")
    assert info.issued_count == 3 and info.entries_written == 3 and dict(info.entries_by_role) == {PO: 3}
    for token, original in ORIGINALS.items():
        assert lookup(db, info, token) == original


def test_originals_are_not_stored_in_the_clear(db):
    unique = "zq9kx3w7.unique@northbridge.example"
    art = make_artifact(f"Reach the supplier at {unique} for the quotation.")
    assert art.rehydration_table == {"[EMAIL_01]": unique}
    info = vault(art)
    needles = [unique.encode(), unique.encode("utf-16-le"), b"zq9kx3w7"]
    for table in (VaultEntry, VaultSession):
        for row in db.execute(select(table)).scalars():
            for col in table.__table__.columns:
                v = getattr(row, col.name)
                blob = v if isinstance(v, bytes) else str(v).encode()
                assert not any(n in blob for n in needles)
    # ...and not in the SQLite file or its write-ahead log either (the control proves the scan sees stored data)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    base = Path(engine.url.database)
    raw = b"".join(p.read_bytes() for p in base.parent.glob(base.name + "*") if p.is_file())
    assert b"[EMAIL_01]" in raw and info.session_id.encode() in raw  # control: plaintext metadata IS findable
    assert not any(n in raw for n in needles)


def test_each_record_has_its_own_nonce_and_the_database_enforces_it(db):
    info = vault(make_artifact(), artifact_id="PD-nonce")
    rows = list(db.execute(select(VaultEntry).where(VaultEntry.session_id == info.session_id)).scalars())
    assert len({r.nonce for r in rows}) == len(rows) == 3 and all(len(r.nonce) == 12 for r in rows)
    clash = VaultEntry(session_id=info.session_id, token="[PERSON_77]", token_class="PERSON", role=PO,
                       purpose=DEFAULT_PURPOSE, alg=rows[0].alg, nonce=rows[0].nonce, ciphertext=b"x" * 20,
                       created_at=rows[0].created_at)
    db.add(clash)
    with pytest.raises(IntegrityError):  # UNIQUE(session_id, nonce): a repeated nonce is refused, never reused
        db.flush()
    db.rollback()


def test_every_session_has_its_own_salt_and_therefore_its_own_keys(db):
    art = make_artifact()
    a, b = vault(art, artifact_id="PD-a"), vault(art, artifact_id="PD-b")
    sa, sb = db.get(VaultSession, a.session_id), db.get(VaultSession, b.session_id)
    assert sa.kdf_salt != sb.kdf_salt and len(sa.kdf_salt) == 32
    ea = db.execute(select(VaultEntry).where(VaultEntry.session_id == a.session_id,
                                             VaultEntry.token == "[PERSON_01]")).scalar_one()
    eb = db.execute(select(VaultEntry).where(VaultEntry.session_id == b.session_id,
                                             VaultEntry.token == "[PERSON_01]")).scalar_one()
    assert ea.ciphertext != eb.ciphertext  # same plaintext, different key and nonce
    master = load_master_secret()
    assert derive_key(master, salt=sa.kdf_salt, purpose=DEFAULT_PURPOSE) != derive_key(master, salt=sb.kdf_salt,
                                                                                     purpose=DEFAULT_PURPOSE)


def test_wrong_master_secret_cannot_decrypt(db, monkeypatch):
    info = vault(make_artifact())
    assert lookup(db, info, "[PERSON_01]") == "Ayesha Khan"
    monkeypatch.setenv(VAULT_SECRET_ENV, ALT_SECRET)
    with pytest.raises(VaultAuthError):
        lookup(db, info, "[PERSON_01]")
    monkeypatch.delenv(VAULT_SECRET_ENV)
    assert lookup(db, info, "[PERSON_01]") == "Ayesha Khan"


@pytest.mark.parametrize("column", ["ciphertext", "nonce"])
def test_tampered_stored_bytes_are_detected(db, column):
    info = vault(make_artifact())
    row = db.execute(select(VaultEntry).where(VaultEntry.session_id == info.session_id,
                                              VaultEntry.token == "[PERSON_01]")).scalar_one()
    bad = bytearray(getattr(row, column))
    bad[0] ^= 0x01
    db.execute(update(VaultEntry).where(VaultEntry.id == row.id).values({column: bytes(bad)}))
    db.commit()
    with pytest.raises(VaultAuthError):
        lookup(db, info, "[PERSON_01]")
    assert lookup(db, info, "[ORG_01]") == "Northbridge University"  # only the touched record is affected


def test_unknown_record_format_fails_closed(db):
    info = vault(make_artifact())
    db.execute(update(VaultEntry).where(VaultEntry.session_id == info.session_id).values(alg="AES-128-CBC/v0"))
    db.commit()
    with pytest.raises(VaultAuthError):
        lookup(db, info, "[PERSON_01]")


def test_moving_a_record_to_another_token_fails(db):
    info = vault(make_artifact())
    q = select(VaultEntry).where(VaultEntry.session_id == info.session_id)
    person = db.execute(q.where(VaultEntry.token == "[PERSON_01]")).scalar_one()
    org = db.execute(q.where(VaultEntry.token == "[ORG_01]")).scalar_one()
    p_nonce, p_ct, o_nonce, o_ct = person.nonce, person.ciphertext, org.nonce, org.ciphertext
    db.execute(update(VaultEntry).where(VaultEntry.id == person.id).values(nonce=b"\x00" * 12, ciphertext=b"\x00" * 20))
    db.execute(update(VaultEntry).where(VaultEntry.id == org.id).values(nonce=p_nonce, ciphertext=p_ct))
    db.execute(update(VaultEntry).where(VaultEntry.id == person.id).values(nonce=o_nonce, ciphertext=o_ct))
    db.commit()
    for token in ("[PERSON_01]", "[ORG_01]"):  # each ciphertext is bound to the token it was made for
        with pytest.raises(VaultAuthError):
            lookup(db, info, token)


def test_replaying_a_record_into_another_session_fails(db):
    art = make_artifact()
    a, b = vault(art, artifact_id="PD-ra"), vault(art, artifact_id="PD-rb")
    src = db.execute(select(VaultEntry).where(VaultEntry.session_id == a.session_id,
                                              VaultEntry.token == "[PERSON_01]")).scalar_one()
    db.execute(update(VaultEntry).where(VaultEntry.session_id == b.session_id, VaultEntry.token == "[PERSON_01]")
               .values(nonce=src.nonce, ciphertext=src.ciphertext))
    db.commit()
    with pytest.raises(VaultAuthError):
        lookup(db, b, "[PERSON_01]")
    assert lookup(db, a, "[PERSON_01]") == "Ayesha Khan"


def test_editing_role_purpose_or_tenant_columns_does_not_widen_scope(db):
    info = vault(make_artifact(), artifact_id="PD-edit")
    # role: a copy encrypted for the procurement officer relabelled as a finance manager's
    db.execute(update(VaultEntry).where(VaultEntry.session_id == info.session_id, VaultEntry.token == "[ORG_01]")
               .values(role=FM))
    db.commit()
    with pytest.raises(VaultAuthError):
        lookup(db, info, "[ORG_01]", role=FM)
    assert code_of(db, info, "[ORG_01]", role=PO) == "NO_ENTRY_FOR_SCOPE"
    # purpose: relabelled to another purpose (different key AND different associated data)
    db.execute(update(VaultEntry).where(VaultEntry.session_id == info.session_id, VaultEntry.token == "[EMAIL_01]")
               .values(purpose="export_external"))
    db.commit()
    with pytest.raises(VaultAuthError):
        lookup(db, info, "[EMAIL_01]", purpose="export_external")
    # tenant: moving the session to another tenant does not let that tenant read it
    db.execute(update(VaultSession).where(VaultSession.session_id == info.session_id).values(tenant_id="southfield-lab"))
    db.commit()
    with pytest.raises(VaultAuthError):
        lookup(db, info, "[PERSON_01]", tenant="southfield-lab")


# ------------------------------------------------------------------ scope, policy ceiling, tenants
def test_role_grants_cover_exactly_the_known_roles_and_real_token_classes():
    assert set(ROLE_CLASS_GRANTS) == set(KNOWN_ROLES)
    assert all(classes <= set(PSEUDONYM_CLASS.values()) for classes in ROLE_CLASS_GRANTS.values())
    assert ROLE_CLASS_GRANTS[SA] == frozenset()  # the analyst reviews pseudonymized evidence only


def test_policy_ceiling_is_applied_when_storing(db):
    art = make_artifact()
    info = vault(art, grant_roles=[PO, FM, JC, SA])
    assert dict(info.entries_by_role) == {PO: 3, FM: 3, JC: 1, SA: 0}
    assert db.execute(select(func.count()).select_from(VaultEntry)).scalar_one() == 7
    # the analyst holds no ciphertext at all, so there is nothing for it to even attempt to open
    assert lookup(db, info, "[ORG_01]", role=JC) == "Northbridge University"
    for token in ("[PERSON_01]", "[EMAIL_01]"):
        assert code_of(db, info, token, role=JC) == "ROLE_NOT_GRANTED"
    for token in ORIGINALS:
        assert code_of(db, info, token, role=SA) == "ROLE_NOT_GRANTED"


def test_a_role_that_was_not_granted_at_store_time_has_no_entry(db):
    info = vault(make_artifact())  # default: only the owner's role
    assert code_of(db, info, "[PERSON_01]", role=FM) == "NO_ENTRY_FOR_SCOPE"


def test_purpose_must_match_exactly(db):
    info = vault(make_artifact(), purpose="quotation_review")
    assert lookup(db, info, "[PERSON_01]", purpose="quotation_review") == "Ayesha Khan"
    assert code_of(db, info, "[PERSON_01]") == "NO_ENTRY_FOR_SCOPE"  # default purpose
    assert code_of(db, info, "[PERSON_01]", purpose="export_external") == "NO_ENTRY_FOR_SCOPE"
    assert code_of(db, info, "[PERSON_01]", purpose="Not A Slug") == "NO_ENTRY_FOR_SCOPE"


def test_unknown_session_other_tenant_and_malformed_id_are_indistinguishable(db):
    info = vault(make_artifact())
    codes = {
        code_of(db, info, "[PERSON_01]", tenant="southfield-lab"),
        code_of(db, replace(info, session_id="VS-" + "0" * 32), "[PERSON_01]"),
        code_of(db, replace(info, session_id="not-a-session"), "[PERSON_01]"),
    }
    assert codes == {"SESSION_NOT_FOUND"}


def test_only_issued_reversible_tokens_can_be_looked_up(db):
    art = make_artifact("Approved ceiling: PKR 7,100,000. Contact Ayesha Khan.", role=FM)
    assert "[REDACTED:BUDGET_FIGURE]" in art.text
    info = vault(art, role=FM, user="u-fm-01")
    assert lookup(db, info, "[PERSON_01]", role=FM) == "Ayesha Khan"
    assert code_of(db, info, "[REDACTED:BUDGET_FIGURE]", role=FM) == "IRREVERSIBLE"  # redaction keeps nothing
    assert code_of(db, info, "[PERSON_09]", role=FM) == "TOKEN_NOT_ISSUED"
    assert dict(info.entries_by_role) == {FM: 1} and info.issued_count == 2


def test_open_context_resolves_by_session_or_artifact_and_they_must_agree(db):
    a, b = vault(make_artifact(), artifact_id="PD-ctx-a"), vault(make_artifact(), artifact_id="PD-ctx-b")
    ctx = open_context(db, tenant_id=TENANT, session_id=a.session_id)
    assert ctx.session_id == a.session_id and ctx.issued_tokens == frozenset(ORIGINALS)
    assert open_context(db, tenant_id=TENANT, artifact_id="PD-ctx-b").session_id == b.session_id
    assert open_context(db, tenant_id=TENANT, session_id=a.session_id, artifact_id="PD-ctx-a").session_id == a.session_id
    assert open_context(db, tenant_id=TENANT) is None
    for kwargs in ({"session_id": a.session_id, "artifact_id": "PD-ctx-b"}, {"artifact_id": "PD-missing"},
                   {"session_id": a.session_id, "tenant_id": "southfield-lab"}):
        kw = {"tenant_id": TENANT, **kwargs}
        with pytest.raises(VaultAccessError) as ei:
            open_context(db, **kw)
        assert ei.value.code == "SESSION_NOT_FOUND"


def test_reveal_does_not_print_the_original():
    assert "secret" not in repr(Reveal("[PERSON_01]", "OK", "secret"))


# ------------------------------------------------------------------ lifecycle
def test_expired_sessions_are_unusable_and_purge_removes_every_ciphertext(db):
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)
    info = vault(make_artifact(), artifact_id="PD-old", now=old)
    assert code_of(db, info, "[PERSON_01]") == "SESSION_EXPIRED"
    with pytest.raises(VaultAccessError) as ei:
        open_context(db, tenant_id=TENANT, session_id=info.session_id)
    assert ei.value.code == "SESSION_EXPIRED"
    fresh = vault(make_artifact(), artifact_id="PD-new")
    assert purge_expired(db) == 1
    assert db.execute(select(func.count()).select_from(VaultSession)).scalar_one() == 1
    assert db.execute(select(func.count()).select_from(VaultEntry)).scalar_one() == 3
    assert lookup(db, fresh, "[PERSON_01]") == "Ayesha Khan"


def test_purging_a_session_makes_its_originals_unrecoverable(db):
    info = vault(make_artifact())
    assert purge_session(db, session_id=info.session_id, tenant_id=TENANT) == 3
    assert code_of(db, info, "[PERSON_01]") == "SESSION_NOT_FOUND"
    assert db.execute(select(func.count()).select_from(VaultEntry)).scalar_one() == 0
    other = vault(make_artifact())
    with pytest.raises(VaultAccessError):  # another tenant cannot purge it
        purge_session(db, session_id=other.session_id, tenant_id="southfield-lab")


def test_ttl_is_clamped(db):
    now = datetime(2026, 1, 1)
    short = store_artifact(db, make_artifact(), tenant_id=TENANT, owner_user_id="u", owner_role=PO, ttl_seconds=1, now=now)
    long = store_artifact(db, make_artifact(), tenant_id=TENANT, owner_user_id="u", owner_role=PO,
                          ttl_seconds=10**9, now=now)
    assert short.expires_at - now == timedelta(seconds=60)
    assert long.expires_at - now == timedelta(days=7)


# ------------------------------------------------------------------ what may never be vaulted
def test_blocked_artifacts_and_foreign_objects_are_refused(db):
    blocked = protect_text("Secret LAB-CANARY-7731 here", task="t", role=PO, destination="local_simulator")
    assert not blocked.export_allowed
    with pytest.raises(VaultError) as ei:
        store_artifact(db, blocked, tenant_id=TENANT, owner_user_id="u", owner_role=PO)
    assert ei.value.code == "ARTIFACT_NOT_EXPORTABLE"
    with pytest.raises(VaultError):
        store_artifact(db, object(), tenant_id=TENANT, owner_user_id="u", owner_role=PO)  # type: ignore[arg-type]


@pytest.mark.parametrize("original,reason", [
    (CANARY, "RESTRICTED_VALUE"), ("lab canary 7731", "RESTRICTED_VALUE"), ("6,950,000", "RESTRICTED_VALUE"),
    ("[ORG_02]", "PLACEHOLDER_SHAPED"), ("see [REDACTED:X] here", "PLACEHOLDER_SHAPED"),
    ("", "ORIGINAL_INVALID"), ("x" * 5000, "ORIGINAL_INVALID"), ("bad \ud800 surrogate", "ORIGINAL_INVALID"),
])
def test_restricted_placeholder_shaped_and_invalid_originals_are_never_vaulted(db, original, reason):
    info = vault(make_artifact())
    with pytest.raises(VaultError) as ei:
        encrypt_store(db, session_id=info.session_id, token="[PERSON_01]", original=original, tenant_id=TENANT,
                      role=FM, purpose=DEFAULT_PURPOSE)
    assert ei.value.code == reason
    assert vault_mod.screen_original(original) == reason


def test_encrypt_store_refuses_unissued_redacted_duplicate_and_ungranted_scopes(db):
    info = vault(make_artifact())
    base = dict(session_id=info.session_id, tenant_id=TENANT, original="Ayesha Khan", role=PO, purpose=DEFAULT_PURPOSE)
    cases = [({"token": "[PERSON_09]"}, "TOKEN_NOT_ISSUED"), ({"token": "[REDACTED:BUDGET_FIGURE]"}, "BAD_TOKEN"),
             ({"token": "PERSON_01"}, "BAD_TOKEN"), ({"token": "[PERSON_01]"}, "ENTRY_EXISTS"),
             ({"token": "[PERSON_01]", "role": SA}, "ROLE_NOT_GRANTED"),
             ({"token": "[PERSON_01]", "role": "root"}, "ROLE_NOT_GRANTED"),
             ({"token": "[PERSON_01]", "purpose": "BAD"}, "BAD_PURPOSE"),
             ({"token": "[PERSON_01]", "role": FM, "tenant_id": "southfield-lab"}, "SESSION_NOT_FOUND")]
    for override, code in cases:
        with pytest.raises(VaultError) as ei:
            encrypt_store(db, **{**base, **override})
        assert ei.value.code == code, override
    # a different role or purpose for the same token is a new, independent scope
    encrypt_store(db, **{**base, "token": "[PERSON_01]", "role": FM})
    encrypt_store(db, **{**base, "token": "[PERSON_01]", "purpose": "export_review"})
    assert lookup(db, info, "[PERSON_01]", role=FM) == "Ayesha Khan"
    assert lookup(db, info, "[PERSON_01]", purpose="export_review") == "Ayesha Khan"


def test_an_artifact_can_only_be_vaulted_once_and_the_table_must_match_the_text(db):
    art = make_artifact()
    vault(art, artifact_id="PD-once")
    with pytest.raises(VaultError) as ei:
        vault(art, artifact_id="PD-once")
    assert ei.value.code == "ARTIFACT_ALREADY_VAULTED"
    with pytest.raises(VaultError) as ei:
        vault(fake_artifact("Hello [PERSON_01]", {"[PERSON_01]": "Ayesha Khan", "[ORG_05]": "Northbridge University"}))
    assert ei.value.code == "TABLE_NOT_IN_ARTIFACT"
    for bad in ({"grant_roles": ["root"]}, {"grant_roles": []}, {"purpose": "Bad Purpose"}, {"artifact_id": "bad id!"},
                {"role": "root"}):
        with pytest.raises(VaultError):
            vault(make_artifact(), **bad)
    with pytest.raises(VaultError) as ei:
        store_artifact(db, make_artifact(), tenant_id=TENANT, owner_user_id="u", owner_role=PO, ttl_seconds="soon")  # type: ignore[arg-type]
    assert ei.value.code == "BAD_TTL"


def test_a_failed_store_leaves_nothing_behind(db):
    art = fake_artifact("[PERSON_01] and [ORG_01]", {"[PERSON_01]": "Ayesha Khan", "[ORG_01]": CANARY})
    with pytest.raises(VaultError) as ei:
        vault(art)
    assert ei.value.code == "RESTRICTED_VALUE"
    db.rollback()
    assert db.execute(select(func.count()).select_from(VaultEntry)).scalar_one() == 0
    assert db.execute(select(func.count()).select_from(VaultSession)).scalar_one() == 0


# ------------------------------------------------------------------ hygiene
def test_vault_sources_hold_no_key_material_and_avoid_the_word_anonymization():
    root = Path(vault_mod.__file__).parent.parent
    for rel in ("privacy/vault.py", "privacy/vault_models.py", "assurance/check.py", "assurance/routes.py"):
        src = (root / rel).read_text(encoding="utf-8")
        assert "anonymi" not in src.lower(), rel  # pseudonymization is not anonymization (same rule as WP1)
        assert not re.search(r"\b[0-9a-fA-F]{32,}\b", src), rel  # no embedded hex keys
        for node in ast.walk(ast.parse(src)):  # long byte-string constants may only be domain-separation labels
            if isinstance(node, ast.Constant) and isinstance(node.value, bytes) and len(node.value) >= 16:
                assert node.value.startswith(b"aman-gate/"), (rel, node.value)
    assert re.search(r"nonproduction", (root / "privacy/vault.py").read_text(encoding="utf-8"))


def test_default_session_ttl_comes_from_the_environment(db, monkeypatch):
    monkeypatch.setenv(vault_mod.VAULT_TTL_ENV, "7200")
    now = datetime(2026, 1, 1)
    info = store_artifact(db, make_artifact(), tenant_id=TENANT, owner_user_id="u", owner_role=PO, now=now)
    assert info.expires_at - now == timedelta(seconds=7200)
    monkeypatch.setenv(vault_mod.VAULT_TTL_ENV, "not-a-number")
    info = store_artifact(db, make_artifact(), tenant_id=TENANT, owner_user_id="u", owner_role=PO, now=now)
    assert info.expires_at - now == timedelta(seconds=vault_mod.DEFAULT_TTL_SECONDS)


def test_quote_text_fixture_still_yields_the_documented_originals():
    assert dict(make_artifact(QUOTE_TEXT).rehydration_table) == ORIGINALS
    assert build_aad(tenant_id="a", session_id="b", token="c", role="d", purpose="e") != build_aad(
        tenant_id="a", session_id="b", token="c", role="d", purpose="f")
