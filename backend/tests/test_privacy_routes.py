"""T1/T2: the Privacy Shield HTTP routes and the seeded film document.

These prove the integration seam: analyze reads through the ACL, runs the WP1 engine, and the seeded
film document reproduces engine run R1 (7 findings, verifier PASS). Full-suite regression lives in the
other test modules; here we assert route behaviour, ACL enforcement and no-raw-value audit."""
from __future__ import annotations

import hashlib

from conftest import auth, login

FILM_DOC_ID = "PR-2026-118"
FILM_SHA256 = "2080f14050accc60219adb58923b5e2bdedb445486bb3ab2c2f0df3c29bca731"
CANARY = "LAB-CANARY-7731"
SECRET_CEILING = "6,950,000"


def test_seeded_film_document_is_byte_exact():
    """Byte-exactness is what makes the analysis reproduce R1 deterministically."""
    from app.seed import FILM_DOC_PR118
    assert hashlib.sha256(FILM_DOC_PR118.encode("utf-8")).hexdigest() == FILM_SHA256
    assert len(FILM_DOC_PR118.encode("utf-8")) == 762


def test_analyze_film_document_reproduces_R1(client):
    tok = login(client, "ayesha.po")
    r = client.post("/api/privacy/analyze", headers=auth(tok), json={"document_id": FILM_DOC_ID})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "READY_FOR_REVIEW"
    assert body["disclosure"]["findings_count"] == 7  # R1
    assert body["safe_artifact_id"].startswith("SA-")
    # the element view carries no raw values, only ids/types/actions
    kinds = {e["type"] for e in body["disclosure"]["elements"]}
    assert {"ORG", "PERSON", "EMAIL", "BUDGET_FIGURE", "ACCOUNT_NUMBER"} & kinds
    blob = r.text
    assert CANARY not in blob and SECRET_CEILING not in blob


def test_analyze_respects_acl_denies_budget(client):
    """A procurement officer may not read the restricted budget, so analyze is refused by the same ACL."""
    tok = login(client, "ayesha.po")
    r = client.post("/api/privacy/analyze", headers=auth(tok), json={"document_id": "BUDGET-SECRET-01"})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] in ("ACL_DENIED", "RESOURCE_NOT_ACCESSIBLE")


def test_artifact_preview_safe_copy_redacts_secrets(client):
    tok = login(client, "ayesha.po")
    sa = client.post("/api/privacy/analyze", headers=auth(tok),
                     json={"document_id": FILM_DOC_ID}).json()["safe_artifact_id"]
    r = client.get(f"/api/privacy/artifacts/{sa}", headers=auth(tok))
    assert r.status_code == 200, r.text
    body = r.json()
    # The officer holds the doc grant, so the original preview is returned (ORIGINAL — STAYS LOCAL)...
    assert "Ayesha Khan" in body["original_preview"]
    # ...but the safe copy carries neither the budget ceiling nor any pseudonym's original, and never the canary.
    assert SECRET_CEILING not in body["safe_copy_preview"]
    assert CANARY not in body["safe_copy_preview"]
    assert "[REDACTED:BUDGET_FIGURE]" in body["safe_copy_preview"]
    assert body["findings"], "findings should be returned for highlighting"
    assert all("start" in f and "end" in f for f in body["findings"])


def test_artifact_unknown_id_is_404(client):
    tok = login(client, "ayesha.po")
    assert client.get("/api/privacy/artifacts/SA-does-not-exist", headers=auth(tok)).status_code == 404


def test_privacy_analyzed_audit_has_no_raw_values(client):
    tok = login(client, "ayesha.po")
    client.post("/api/privacy/analyze", headers=auth(tok), json={"document_id": FILM_DOC_ID})
    events = client.get("/api/audit/events", headers=auth(tok), params={"limit": "200"}).json()["events"]
    analyzed = [e for e in events if e["event_type"] == "privacy.analyzed"]
    assert analyzed, "a privacy.analyzed event must be recorded"
    blob = str(analyzed)
    assert CANARY not in blob and SECRET_CEILING not in blob and "Ayesha Khan" not in blob


def test_analyze_requires_auth(client):
    assert client.post("/api/privacy/analyze", json={"document_id": FILM_DOC_ID}).status_code == 401
