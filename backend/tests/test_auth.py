"""Authentication & JWT hardening: missing/forged/expired tokens, alg confusion, role from DB."""
from __future__ import annotations

import time

import jwt
import pytest
from conftest import auth, login


def test_login_success_and_me(client):
    tok = login(client, "ayesha.po")
    assert tok
    r = client.get("/api/me", headers=auth(tok))
    assert r.status_code == 200
    assert r.json()["role"] == "procurement_officer"


def test_wrong_password_rejected(client):
    assert login(client, "ayesha.po", "wrong-password") is None


def test_missing_token_rejected(client):
    r = client.get("/api/me")
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "AUTH_MISSING_TOKEN"


def test_garbage_token_rejected(client):
    r = client.get("/api/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_alg_none_forgery_rejected(client):
    # Attacker crafts an unsigned token (alg=none) claiming to be a finance manager.
    forged = jwt.encode({"sub": "u-fm-01", "iss": "aman-gate-lab", "aud": "aman-gate-api",
                         "iat": int(time.time()), "exp": int(time.time()) + 999}, key="", algorithm="none")
    r = client.get("/api/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_wrong_secret_forgery_rejected(client):
    forged = jwt.encode({"sub": "u-fm-01", "iss": "aman-gate-lab", "aud": "aman-gate-api",
                         "iat": int(time.time()), "exp": int(time.time()) + 999},
                        key="attacker-secret", algorithm="HS256")
    r = client.get("/api/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_expired_token_rejected(client):
    cfg = client._modules["config"]
    sec = client._modules["security"]
    now = int(time.time())
    expired = jwt.encode({"sub": "u-po-01", "iss": sec.ISSUER, "aud": sec.AUDIENCE,
                          "iat": now - 10000, "nbf": now - 10000, "exp": now - 5000},
                         key=cfg.settings.jwt_secret, algorithm="HS256")
    r = client.get("/api/me", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "AUTH_TOKEN_EXPIRED"


def test_role_claim_in_token_does_not_escalate(client):
    """A valid token for a clerk, but with a forged role_hint=finance_manager, must NOT grant budget access.
    The server authorises from the database role, not the token claim."""
    cfg = client._modules["config"]
    sec = client._modules["security"]
    now = int(time.time())
    tok = jwt.encode({"sub": "u-jc-01", "iss": sec.ISSUER, "aud": sec.AUDIENCE, "iat": now, "nbf": now,
                      "exp": now + 999, "role_hint": "finance_manager", "jti": "x"},
                     key=cfg.settings.jwt_secret, algorithm="HS256")
    # /me reports the true DB role
    assert client.get("/api/me", headers=auth(tok)).json()["role"] == "junior_clerk"
    # budget read still denied
    r = client.post("/api/tools/invoke", headers=auth(tok),
                    json={"tool": "read_document", "args": {"document_id": "BUDGET-SECRET-01"}})
    assert r.json()["decision"] == "DENY"


def test_unknown_subject_rejected(client):
    cfg = client._modules["config"]
    sec = client._modules["security"]
    now = int(time.time())
    tok = jwt.encode({"sub": "u-does-not-exist", "iss": sec.ISSUER, "aud": sec.AUDIENCE, "iat": now,
                      "nbf": now, "exp": now + 999}, key=cfg.settings.jwt_secret, algorithm="HS256")
    r = client.get("/api/me", headers=auth(tok))
    assert r.status_code == 401
