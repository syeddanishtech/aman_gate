"""Test harness. A single app instance is backed by a dedicated temp SQLite file; each test resets the
demo data so the audit chain is deterministic. Tests drive the HTTP API directly (not the UI) so every
assertion targets real server-side enforcement."""
from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

import pytest

# Pin a demo environment with fixed, sufficiently long secrets BEFORE importing app.config.
_TMP = Path(tempfile.gettempdir()) / f"aman_gate_test_{uuid.uuid4().hex}.db"
os.environ["AMAN_ENV"] = "demo"
os.environ["AMAN_DATABASE_URL"] = f"sqlite:///{_TMP.as_posix()}"
os.environ["AMAN_JWT_SECRET"] = "test-jwt-secret-with-sufficient-length-0001"
os.environ["AMAN_AUDIT_HMAC_KEY"] = "test-audit-hmac-key-with-sufficient-len-0001"
os.environ["AMAN_DEMO_PASSWORD"] = "Lab-Only-Demo-2026!"

from fastapi.testclient import TestClient  # noqa: E402

import app.audit as audit  # noqa: E402
import app.bootstrap as bootstrap  # noqa: E402
import app.config as config  # noqa: E402
import app.db as db  # noqa: E402
import app.gateway as gateway  # noqa: E402
import app.main as main  # noqa: E402
import app.models as models  # noqa: E402
import app.security as security  # noqa: E402

MODULES = {"db": db, "models": models, "audit": audit, "gateway": gateway,
           "security": security, "config": config, "bootstrap": bootstrap}
DEMO_PW = "Lab-Only-Demo-2026!"


@pytest.fixture()
def client():
    bootstrap.reset_demo()  # fresh seed + empty audit chain for each test
    with TestClient(main.app) as c:
        c._modules = MODULES
        yield c


def pytest_sessionfinish(session, exitstatus):
    for p in _TMP.parent.glob(_TMP.name + "*"):
        try:
            p.unlink()
        except OSError:
            pass


def login(client, username: str, password: str = DEMO_PW) -> str | None:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    return r.json()["access_token"] if r.status_code == 200 else None


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
