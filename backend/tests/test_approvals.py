"""Approval state machine: two-person rule, self-approval block, expiry, replay/idempotency, race."""
from __future__ import annotations

import concurrent.futures

from conftest import auth, login


def draft_and_request(client, tok, dest="finance-approvals@university.test"):
    draft = client.post("/api/tools/invoke", headers=auth(tok),
                        json={"tool": "draft_purchase_summary",
                              "args": {"quote_ids": ["QUOTE-101", "QUOTE-103"]}}).json()
    rid = draft["output"]["report_id"]
    req = client.post("/api/tools/invoke", headers=auth(tok),
                      json={"tool": "send_report", "args": {"destination": dest, "report_id": rid}}).json()
    return req["approval_id"]


def test_requester_cannot_self_approve(client):
    tok = login(client, "fatima.fm")  # finance manager requests their own send
    apid = draft_and_request(client, tok)
    r = client.post(f"/api/approvals/{apid}/decision", headers=auth(tok), json={"approve": True})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "SELF_APPROVAL_BLOCKED"


def test_non_finance_cannot_decide(client):
    po = login(client, "ayesha.po")
    apid = draft_and_request(client, po)
    # officer tries to approve
    r = client.post(f"/api/approvals/{apid}/decision", headers=auth(po), json={"approve": True})
    assert r.status_code == 403


def test_full_two_person_flow_executes_once(client):
    po = login(client, "ayesha.po")
    fm = login(client, "fatima.fm")
    apid = draft_and_request(client, po)
    # different finance manager approves
    assert client.post(f"/api/approvals/{apid}/decision", headers=auth(fm), json={"approve": True}).status_code == 200
    # requester executes
    ex = client.post(f"/api/approvals/{apid}/execute", headers=auth(po))
    assert ex.status_code == 200
    assert ex.json()["status"] == "executed"
    # replay: second execute refused
    ex2 = client.post(f"/api/approvals/{apid}/execute", headers=auth(po))
    assert ex2.status_code == 409
    assert ex2.json()["detail"]["code"] == "ALREADY_EXECUTED"


def test_denied_approval_cannot_execute(client):
    po = login(client, "ayesha.po")
    fm = login(client, "fatima.fm")
    apid = draft_and_request(client, po)
    client.post(f"/api/approvals/{apid}/decision", headers=auth(fm), json={"approve": False})
    ex = client.post(f"/api/approvals/{apid}/execute", headers=auth(po))
    assert ex.status_code == 409
    assert ex.json()["detail"]["code"] == "NOT_APPROVED"


def test_expired_approval_cannot_execute(client):
    po = login(client, "ayesha.po")
    fm = login(client, "fatima.fm")
    apid = draft_and_request(client, po)
    # force expiry directly in the DB, then approve attempt should fail as not pending
    gateway = client._modules["gateway"]
    db_mod = client._modules["db"]
    from datetime import datetime, timezone
    s = db_mod.SessionLocal()
    ap = s.get(client._modules["models"].Approval, apid)
    ap.expires_at = datetime.now(timezone.utc).replace(tzinfo=None)
    s.commit()
    s.close()
    s2 = db_mod.SessionLocal()
    gateway.expire_due(s2)
    s2.close()
    # now approve should fail (not pending) and execute should fail
    dec = client.post(f"/api/approvals/{apid}/decision", headers=auth(fm), json={"approve": True})
    assert dec.status_code == 409
    ex = client.post(f"/api/approvals/{apid}/execute", headers=auth(po))
    assert ex.status_code == 409


def test_idempotent_request_returns_same_approval(client):
    po = login(client, "ayesha.po")
    draft = client.post("/api/tools/invoke", headers=auth(po),
                        json={"tool": "draft_purchase_summary",
                              "args": {"quote_ids": ["QUOTE-101", "QUOTE-103"]}}).json()
    rid = draft["output"]["report_id"]
    body = {"tool": "send_report",
            "args": {"destination": "finance-approvals@university.test", "report_id": rid}}
    a1 = client.post("/api/tools/invoke", headers=auth(po), json=body).json()["approval_id"]
    a2 = client.post("/api/tools/invoke", headers=auth(po), json=body).json()["approval_id"]
    assert a1 == a2  # no duplicate pending approvals for identical args


def test_concurrent_execute_only_one_succeeds(client):
    po = login(client, "ayesha.po")
    fm = login(client, "fatima.fm")
    apid = draft_and_request(client, po)
    client.post(f"/api/approvals/{apid}/decision", headers=auth(fm), json={"approve": True})

    def do_exec(_):
        return client.post(f"/api/approvals/{apid}/execute", headers=auth(po)).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        codes = list(ex.map(do_exec, range(6)))
    assert codes.count(200) == 1
    assert codes.count(409) == 5
