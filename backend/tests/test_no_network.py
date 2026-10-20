"""Guarantee the app opens no outbound sockets during a full workflow (no real exfiltration)."""
from __future__ import annotations

import socket

import pytest
from conftest import auth, login


@pytest.fixture()
def block_network(monkeypatch):
    real_connect = socket.socket.connect
    allowed_hosts = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
    calls = []

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else str(address)
        calls.append(host)
        if host not in allowed_hosts:
            raise AssertionError(f"Outbound network connection attempted to {host}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)
    return calls


def test_full_send_flow_opens_no_external_socket(client, block_network):
    po = login(client, "ayesha.po")
    fm = login(client, "fatima.fm")
    draft = client.post("/api/tools/invoke", headers=auth(po),
                        json={"tool": "draft_purchase_summary",
                              "args": {"quote_ids": ["QUOTE-101", "QUOTE-103"]}}).json()
    rid = draft["output"]["report_id"]
    apid = client.post("/api/tools/invoke", headers=auth(po),
                       json={"tool": "send_report",
                             "args": {"destination": "finance-approvals@university.test",
                                      "report_id": rid}}).json()["approval_id"]
    client.post(f"/api/approvals/{apid}/decision", headers=auth(fm), json={"approve": True})
    ex = client.post(f"/api/approvals/{apid}/execute", headers=auth(po))
    assert ex.status_code == 200
    # Everything delivered to a local simulator; no non-local host was contacted.
    assert ex.json()["delivered"] == "local-simulator"


def test_running_every_scenario_opens_no_external_socket(client, block_network):
    tok = login(client, "ayesha.po")
    sids = [s["id"] for s in client.get("/api/scenarios", headers=auth(tok)).json()["scenarios"]]
    for sid in sids:
        client.post("/api/scenarios/run", headers=auth(tok), json={"scenario_id": sid})
    # If any non-local connect had occurred, the guard would have raised.
