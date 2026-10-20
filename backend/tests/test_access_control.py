"""Document ACL, IDOR, path traversal, tenant confusion — tested through the HTTP API directly."""
from __future__ import annotations

import pytest
from conftest import auth, login


def inv(client, tok, tool, args):
    return client.post("/api/tools/invoke", headers=auth(tok), json={"tool": tool, "args": args})


def test_officer_can_read_quotations(client):
    tok = login(client, "ayesha.po")
    for q in ("QUOTE-101", "QUOTE-102"):
        r = client.get(f"/api/documents/{q}", headers=auth(tok))
        assert r.status_code == 200


def test_officer_cannot_read_budget(client):
    tok = login(client, "ayesha.po")
    r = client.get("/api/documents/BUDGET-SECRET-01", headers=auth(tok))
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "ACL_DENIED"


def test_finance_manager_can_read_budget(client):
    tok = login(client, "fatima.fm")
    r = client.get("/api/documents/BUDGET-SECRET-01", headers=auth(tok))
    assert r.status_code == 200
    assert "BUDGET-SECRET-01" in r.json()["document"]["content"]


def test_clerk_cannot_read_budget(client):
    tok = login(client, "bilal.clerk")
    assert inv(client, tok, "read_document", {"document_id": "BUDGET-SECRET-01"}).json()["decision"] == "DENY"


def test_budget_read_via_tool_also_denied(client):
    """ACL is enforced on the tool path too, not only the UI route."""
    tok = login(client, "ayesha.po")
    r = inv(client, tok, "read_document", {"document_id": "BUDGET-SECRET-01"})
    body = r.json()
    assert body["decision"] == "DENY"
    assert body["reason_codes"] == ["ACL_DENIED"]
    # content must not leak in the tool output
    assert body["output"] is None


@pytest.mark.parametrize("bad", [
    "../../etc/passwd", "..\\..\\windows", "BUDGET-SECRET-01/../POLICY-01", "'; DROP TABLE documents;--",
    "QUOTE-101 OR 1=1", "%2e%2e%2f", "QUOTE_101", "quote-101",
])
def test_path_traversal_and_injection_ids_rejected(client, bad):
    tok = login(client, "ayesha.po")
    r = inv(client, tok, "read_document", {"document_id": bad})
    assert r.json()["decision"] == "DENY"  # schema or ACL, never ALLOW


def test_idor_cross_tenant_document_hidden(client):
    """An officer of Northbridge must not reach the other tenant's SF-QUOTE-001 (IDOR)."""
    tok = login(client, "ayesha.po")
    r = inv(client, tok, "read_document", {"document_id": "SF-QUOTE-001"})
    body = r.json()
    assert body["decision"] == "DENY"
    assert body["reason_codes"] == ["RESOURCE_NOT_ACCESSIBLE"]  # indistinguishable from not-found


def test_compare_includes_unauthorized_doc_denied(client):
    tok = login(client, "ayesha.po")
    r = inv(client, tok, "compare_quotations", {"quote_ids": ["QUOTE-101", "BUDGET-SECRET-01"]})
    body = r.json()
    # BUDGET is not a quotation AND not readable -> whole call denied
    assert body["decision"] == "DENY"


def test_document_list_readable_flags_match_role(client):
    po = login(client, "ayesha.po")
    fm = login(client, "fatima.fm")
    po_docs = {d["document_id"]: d["readable"] for d in client.get("/api/documents", headers=auth(po)).json()["documents"]}
    fm_docs = {d["document_id"]: d["readable"] for d in client.get("/api/documents", headers=auth(fm)).json()["documents"]}
    assert po_docs["BUDGET-SECRET-01"] is False
    assert fm_docs["BUDGET-SECRET-01"] is True
    # Cross-tenant doc is not even listed for Northbridge users
    assert "SF-QUOTE-001" not in po_docs
