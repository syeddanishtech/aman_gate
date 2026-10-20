"""Tool allowlist, strict schemas, RBAC, destination policy, forbidden tool, nested-JSON payloads."""
from __future__ import annotations

import pytest
from conftest import auth, login


def inv(client, tok, tool, args, extra=None):
    body = {"tool": tool, "args": args}
    if extra:
        body.update(extra)
    return client.post("/api/tools/invoke", headers=auth(tok), json=body)


def test_unknown_tool_denied(client):
    tok = login(client, "ayesha.po")
    r = inv(client, tok, "run_shell_command", {"command": "rm -rf /"})
    assert r.json()["decision"] == "DENY"
    assert r.json()["reason_codes"] == ["UNKNOWN_TOOL"]


def test_freeform_tool_name_denied(client):
    tok = login(client, "ayesha.po")
    for name in ("eval", "os.system", "read_document; drop", "simulated_external_sink "):
        assert inv(client, tok, name, {}).json()["decision"] == "DENY"


def test_external_sink_always_forbidden(client):
    for u in ("ayesha.po", "fatima.fm", "sana.sa", "bilal.clerk"):
        tok = login(client, u)
        r = inv(client, tok, "simulated_external_sink", {"payload_summary": "x"})
        assert r.json()["decision"] == "DENY"
        assert r.json()["reason_codes"] == ["TOOL_FORBIDDEN"]


def test_rbac_clerk_cannot_draft_summary(client):
    tok = login(client, "bilal.clerk")
    r = inv(client, tok, "draft_purchase_summary", {"quote_ids": ["QUOTE-101", "QUOTE-103"]})
    assert r.json()["decision"] == "DENY"
    assert r.json()["reason_codes"] == ["ROLE_NOT_PERMITTED"]


def test_security_analyst_cannot_compare(client):
    tok = login(client, "sana.sa")
    r = inv(client, tok, "compare_quotations", {"quote_ids": ["QUOTE-101", "QUOTE-103"]})
    assert r.json()["decision"] == "DENY"
    assert r.json()["reason_codes"] == ["ROLE_NOT_PERMITTED"]


@pytest.mark.parametrize("args", [
    {},                                              # missing
    {"quote_ids": ["QUOTE-101"]},                    # too few
    {"quote_ids": ["QUOTE-101", "QUOTE-101"]},       # duplicates
    {"quote_ids": "QUOTE-101,QUOTE-102"},            # wrong type
    {"quote_ids": ["QUOTE-101", "QUOTE-102"], "x": 1},  # extra field
    {"quote_ids": ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6"]},  # too many
])
def test_compare_schema_rejections(client, args):
    tok = login(client, "ayesha.po")
    assert inv(client, tok, "compare_quotations", args).json()["decision"] == "DENY"


def test_extra_field_forbidden_everywhere(client):
    tok = login(client, "ayesha.po")
    r = inv(client, tok, "read_document", {"document_id": "QUOTE-101", "override_acl": True})
    assert r.json()["decision"] == "DENY"
    assert "SCHEMA_INVALID" in r.json()["reason_codes"]


def test_deeply_nested_payload_rejected(client):
    tok = login(client, "ayesha.po")
    nested = {"document_id": "QUOTE-101"}
    cur = nested
    for _ in range(12):
        cur["child"] = {}
        cur = cur["child"]
    r = inv(client, tok, "read_document", nested)
    assert r.json()["decision"] == "DENY"


def test_oversized_payload_rejected(client):
    tok = login(client, "ayesha.po")
    r = inv(client, tok, "read_document", {"document_id": "QUOTE-101", "blob": "A" * 20000})
    assert r.json()["decision"] == "DENY"


def test_send_to_unapproved_destination_denied(client):
    tok = login(client, "ayesha.po")
    draft = inv(client, tok, "draft_purchase_summary", {"quote_ids": ["QUOTE-101", "QUOTE-103"]}).json()
    rid = draft["output"]["report_id"]
    r = inv(client, tok, "send_report", {"destination": "bids-review@example.test", "report_id": rid})
    body = r.json()
    assert body["decision"] == "DENY"
    assert "DEST_NOT_ALLOWLISTED" in body["reason_codes"]
    assert "DEST_EXPLICITLY_UNAPPROVED_DOMAIN" in body["reason_codes"]


def test_send_to_allowlisted_destination_needs_approval(client):
    tok = login(client, "ayesha.po")
    draft = inv(client, tok, "draft_purchase_summary", {"quote_ids": ["QUOTE-101", "QUOTE-103"]}).json()
    rid = draft["output"]["report_id"]
    r = inv(client, tok, "send_report", {"destination": "finance-approvals@university.test", "report_id": rid})
    assert r.json()["decision"] == "NEEDS_APPROVAL"


def test_send_report_not_owned_denied(client):
    """A user cannot send someone else's report (report ownership)."""
    po = login(client, "ayesha.po")
    draft = inv(client, po, "draft_purchase_summary", {"quote_ids": ["QUOTE-101", "QUOTE-103"]}).json()
    rid = draft["output"]["report_id"]
    other = login(client, "omar.fm")  # finance manager, different user
    r = inv(client, other, "send_report", {"destination": "finance-approvals@university.test", "report_id": rid})
    assert r.json()["decision"] == "DENY"
    assert "REPORT_NOT_ACCESSIBLE" in r.json()["reason_codes"]


def test_tool_output_never_contains_document_content(client):
    tok = login(client, "fatima.fm")
    r = inv(client, tok, "read_document", {"document_id": "BUDGET-SECRET-01"})
    assert r.json()["decision"] == "ALLOW"
    # the generic tool endpoint strips content
    assert "content" not in (r.json()["output"] or {})
