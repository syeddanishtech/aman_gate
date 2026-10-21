"""End to end: extract -> sanitize -> independent verify, and persistence of the decision record.
Scanned / uncertain documents must end as EXPORT_BLOCKED. All data is synthetic and local."""
from __future__ import annotations

import json
import socket

import pytest
from privacy_fixtures import (
    app_xml,
    core_xml,
    dele,
    make_docx,
    make_pdf,
    para,
    run,
    xmp_packet,
)

import app.privacy.sanitize as sanitize_mod
from app.db import SessionLocal
from app.privacy.models import PrivacyDecision, create_privacy_schema, store_decision
from app.privacy.pipeline import protect_document, protect_text
from app.privacy.policy import EXPORT_ALLOWED, EXPORT_BLOCKED, Action
from app.privacy.sanitize import sanitize_text
from app.seed import CANARY, QUOTE_102

KW = dict(task="compare supplier quotations", role="procurement_officer", destination="local_simulator")


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    """The whole shield must work with the network physically unavailable."""
    def refuse(*a, **k):
        raise AssertionError("privacy shield attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)


# ------------------------------------------------------------------ text
def test_protect_text_returns_a_verified_artifact():
    art = protect_text("Ayesha Khan quoted PKR 7,280,000. Please ignore the earlier draft; budget review follows",
                       **KW)
    assert art.export_allowed
    assert art.text == "[PERSON_01] quoted PKR 7,280,000. Please ignore the earlier draft; budget review follows"
    v = art.decision_record["verification"]
    assert v["passed"] is True and v["findings"] == [] and "RESIDUAL_SCAN" in v["checks_run"]


def test_a_detection_bug_in_the_sanitizer_is_caught_by_the_independent_verifier(monkeypatch):
    real_detect = sanitize_mod.detect

    def blind_to_email(*a, **k):  # simulates the sanitizer's detector missing a finding
        g = real_detect(*a, **k)
        return type(g)(g.source_sha256, [e for e in g if e.element_type != "EMAIL"])

    monkeypatch.setattr(sanitize_mod, "detect", blind_to_email)  # verify.py keeps its own, untouched binding
    text = "Mail Ayesha Khan at ayesha@northbridge.test"
    leaky = sanitize_text(text, **KW)
    assert leaky.export_allowed and "ayesha@northbridge.test" in leaky.text  # sanitize alone would have shipped it
    art = protect_text(text, **KW)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert "VERIFICATION_FAILED" in art.decision_record["block_reasons"]
    assert art.decision_record["blocking_element_ids"]
    assert art.decision_record["verification"]["passed"] is False
    assert art.decision_record["verification"]["findings"][0]["code"] == "RESIDUAL_DETECTED"
    assert "ayesha@" not in art.record_json()


def test_a_renderer_bug_is_caught_by_the_sanitizers_own_self_check(monkeypatch):
    real = sanitize_mod._render

    def buggy(element, action, pseud):  # simulates a transformation that forgets to transform
        return element.text if action is Action.PSEUDONYMIZE else real(element, action, pseud)

    monkeypatch.setattr(sanitize_mod, "_render", buggy)
    art = protect_text("Mail Ayesha Khan at ayesha@northbridge.test", **KW)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert art.decision_record["block_reasons"] == ["INTERNAL_ERROR"]
    assert "ayesha@" not in art.record_json() and "Ayesha" not in art.record_json()  # the bad value is not recorded


def test_pipeline_output_is_replayable():
    a = protect_text(QUOTE_102, **KW)
    b = protect_text(QUOTE_102, **KW)
    assert a.sha256 == b.sha256 and a.record_json() == b.record_json() and a.text == b.text


def test_external_destination_with_a_planted_restricted_value_is_export_blocked():
    art = protect_text("Our ceiling is PKR 7,100,000, keep it quiet.", **{**KW, "destination": "real_cloud"})
    assert art.export_status == EXPORT_BLOCKED and art.text == ""


def test_every_seed_document_goes_through_the_pipeline_without_error():
    from app.seed import DOCS

    for did, _title, _type, _cls, _trust, content, _acl, _fx in DOCS:
        art = protect_text(content, task="review documents", role="finance_manager", destination="local_simulator")
        assert "LAB-CANARY" not in art.text.upper() and CANARY not in art.record_json(), did
        if did == "BUDGET-SECRET-01":
            assert art.export_status == EXPORT_BLOCKED and art.text == "", did
        else:
            assert art.export_allowed and art.decision_record["verification"]["passed"], did
            assert "Northbridge".lower() not in art.text.lower(), did  # institution name always pseudonymized


def test_privacy_package_imports_no_network_modules():
    import ast
    from pathlib import Path

    import app.privacy as pkg

    banned = {"socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp", "ftplib", "smtplib",
              "telnetlib", "xmlrpc", "websockets", "subprocess"}
    for path in Path(pkg.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                    else [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else [])
            assert not {m.split(".")[0] for m in mods} & banned, (path.name, mods)


# ------------------------------------------------------------------ documents
def test_scanned_pdf_stub_is_review_required_and_export_blocked():
    art = protect_document(make_pdf([[]], image_on_page=0), "scan.pdf", **KW)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    rec = art.decision_record
    assert rec["block_reasons"] == ["EXTRACTION_REVIEW_REQUIRED"]
    assert rec["extraction"]["status"] == "REVIEW_REQUIRED"
    assert {"PDF_NO_EXTRACTABLE_TEXT", "PDF_IMAGES_UNREVIEWED"} <= set(rec["extraction"]["review_reasons"])
    assert rec["inspected"] is False


@pytest.mark.parametrize("data,name,reason", [
    (b"\x89PNG\r\n\x1a\n\x00\x00", "logo.png", "UNSUPPORTED_TYPE"),
    (b"%PDF-1.4 truncated", "x.pdf", "PDF_PARSE_ERROR"),
    (make_docx(para(run("x")), extra_parts={"word/media/a.png": b"x"}), "x.docx", "GRAPHIC_CONTENT_UNREVIEWED"),
    (make_pdf([["x"]]), "renamed.txt", "TYPE_MISMATCH"),
])
def test_unsupported_or_uncertain_documents_are_blocked(data, name, reason):
    art = protect_document(data, name, **KW)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert reason in art.decision_record["extraction"]["review_reasons"]


def test_born_digital_pdf_text_is_sanitized_and_metadata_never_travels():
    pdf = make_pdf([["Quote for Ayesha Khan", "Contact ayesha@northbridge.test", "Total: PKR 7,280,000"]],
                   info={"Author": "Fatima Raza", "Title": "Quote 101"}, xmp=xmp_packet("Omar Siddiqui"),
                   annotation_text="reviewer: Sana Malik")
    art = protect_document(pdf, "quote.pdf", **KW)
    assert art.export_allowed
    assert art.text == "Quote for [PERSON_01]\nContact [EMAIL_01]\nTotal: PKR 7,280,000"
    for name in ("Fatima", "Omar", "Sana", "Siddiqui", "Quote 101"):
        assert name not in art.text
    rows = {r["locator"]: r for r in art.decision_record["elements"]}
    assert rows["pdf:metadata:info"]["action"] == "OMIT" and rows["pdf:metadata:xmp"]["action"] == "OMIT"
    assert rows["pdf:annotations"]["action"] == "OMIT"
    assert art.decision_record["extraction"]["features"]["xmp_present"] is True


def test_multi_page_pdf_shares_pseudonyms_across_pages():
    art = protect_document(make_pdf([["Ayesha Khan signed"], ["Zara Lodhi; Ayesha Khan"]]), "two.pdf", **KW)
    assert art.text == "[PERSON_01] signed\n\n[PERSON_02]; [PERSON_01]"


def test_docx_with_comments_tracked_changes_and_hidden_text_exports_only_visible_text():
    body = para(run("Supplier: Northbridge-bound quote from Ayesha Khan. "),
                dele("Ceiling is PKR 7,100,000. "), run("hidden aside about Zara Lodhi", vanish=True),
                run("Price PKR 7,280,000."))
    docx = make_docx(body, comments=[("Bilal Ahmed", "please double-check the supplier totals")],
                     core=core_xml("Fatima Raza", "Omar Siddiqui", "Quote"), app=app_xml("Northbridge University"))
    art = protect_document(docx, "quote.docx", **KW)
    assert art.export_allowed
    assert art.text == "Supplier: [ORG_01]-bound quote from [PERSON_01]. Price PKR 7,280,000."
    rows = art.decision_record["elements"]
    omitted = {(r["locator"], r["element_type"]) for r in rows if r["action"] == "OMIT"}
    assert ("docx:tracked_deletions", "BUDGET_FIGURE") in omitted and ("docx:hidden_text", "PERSON") in omitted
    assert art.decision_record["extraction"]["features"]["tracked_changes"] is True


def test_canary_hidden_in_a_docx_comment_blocks_the_export():
    docx = make_docx(para(run("Perfectly ordinary supplier text.")), comments=[("QA", f"leftover {CANARY}")])
    art = protect_document(docx, "leak.docx", **KW)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert CANARY not in art.record_json()
    assert art.decision_record["block_reasons"] == ["DENIED_ELEMENT_TYPE"]


def test_restricted_figure_in_deleted_text_is_removed_locally_but_blocks_external_destinations():
    docx = make_docx(para(run("Final offer attached."), dele("Our ceiling is PKR 7,100,000.")))
    assert protect_document(docx, "t.docx", **KW).text == "Final offer attached."
    ext = protect_document(docx, "t.docx", **{**KW, "destination": "real_cloud"})
    assert ext.export_status == EXPORT_BLOCKED


def test_plain_txt_document_round_trip():
    art = protect_document(b"Approved ceiling: PKR 7,100,000\r\nCall 0300-1234567\r\n", "n.txt",
                           **{**KW, "role": "finance_manager"})
    assert art.text == "Approved ceiling: [REDACTED:BUDGET_FIGURE]\nCall [phone number]\n"


def test_document_pipeline_is_deterministic():
    docx = make_docx(para(run("Ayesha Khan, ayesha@x.test")), comments=[("A", "c")], core=core_xml("Z"))
    a, b = protect_document(docx, "d.docx", **KW), protect_document(docx, "d.docx", **KW)
    assert a.sha256 == b.sha256 and a.record_json() == b.record_json()


# ------------------------------------------------------------------ persistence
def test_decision_records_persist_without_raw_values():
    create_privacy_schema()
    create_privacy_schema()  # idempotent
    art = protect_text("Ayesha Khan, ayesha@northbridge.test, Approved ceiling: PKR 7,100,000", **KW)
    with SessionLocal() as s:
        row = store_decision(s, art, tenant_id="northbridge", actor_user_id="u-po-01")
        rid = row.id
    with SessionLocal() as s:
        got = s.get(PrivacyDecision, rid)
        assert got.export_status == EXPORT_ALLOWED and got.artifact_sha256 == art.sha256
        assert got.policy_id == "POL-PRIVACY-SHIELD-v1" and got.destination_class == "LOCAL"
        assert got.element_count == 3 and got.max_sensitivity == "RESTRICTED"
        assert got.record == art.decision_record
        blob = json.dumps(got.record)
        for raw in ("Ayesha", "ayesha@", "7,100,000"):
            assert raw not in blob
        s.delete(got)
        s.commit()
