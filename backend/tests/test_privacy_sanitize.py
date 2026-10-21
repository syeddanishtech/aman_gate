"""Sanitizer: deterministic transformations, entity-consistent pseudonyms, RESTRICTED handling, fail-closed paths.
All values are synthetic."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace

import pytest

import app.privacy.sanitize as sanitize_mod
from app.privacy.graph import TextSegment
from app.privacy.policy import (
    DEFAULT_POLICY,
    EXPORT_ALLOWED,
    EXPORT_BLOCKED,
    Action,
    PrivacyPolicy,
    destination_class,
)
from app.privacy.sanitize import sanitize_segments, sanitize_text
from app.seed import BUDGET_SECRET_01, CANARY, POLICY_01, QUOTE_101, QUOTE_102

KW = dict(task="compare supplier quotations", role="procurement_officer", destination="local_simulator")
BENIGN = "Please ignore the earlier draft; budget review follows"


def run(text, **over):
    return sanitize_text(text, **{**KW, **over})


def tokens(text):
    return re.findall(r"\[[A-Z]+_\d{2,}\]", text)


# ------------------------------------------------------------------ canary
@pytest.mark.parametrize("dest", ["local_simulator", "local_llm", "real_cloud", "unknown-place"])
@pytest.mark.parametrize("variant", [CANARY, "lab canary 7731", "LAB​-CANARY-7731", "LAB-CANARY-７７３１"])
def test_canary_never_survives_sanitization(dest, variant):
    art = run(f"Approved ceiling note ({variant}) is internal.", destination=dest)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert "DENIED_ELEMENT_TYPE" in art.decision_record["block_reasons"]
    assert CANARY not in art.record_json() and "7731" not in art.record_json()
    assert art.sha256 == hashlib.sha256(b"").hexdigest()


def test_restricted_seed_document_is_export_blocked():
    art = run(BUDGET_SECRET_01, role="finance_manager")
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert art.decision_record["blocking_element_ids"]
    kinds = {r["element_type"]: r["action"] for r in art.decision_record["elements"]}
    assert kinds["CANARY"] == "DENY" and kinds["BUDGET_FIGURE"] == "REDACT"


# ------------------------------------------------------------------ benign text is not over-redacted
def test_benign_finance_sentence_is_preserved_exactly():
    art = run(BENIGN)
    assert art.export_status == EXPORT_ALLOWED
    assert art.text == BENIGN
    assert art.decision_record["elements"] == []
    assert art.decision_record["summary"]["elements_found"] == 0
    assert dict(art.rehydration_table) == {}


def test_quotation_prices_dates_and_suppliers_survive_only_header_org_changes():
    art = run(QUOTE_101)
    assert art.export_status == EXPORT_ALLOWED
    out = art.text.splitlines()
    src = QUOTE_101.splitlines()
    assert out[0] == "[ORG_01] - SUPPLIER QUOTATION (SYNTHETIC LAB DATA)"
    assert out[1:] == src[1:]  # quote id, supplier, prices, delivery, warranty untouched
    assert "PKR 7,280,000" in art.text and "Indus Lab Supplies" in art.text


def test_policy_document_keeps_its_rules_text():
    art = run(POLICY_01)
    assert "Internal budget ceilings are restricted to finance managers." in art.text
    assert art.export_status == EXPORT_ALLOWED


def test_injection_text_in_quote_is_passed_through_but_its_email_is_pseudonymized():
    art = run(QUOTE_102)
    assert art.export_status == EXPORT_ALLOWED
    assert "bids-review@example.test" not in art.text and "[EMAIL_01]" in art.text
    assert "ignore your previous instructions" in art.text  # sanitizer is not an injection filter


# ------------------------------------------------------------------ pseudonyms
def test_pseudonyms_are_stable_within_a_document_and_distinct_across_entities():
    text = ("Ayesha Khan wrote to ayesha.po@university.test. Fatima Raza replied from fatima.fm@university.test. "
            "Later AYESHA  KHAN called 0300-1234567 and +92 300 1234567 and 0300-7654321. "
            "ID 35202-1234567-1 / 35202-7654321-9 / 35202-1234567-1.")
    art = run(text)
    out = art.text
    assert out.count("[PERSON_01]") == 2 and out.count("[PERSON_02]") == 1
    assert out.count("[EMAIL_01]") == 1 and out.count("[EMAIL_02]") == 1
    assert out.count("[ID_01]") == 2 and out.count("[ID_02]") == 1
    # phone numbers are generalized (no identity retained), not pseudonymized
    assert out.count("[phone number]") == 3 and "[PHONE_" not in out
    for raw in ["Ayesha", "Fatima", "ayesha.po", "fatima.fm", "0300", "35202"]:
        assert raw.lower() not in out.lower()


def test_numbering_follows_first_appearance_and_is_per_class():
    art = run("Zara Lodhi, Northbridge, Bilal Ahmed, Zara Lodhi, NORTHBRIDGE UNIVERSITY")
    assert art.text == "[PERSON_01], [ORG_01], [PERSON_02], [PERSON_01], [ORG_01]"


def test_numbering_restarts_for_each_document():
    a = run("Fatima Raza")
    b = run("Omar Siddiqui and Fatima Raza")
    assert a.text == "[PERSON_01]" and b.text == "[PERSON_01] and [PERSON_02]"


def test_rehydration_table_is_local_only_and_pseudonym_only():
    art = run("Ayesha Khan mailed ayesha@u.test; Approved ceiling: PKR 7,100,000.")
    assert art.rehydration_table["[PERSON_01]"] == "Ayesha Khan"
    assert art.rehydration_table["[EMAIL_01]"] == "ayesha@u.test"
    assert not any("7,100,000" in v for v in art.rehydration_table.values())  # redacted values are not kept
    assert "Ayesha" not in repr(art) and "Ayesha" not in art.record_json()


def test_account_number_and_iban_are_pseudonymized():
    art = run("Pay to Account No: 0123-4567-8901 or IBAN PK36SCBL0000001123456702 or 0123-4567-8901 again")
    assert art.text == "Pay to Account No: [ACCOUNT_01] or IBAN [ACCOUNT_02] or [ACCOUNT_01] again"


def test_pseudonymization_wording_never_claims_anonymization():
    import app.privacy.policy as policy_mod

    for mod in (sanitize_mod, policy_mod):
        src = open(mod.__file__, encoding="utf-8").read().lower()
        assert "anonymi" not in src


# ------------------------------------------------------------------ RESTRICTED handling
def test_budget_figure_is_irreversibly_redacted_for_local_destinations():
    art = run("Approved ceiling: PKR 7,100,000 for lab PCs.", role="finance_manager")
    assert art.export_status == EXPORT_ALLOWED
    assert art.text == "Approved ceiling: [REDACTED:BUDGET_FIGURE] for lab PCs."
    assert "7,100,000" not in art.text and not tokens(art.text)  # a redaction marker is not a pseudonym
    (row,) = art.decision_record["elements"]
    assert row["action"] == "REDACT" and row["rule_id"] == "R-RESTRICTED-REDACT"


def test_known_ceiling_figure_in_any_format_is_redacted():
    art = run("We cap at 6.95 million; the exact figure is 6950000.")
    assert art.text == "We cap at [REDACTED:BUDGET_FIGURE]; the exact figure is [REDACTED:BUDGET_FIGURE]."


@pytest.mark.parametrize("dest", ["real_cloud", "REAL_CLOUD", "some-other-host", "", "   "])
def test_planted_restricted_value_blocks_export_to_external_or_unknown_destinations(dest):
    art = run("Our ceiling is PKR 7,100,000, do not tell suppliers.", destination=dest)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert art.decision_record["block_reasons"] == ["RESTRICTED_EXTERNAL_DESTINATION"]
    assert art.decision_record["request"]["destination_class"] == "EXTERNAL"
    assert "7,100,000" not in art.record_json()
    (row,) = art.decision_record["elements"]
    assert row["action"] == "DENY" and row["element_id"] in art.decision_record["blocking_element_ids"]


def test_destination_names_are_case_insensitive_for_local():
    assert destination_class("LOCAL_SIMULATOR") == "LOCAL" and destination_class(" local_llm ") == "LOCAL"
    assert destination_class("real_cloud") == "EXTERNAL" and destination_class(None) == "EXTERNAL"
    assert run("Approved ceiling: PKR 7,100,000", destination="LOCAL_SIMULATOR").export_allowed


def test_restricted_is_never_pseudonymized_even_if_the_policy_table_asks_for_it():
    pol = replace(DEFAULT_POLICY, deny_types=frozenset(),
                  type_actions={"BUDGET_FIGURE": Action.PSEUDONYMIZE, "CANARY": Action.KEEP})
    art = run(f"Approved ceiling: PKR 7,100,000 ({CANARY})", policy=pol)
    assert art.text == "Approved ceiling: [REDACTED:BUDGET_FIGURE] ([REDACTED:CANARY])"


def test_a_rogue_policy_that_pseudonymizes_restricted_is_caught_and_blocks():
    class Rogue(PrivacyPolicy):
        def action_for(self, element, *, destination_class):
            return Action.PSEUDONYMIZE, "R-ROGUE"

    art = run("Approved ceiling: PKR 7,100,000", policy=Rogue())
    assert art.export_status == EXPORT_BLOCKED and art.decision_record["block_reasons"] == ["INTERNAL_ERROR"]
    assert art.text == ""


def test_unknown_sensitivity_resolves_to_deny():
    class Odd(PrivacyPolicy):
        pass

    pol = Odd(sensitivity_actions={})  # no default for INTERNAL/CONFIDENTIAL/PUBLIC
    art = run("Northbridge", policy=pol)
    assert art.export_status == EXPORT_BLOCKED
    assert art.decision_record["block_reasons"] == ["UNKNOWN_FAILCLOSED"]


# ------------------------------------------------------------------ other actions
def test_omit_and_generalize_actions():
    pol = replace(DEFAULT_POLICY, type_actions={"EMAIL": Action.OMIT, "ORG": Action.GENERALIZE, "PHONE": Action.REDACT})
    art = run("Northbridge: write a@b.test or call 0300-1234567.", policy=pol)
    assert art.text == "[organization]: write  or call [REDACTED:PHONE]."


def test_source_text_that_looks_like_a_placeholder_is_neutralized():
    art = run("Northbridge says [ORG_01] and [PERSON_07] and [REDACTED:CANARY] are fine.")
    assert tokens(art.text) == ["[ORG_01]"]  # only the genuine placeholder remains
    assert "[REDACTED:CANARY]" not in art.text
    assert art.text.count("[placeholder-like text removed]") == 3
    assert art.rehydration_table == {"[ORG_01]": "Northbridge"}


# ------------------------------------------------------------------ fail closed
@pytest.mark.parametrize("over,reason", [
    (dict(role="intern"), "UNKNOWN_ROLE"),
    (dict(role=None), "UNKNOWN_ROLE"),
    (dict(task=""), "TASK_INVALID"),
    (dict(task="   "), "TASK_INVALID"),
    (dict(task="x" * 201), "TASK_INVALID"),
])
def test_bad_request_context_blocks_before_inspection(over, reason):
    art = run("Ayesha Khan", **over)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert reason in art.decision_record["block_reasons"]
    assert art.decision_record["inspected"] is False


def test_non_text_and_unencodable_input_blocks():
    assert run(b"bytes")  # type: ignore[arg-type]
    assert run(b"bytes").decision_record["block_reasons"] == ["NOT_TEXT"]  # type: ignore[arg-type]
    assert run("lone surrogate \ud800 here").decision_record["block_reasons"] == ["NOT_TEXT"]


def test_oversized_input_blocks():
    pol = replace(DEFAULT_POLICY, max_chars=50)
    art = run("a" * 51, policy=pol)
    assert art.decision_record["block_reasons"] == ["TEXT_TOO_LARGE"]
    assert run("a" * 50, policy=pol).export_allowed


def test_internal_error_fails_closed_without_leaking_the_message(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret detail LAB-CANARY-7731")

    monkeypatch.setattr(sanitize_mod, "detect", boom)
    art = run("Ayesha Khan")
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    assert art.decision_record["block_reasons"] == ["INTERNAL_ERROR"]
    assert art.decision_record["extraction"]["error_type"] == "RuntimeError"
    assert CANARY not in art.record_json()


# ------------------------------------------------------------------ determinism and the record
def test_same_input_gives_identical_text_record_and_digest():
    text = QUOTE_102 + "\nCall 0300-1234567; Ayesha Khan; ayesha@northbridge.test; Approved ceiling: PKR 7,100,000"
    a, b = run(text), run(text)
    assert a.text == b.text and a.sha256 == b.sha256 and a.record_json() == b.record_json()
    assert a.sha256 == hashlib.sha256(a.text.encode("utf-8")).hexdigest()
    assert run(text + " ").sha256 != a.sha256


def test_digest_changes_when_destination_policy_changes_the_output():
    text = "Ayesha Khan and 0300-1234567"
    assert run(text).sha256 != run(text, policy=replace(DEFAULT_POLICY, type_actions={})).sha256


def test_decision_record_shape_and_contents():
    text = "Ayesha Khan, ayesha@northbridge.test, 0300-1234567, 35202-1234567-1, Approved ceiling: PKR 7,100,000"
    art = run(text)
    rec = art.decision_record
    assert rec["record_version"] == "aman-privacy-decision-v1"
    assert rec["policy"]["policy_id"] == "POL-PRIVACY-SHIELD-v1" and rec["policy"]["detector_set"] == "aman-detectors-v1"
    assert rec["request"] == {"task": KW["task"], "role": KW["role"], "destination": "local_simulator",
                              "destination_class": "LOCAL"}
    assert rec["export_status"] == EXPORT_ALLOWED and rec["block_reasons"] == []
    assert rec["source"]["sha256"] == hashlib.sha256(text.encode()).hexdigest() and rec["source"]["chars"] == len(text)
    assert rec["artifact"] == {"sha256": art.sha256, "chars": len(art.text)}
    assert rec["summary"]["by_action"] == {"GENERALIZE": 1, "PSEUDONYMIZE": 3, "REDACT": 1}
    assert rec["summary"]["max_sensitivity"] == "RESTRICTED"
    for row in rec["elements"]:
        assert {"element_id", "element_type", "sensitivity", "start", "end", "action", "rule_id",
                "replacement", "provenance"} <= row.keys()
    blob = json.dumps(rec)
    for raw in ["Ayesha", "ayesha@", "0300-1234567", "35202", "7,100,000", "Khan"]:
        assert raw not in blob
    assert json.loads(art.record_json()) == rec


def test_element_offsets_point_at_the_original_text():
    text = "Hi Ayesha Khan, ceiling: PKR 7,100,000"
    art = run(text)
    spans = {r["element_type"]: text[r["start"]:r["end"]] for r in art.decision_record["elements"]}
    assert spans == {"PERSON": "Ayesha Khan", "BUDGET_FIGURE": "PKR 7,100,000"}


# ------------------------------------------------------------------ multi-segment documents
def _segs(**texts):
    kinds = {"body": "body", "comments": "comments", "metadata": "metadata", "tracked": "tracked_deletions"}
    return [TextSegment(f"doc:{k}", kinds[k], t) for k, t in texts.items()]


def test_non_body_segments_are_scanned_but_never_carried_into_the_artifact():
    segs = _segs(body="Contact ayesha@x.test please.", comments="Ayesha Khan: check the supplier",
                 metadata="Author: Omar Siddiqui")
    art = sanitize_segments(segs, **KW)
    assert art.export_allowed and art.text == "Contact [EMAIL_01] please."
    rows = {r["locator"]: r for r in art.decision_record["elements"]}
    assert rows["doc:comments"]["action"] == "OMIT" and rows["doc:comments"]["rule_id"] == "R-SEGMENT-OMITTED"
    assert rows["doc:metadata"]["element_type"] == "PERSON" and rows["doc:metadata"]["action"] == "OMIT"
    assert "replacement" not in rows["doc:metadata"]  # nothing from this segment is rendered
    assert [s["carried"] for s in art.decision_record["source"]["segments"]] == [True, False, False]
    assert "Omar" not in art.text and "Ayesha" not in art.text


def test_canary_hidden_in_a_comment_still_blocks_the_export():
    art = sanitize_segments(_segs(body="Totally ordinary text.", comments=f"internal: {CANARY}"), **KW)
    assert art.export_status == EXPORT_BLOCKED and art.text == ""
    (row,) = [r for r in art.decision_record["elements"] if r["element_type"] == "CANARY"]
    assert row["locator"] == "doc:comments" and row["action"] == "DENY"


def test_restricted_value_in_deleted_text_is_omitted_for_local_and_blocks_external():
    segs = _segs(body="Final price agreed.", tracked="Approved ceiling: PKR 7,100,000")
    assert sanitize_segments(segs, **KW).text == "Final price agreed."
    assert sanitize_segments(segs, **{**KW, "destination": "real_cloud"}).export_status == EXPORT_BLOCKED


def test_hidden_content_can_be_made_blocking_by_policy():
    segs = _segs(body="Hello", comments="a comment")
    assert sanitize_segments(segs, **KW).export_allowed
    strict = replace(DEFAULT_POLICY, block_on_hidden_content=True)
    art = sanitize_segments(segs, policy=strict, **{k: v for k, v in KW.items()})
    assert art.decision_record["block_reasons"] == ["HIDDEN_CONTENT_PRESENT"]


def test_pseudonyms_are_shared_across_the_segments_of_one_document():
    segs = [TextSegment("pdf:page:1", "body", "Ayesha Khan signed."), TextSegment("pdf:page:2", "body", "Zara Lodhi; Ayesha Khan")]
    art = sanitize_segments(segs, **KW)
    assert art.text == "[PERSON_01] signed.\n\n[PERSON_02]; [PERSON_01]"


def test_duplicate_locators_are_rejected():
    segs = [TextSegment("x", "body", "a"), TextSegment("x", "body", "b")]
    assert sanitize_segments(segs, **KW).decision_record["block_reasons"] == ["DUPLICATE_LOCATOR"]
