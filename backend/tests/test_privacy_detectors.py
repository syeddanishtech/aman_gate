"""Deterministic detectors: one test group per pattern, plus normalization, overlap and vocabulary rules.
All values are synthetic."""
from __future__ import annotations

import json

import pytest

from app.privacy.detectors import (
    DEFAULT_VOCABULARY,
    DETECTOR_SET_VERSION,
    PATTERN_DETECTORS,
    InstitutionVocabulary,
    VocabEntry,
    detect,
    figure_patterns,
    fold,
    normalize_with_map,
    squash,
)
from app.seed import CANARY, QUOTE_101, QUOTE_102, QUOTE_103, QUOTE_104, POLICY_01


def found(text: str, etype: str, **kw) -> list[str]:
    """Original-text slices of every element of `etype` detected in `text`."""
    g = detect(text, **kw)
    return [text[e.start:e.end] for e in g.by_type(etype)]


# ------------------------------------------------------------------ email
@pytest.mark.parametrize("text,expected", [
    ("write to ayesha.po@university.test today", ["ayesha.po@university.test"]),
    ("a@b.test and c.d+tag@mail.sub.example.test.", ["a@b.test", "c.d+tag@mail.sub.example.test"]),
    ("Contact: BIDS-REVIEW@EXAMPLE.TEST", ["BIDS-REVIEW@EXAMPLE.TEST"]),
])
def test_email_detected(text, expected):
    assert found(text, "EMAIL") == expected


@pytest.mark.parametrize("text", ["no at sign here", "user@localhost", "@handle only", "price 5 @ 10 each"])
def test_email_negatives(text):
    assert found(text, "EMAIL") == []


def test_email_is_confidential():
    (e,) = detect("x@y.test").by_type("EMAIL")
    assert e.sensitivity == "CONFIDENTIAL"


# ------------------------------------------------------------------ phone
@pytest.mark.parametrize("number", [
    "0300-1234567", "03001234567", "+92 300 1234567", "+923001234567", "0092 300 1234567",
    "021-34567890", "051 2345678", "+1 415 555 0132", "+44 20 7946 0958",
])
def test_phone_formats_detected(number):
    assert found(f"call {number} now", "PHONE") == [number]


@pytest.mark.parametrize("text", [
    "Total price: PKR 7,280,000", "Unit price: PKR 182,000", "Quote ID: QUOTE-101", "dated 2026-10-21",
    "40 x Laboratory workstation", "reference 12345", "Delivery: 6 weeks Warranty: 3 years",
])
def test_phone_negatives_on_quote_text(text):
    assert found(text, "PHONE") == []


def test_phone_entity_matches_across_formats():
    g = detect("0300-1234567 and +92 300 1234567 and 03001234568")
    keys = [e.entity_key for e in g.by_type("PHONE")]
    assert keys[0] == keys[1] == "03001234567" and keys[2] != keys[0]


# ------------------------------------------------------------------ national id
def test_national_id_synthetic_format():
    assert found("CNIC 35202-1234567-1 on file", "NATIONAL_ID") == ["35202-1234567-1"]


@pytest.mark.parametrize("text", ["3520-1234567-1", "35202-123456-1", "35202-1234567-12", "135202-1234567-1",
                                  "35202 1234567 1"])
def test_national_id_wrong_grouping_not_matched(text):
    assert found(text, "NATIONAL_ID") == []


def test_national_id_labeled_thirteen_digits():
    assert found("CNIC: 3520212345671 and NIC No. 4210198765432", "NATIONAL_ID") == ["3520212345671", "4210198765432"]
    assert found("Order 3520212345671 shipped", "NATIONAL_ID") == []  # no label, no match


# ------------------------------------------------------------------ account number
def test_account_iban_and_labeled():
    assert found("IBAN PK36SCBL0000001123456702 ok", "ACCOUNT_NUMBER") == ["PK36SCBL0000001123456702"]
    assert found("Account No: 0123-4567-8901", "ACCOUNT_NUMBER") == ["0123-4567-8901"]
    assert found("a/c 12345678", "ACCOUNT_NUMBER") == ["12345678"]


@pytest.mark.parametrize("text", [
    "Total price: PKR 7,280,000", "account for 7,280,000 PKR", "Account: pending", "acct 2026",
])
def test_account_negatives(text):
    assert found(text, "ACCOUNT_NUMBER") == []


def test_account_label_is_kept_and_only_digits_are_the_finding():
    text = "Account No: 0123456789"
    (e,) = detect(text).by_type("ACCOUNT_NUMBER")
    assert text[e.start:e.end] == "0123456789"


# ------------------------------------------------------------------ institution vocabulary
def test_default_vocabulary_org_surface_forms_share_one_entity():
    g = detect("NORTHBRIDGE UNIVERSITY wrote to Northbridge. See northbridge university.")
    orgs = g.by_type("ORG")
    assert [e.text for e in orgs] == ["NORTHBRIDGE UNIVERSITY", "Northbridge", "northbridge university"]
    assert {e.entity_key for e in orgs} == {"org:northbridge"}
    assert all(e.sensitivity == "INTERNAL" for e in orgs)


def test_vocabulary_respects_word_boundaries():
    assert found("Northbridgeville is a different place", "ORG") == []
    assert found("Southbridge University", "ORG") == []


def test_vocabulary_persons_and_distinct_entities():
    g = detect("Ayesha Khan met Fatima Raza; Ayesha  Khan left.")
    persons = g.by_type("PERSON")
    assert [e.entity_key for e in persons] == ["person:ayesha-khan", "person:fatima-raza", "person:ayesha-khan"]
    assert all(e.sensitivity == "CONFIDENTIAL" for e in persons)


def test_vocabulary_is_configurable():
    vocab = InstitutionVocabulary(entries=(VocabEntry("org:acme", "ORG", "INTERNAL", ("Acme Corp", "ACME")),))
    assert found("Acme Corp and acme", "ORG", vocabulary=vocab) == ["Acme Corp", "acme"]
    assert found("Northbridge", "ORG", vocabulary=vocab) == []
    assert found("Northbridge", "ORG", vocabulary=InstitutionVocabulary()) == []


# ------------------------------------------------------------------ canary
def test_canary_constant_matches_seed():
    assert any(CANARY in entry.terms for entry in DEFAULT_VOCABULARY.entries)
    assert CANARY == "LAB-CANARY-7731"


@pytest.mark.parametrize("variant", [
    "LAB-CANARY-7731", "lab-canary-7731", "LAB CANARY 7731", "LAB_CANARY_7731", "LAB-CANARY-9999",
    "LAB​-CANARY-7731",  # zero-width space inside
    "LAB‑CANARY‑7731",  # non-breaking hyphens
    "LAB-CANARY-７７３１",  # fullwidth digits
    "LAB-CANARY-۷۷۳۱",  # Extended Arabic-Indic digits
])
def test_canary_variants_detected_with_exact_original_span(variant):
    text = f"ceiling note ({variant}) end"
    g = detect(text)
    (e,) = g.by_type("CANARY")
    assert e.sensitivity == "RESTRICTED"
    assert text[e.start:e.end] == variant


# ------------------------------------------------------------------ budget figure
@pytest.mark.parametrize("variant", ["PKR 6,950,000", "6,950,000", "6950000", "6.950.000", "6 950 000",
                                     "Rs. 6,950,000", "6.95 million", "PKR 6.95M"])
def test_known_budget_figure_variants(variant):
    text = f"The number is {variant} for lab workstations."
    (e,) = detect(text).by_type("BUDGET_FIGURE")
    assert e.sensitivity == "RESTRICTED" and text[e.start:e.end] == variant


@pytest.mark.parametrize("text,amount", [
    ("Approved ceiling: PKR 7,100,000", "PKR 7,100,000"),
    ("The procurement ceiling is Rs. 12,500,000.", "Rs. 12,500,000"),
    ("budget cap of 4.5 million", "4.5 million"),
    ("Budget limit: USD 90,000", "USD 90,000"),
])
def test_contextual_budget_figure_unseeded_amounts(text, amount):
    assert found(text, "BUDGET_FIGURE") == [amount]


@pytest.mark.parametrize("text", [
    "Total price: PKR 7,280,000", "Unit price: PKR 182,000", "ceiling fans: 40 units",
    "Please ignore the earlier draft; budget review follows", "Internal budget ceilings are restricted.",
    "16,950,000 is a different figure", "6,950,000,000 is too large to match",
])
def test_budget_negatives_do_not_overredact(text):
    assert found(text, "BUDGET_FIGURE") == []


def test_figure_patterns_are_generated_from_the_integer():
    pats = figure_patterns(2_500_000)
    assert any(p.search("PKR 2,500,000") for p in pats) and any(p.search("2.5 million") for p in pats)
    assert not any(p.search("2,500,001") for p in pats)


# ------------------------------------------------------------------ token lookalike
def test_placeholder_lookalikes_in_source_are_flagged():
    assert found("see [ORG_01] and [REDACTED:CANARY] and [PERSON_123]", "TOKEN_LOOKALIKE") == [
        "[ORG_01]", "[REDACTED:CANARY]", "[PERSON_123]"]
    assert found("array[0] and [ORG] and [org_01]", "TOKEN_LOOKALIKE") == []


# ------------------------------------------------------------------ overlap merge
def test_overlapping_matches_merge_into_one_element_spanning_the_union():
    text = "mail ayesha@northbridge.test now"
    g = detect(text)
    assert len(g) == 1
    (e,) = g.elements
    assert e.element_type == "EMAIL" and text[e.start:e.end] == "ayesha@northbridge.test"
    assert any("VOCAB:org:northbridge" in p for p in e.provenance)


def test_strongest_sensitivity_wins_an_overlap():
    text = "Approved ceiling: PKR 6,950,000 (LAB-CANARY-7731)"
    types = sorted(e.element_type for e in detect(text))
    assert types == ["BUDGET_FIGURE", "CANARY"]
    g = detect("Account No: 0300-1234567")
    assert [e.element_type for e in g] == ["ACCOUNT_NUMBER"]  # labeled account beats bare phone


def test_adjacent_but_non_overlapping_matches_stay_separate():
    g = detect("a@b.test c@d.test")
    assert len(g.by_type("EMAIL")) == 2


# ------------------------------------------------------------------ normalization
def test_normalize_with_map_round_trips_offsets():
    text = "A​B １２ x"
    norm, origin = normalize_with_map(text)
    assert norm == "AB 12 x"
    assert [text[i] for i in origin] == ["A", "B", " ", "１", "２", " ", "x"]


def test_fold_and_squash():
    assert fold("LAB​-Canary") == "lab-canary"
    assert squash("L-A-B  Canary_7731") == "labcanary7731"


# ------------------------------------------------------------------ graph-level properties
def test_detection_is_deterministic_and_ids_are_stable():
    text = QUOTE_102 + "\nwrite ayesha@northbridge.test or 0300-1234567; Approved ceiling: PKR 6,950,000"
    a, b = detect(text), detect(text)
    assert [e.element_id for e in a] == [e.element_id for e in b]
    assert a.to_json() == b.to_json()


def test_decision_record_view_never_contains_raw_values():
    text = "Ayesha Khan, ayesha@northbridge.test, 0300-1234567, 35202-1234567-1, LAB-CANARY-7731, PKR 6,950,000"
    blob = detect(text, source_sha256="abc").to_json()
    for raw in ["Ayesha", "ayesha@", "0300", "35202", "LAB-CANARY", "6,950,000", "Khan"]:
        assert raw not in blob
    assert json.loads(blob)["record_version"] == "aman-disclosure-graph-v1"


def test_metadata_passthrough():
    (e,) = detect("x@y.test", locator="docx:comments", source_trust="untrusted_external",
                  owner="tenant:northbridge").elements
    assert (e.locator, e.source_trust, e.owner) == ("docx:comments", "untrusted_external", "tenant:northbridge")
    assert "locator:docx:comments" in e.provenance and "detector:EMAIL-v1" in e.provenance


def test_every_detector_has_unique_id_and_documentation():
    ids = [d.detector_id for d in PATTERN_DETECTORS]
    assert len(ids) == len(set(ids)) and all(i.endswith("-v1") for i in ids)
    assert all(d.description for d in PATTERN_DETECTORS)
    assert DETECTOR_SET_VERSION == "aman-detectors-v1"


# ------------------------------------------------------------------ false-positive controls on seed text
def test_benign_finance_sentence_has_no_findings():
    assert len(detect("Please ignore the earlier draft; budget review follows")) == 0


def test_supplier_quotes_only_flag_the_institution_header():
    for q in (QUOTE_101, QUOTE_103, QUOTE_104):
        types = {e.element_type for e in detect(q)}
        assert types == {"ORG"}, types  # prices, dates, supplier names and quote ids are untouched


def test_policy_document_flags_only_the_institution_header():
    assert {e.element_type for e in detect(POLICY_01)} == {"ORG"}


def test_untrusted_note_email_in_quote_102_is_found():
    assert found(QUOTE_102, "EMAIL") == ["bids-review@example.test"]
