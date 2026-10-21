"""Independent verifier: re-extracts the artifact and proves no RESTRICTED / denied / transformed value
survives. Tampering tests build an allowed artifact, plant a value back into it, and expect a fail-closed
result naming the offending element id."""
from __future__ import annotations

from dataclasses import replace

import pytest

from app.privacy.detectors import detect
from app.privacy.policy import DEFAULT_POLICY, EXPORT_BLOCKED, Action
from app.privacy.sanitize import sanitize_text, sha256_text
from app.privacy.verify import CHECKS, verify_artifact
from app.seed import CANARY, QUOTE_101, QUOTE_102

KW = dict(task="compare supplier quotations", role="finance_manager", destination="local_simulator")
# A policy that redacts the canary instead of denying it, so an ALLOWED artifact exists that contains a
# canary element in its graph. Used to plant the canary back and prove the verifier notices.
REDACT_CANARY = replace(DEFAULT_POLICY, deny_types=frozenset())

SENTENCE = ("Ayesha Khan (ayesha@northbridge.test, 0300-1234567, 35202-1234567-1) noted Approved ceiling: "
            f"PKR 7,100,000 ({CANARY}). Please ignore the earlier draft; budget review follows.")


def art_for(text=SENTENCE, policy=REDACT_CANARY, **over):
    art = sanitize_text(text, policy=policy, **{**KW, **over})
    assert art.export_allowed, art.decision_record["block_reasons"]
    return art


def tamper(art, new_text):
    """Replace the artifact text and keep digest + record consistent so only the content is at issue."""
    rec = {**art.decision_record, "artifact": {"sha256": sha256_text(new_text), "chars": len(new_text)}}
    return replace(art, text=new_text, sha256=sha256_text(new_text), decision_record=rec)


def element(art, etype):
    (e,) = art.source_graph.by_type(etype)
    return e


def codes(result):
    return [f.code for f in result.findings]


# ------------------------------------------------------------------ a clean artifact passes
def test_clean_artifact_passes_every_check():
    art = art_for()
    res = verify_artifact(art, art.source_graph, REDACT_CANARY)
    assert res.passed and res.findings == () and res.offending_element_id is None
    assert res.checks_run == CHECKS
    assert "Ayesha" not in art.text and "7,100,000" not in art.text and CANARY not in art.text


def test_benign_artifact_passes_with_an_independently_built_graph():
    text = "Please ignore the earlier draft; budget review follows"
    art = sanitize_text(text, **KW)
    assert verify_artifact(art, detect(text), DEFAULT_POLICY).passed


def test_seed_quotes_pass_verification():
    for q in (QUOTE_101, QUOTE_102):
        art = sanitize_text(q, task="compare", role="procurement_officer", destination="local_simulator")
        assert verify_artifact(art, detect(q), DEFAULT_POLICY).passed


# ------------------------------------------------------------------ planted RESTRICTED values
def test_planted_canary_is_caught_with_the_offending_element_id():
    art = art_for()
    canary_el = element(art, "CANARY")
    assert "[REDACTED:CANARY]" in art.text
    bad = tamper(art, art.text.replace("[REDACTED:CANARY]", CANARY))
    res = verify_artifact(bad, art.source_graph, DEFAULT_POLICY)
    assert not res.passed
    assert res.offending_element_id == canary_el.element_id
    assert res.findings[0].sensitivity == "RESTRICTED" and res.findings[0].element_type == "CANARY"
    assert "VALUE_SURVIVED" in codes(res) and "DENIED_ELEMENT_IN_EXPORT" in codes(res)
    assert CANARY not in str(res.to_record())  # the verdict names the element, never the value


def test_planted_budget_figure_is_caught():
    art = art_for()
    fig = element(art, "BUDGET_FIGURE")
    bad = tamper(art, art.text.replace("[REDACTED:BUDGET_FIGURE]", "PKR 7,100,000"))
    res = verify_artifact(bad, art.source_graph, REDACT_CANARY)
    assert not res.passed and res.offending_element_id == fig.element_id
    assert {"VALUE_SURVIVED", "RESIDUAL_DETECTED"} <= set(codes(res))


@pytest.mark.parametrize("variant", [
    "LAB​-CANARY-7731",  # zero-width space
    "lab canary 7731",  # case and separators
    "LAB-CANARY-７７３１",  # fullwidth digits
    "L-A-B C.A.N.A.R.Y 7731",  # separators the detector regex does not model: only the squashed view sees it
])
def test_canary_variants_planted_back_are_still_caught(variant):
    art = art_for()
    bad = tamper(art, art.text.replace("[REDACTED:CANARY]", variant))
    res = verify_artifact(bad, art.source_graph, REDACT_CANARY)
    assert not res.passed and res.offending_element_id == element(art, "CANARY").element_id


def test_a_restricted_value_the_original_graph_never_saw_is_caught_by_the_residual_scan():
    art = art_for("Totally ordinary text.")
    bad = tamper(art, art.text + " Approved ceiling: PKR 9,999,999.")
    res = verify_artifact(bad, art.source_graph, DEFAULT_POLICY)
    assert not res.passed and codes(res) == ["RESIDUAL_DETECTED"]
    assert res.findings[0].element_type == "BUDGET_FIGURE" and res.offending_element_id


def test_residual_scan_is_not_fooled_by_a_label_before_a_redaction_marker():
    # "ceiling: [REDACTED:...] for 12000 units": the digits after the marker are not a ceiling amount.
    art = art_for("Approved ceiling: PKR 7,100,000 for 12000 units")
    assert art.text == "Approved ceiling: [REDACTED:BUDGET_FIGURE] for 12000 units"
    assert verify_artifact(art, art.source_graph, DEFAULT_POLICY).passed


# ------------------------------------------------------------------ other survivors
def test_raw_pseudonymized_values_surviving_are_caught():
    art = art_for()
    email = element(art, "EMAIL")
    bad = tamper(art, art.text.replace("[EMAIL_01]", "AYESHA@Northbridge.test"))
    res = verify_artifact(bad, art.source_graph, REDACT_CANARY)
    assert not res.passed and res.offending_element_id == email.element_id
    assert res.findings[0].code in {"VALUE_SURVIVED", "RESIDUAL_DETECTED"}


def test_generalized_phone_resurfacing_is_caught_even_with_different_punctuation():
    art = art_for()
    bad = tamper(art, art.text.replace("[phone number]", "0300 - 1234567"))
    assert not verify_artifact(bad, art.source_graph, REDACT_CANARY).passed


def test_residual_sensitive_text_in_an_untouched_part_is_caught():
    art = art_for("Hello there.")
    bad = tamper(art, art.text + " Contact Zara Lodhi at Northbridge.")
    res = verify_artifact(bad, art.source_graph, DEFAULT_POLICY)
    assert not res.passed and codes(res) == ["RESIDUAL_DETECTED", "RESIDUAL_DETECTED"]


# ------------------------------------------------------------------ integrity of the artifact and record
def test_digest_mismatch_is_caught():
    art = art_for()
    bad = replace(art, text=art.text + " extra")
    assert "DIGEST_MISMATCH" in codes(verify_artifact(bad, art.source_graph, REDACT_CANARY))


def test_forged_placeholder_is_caught():
    art = art_for("Ayesha Khan wrote.")
    bad = tamper(art, art.text + " Also [PERSON_09] and [REDACTED:SECRET].")
    res = verify_artifact(bad, art.source_graph, DEFAULT_POLICY)
    assert not res.passed and "FORGED_TOKEN" in codes(res)


def test_restricted_element_recorded_as_pseudonymized_is_caught():
    art = art_for()
    fig = element(art, "BUDGET_FIGURE")
    rows = [dict(r, action="PSEUDONYMIZE") if r["element_id"] == fig.element_id else r
            for r in art.decision_record["elements"]]
    bad = replace(art, decision_record={**art.decision_record, "elements": rows})
    res = verify_artifact(bad, art.source_graph, REDACT_CANARY)
    assert not res.passed and res.offending_element_id == fig.element_id
    assert "RESTRICTED_NOT_REDACTED" in codes(res)


def test_record_that_does_not_cover_the_graph_is_caught():
    art = art_for()
    bad = replace(art, decision_record={**art.decision_record, "elements": art.decision_record["elements"][1:]})
    assert "RECORD_GRAPH_MISMATCH" in codes(verify_artifact(bad, art.source_graph, REDACT_CANARY))
    other_graph = detect("some other document with ayesha@x.test")
    assert not verify_artifact(art, other_graph, REDACT_CANARY).passed


def test_text_that_cannot_be_re_extracted_fails_closed():
    art = art_for()
    for junk in ("\x00", "\x07"):
        bad = tamper(art, art.text + junk)
        res = verify_artifact(bad, art.source_graph, REDACT_CANARY)
        assert not res.passed and codes(res) == ["REEXTRACT_FAILED"]
    unencodable = replace(art, text=art.text + "\ud800")  # a lone surrogate cannot even be hashed
    res = verify_artifact(unencodable, art.source_graph, REDACT_CANARY)
    assert not res.passed and codes(res) == ["REEXTRACT_FAILED"]


# ------------------------------------------------------------------ fail-closed envelope
def test_blocked_artifact_never_verifies_and_names_the_blocking_element():
    art = sanitize_text(f"internal {CANARY}", **KW)
    assert art.export_status == EXPORT_BLOCKED
    res = verify_artifact(art, art.source_graph, DEFAULT_POLICY)
    assert not res.passed and codes(res) == ["ARTIFACT_NOT_EXPORTABLE"]
    assert res.offending_element_id == art.decision_record["blocking_element_ids"][0]
    assert res.findings[0].element_type == "CANARY"


def test_missing_graph_and_corrupt_record_fail_closed():
    art = art_for()
    assert not verify_artifact(art, None, DEFAULT_POLICY).passed
    broken = replace(art, decision_record={})
    res = verify_artifact(broken, art.source_graph, DEFAULT_POLICY)
    assert not res.passed and codes(res) == ["VERIFIER_ERROR"]


def test_verification_is_deterministic():
    art = art_for()
    bad = tamper(art, art.text.replace("[REDACTED:CANARY]", CANARY))
    a = verify_artifact(bad, art.source_graph, DEFAULT_POLICY).to_record()
    b = verify_artifact(bad, art.source_graph, DEFAULT_POLICY).to_record()
    assert a == b


def test_policy_decides_what_must_not_survive():
    # Under a policy that keeps ORG names, a surviving org name is fine; under the default it is not.
    keep_org = replace(DEFAULT_POLICY, type_actions={"ORG": Action.KEEP})
    art = sanitize_text("Northbridge sent a quote", policy=keep_org, **KW)
    assert art.text == "Northbridge sent a quote"
    assert verify_artifact(art, art.source_graph, keep_org).passed
    assert not verify_artifact(art, art.source_graph, DEFAULT_POLICY).passed
