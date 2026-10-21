"""Disclosure graph model: validation, stable ids, lookup, and a record that never carries raw values."""
from __future__ import annotations

import json

import pytest

from app.privacy.graph import (
    DisclosureElement,
    DisclosureGraph,
    SENSITIVITIES,
    canonical_json,
    make_element_id,
    max_sensitivity,
    sensitivity_rank,
)

SECRET = "LAB-CANARY-7731"


def _el(start=0, end=15, etype="CANARY", sens="RESTRICTED", locator="body", text=SECRET, **kw):
    return DisclosureElement(
        element_id=make_element_id(locator, start, end, etype), element_type=etype, locator=locator,
        start=start, end=end, sensitivity=sens, text=text, **kw)


def test_sensitivity_order_is_public_to_restricted():
    assert SENSITIVITIES == ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED")
    assert sensitivity_rank("PUBLIC") < sensitivity_rank("INTERNAL") < sensitivity_rank("CONFIDENTIAL") \
        < sensitivity_rank("RESTRICTED")
    assert max_sensitivity(["INTERNAL", "RESTRICTED", "PUBLIC"]) == "RESTRICTED"
    assert max_sensitivity([]) == "PUBLIC"


def test_unknown_sensitivity_fails_closed():
    with pytest.raises(KeyError):
        sensitivity_rank("SECRET")
    with pytest.raises(ValueError):
        _el(sens="SECRET")


@pytest.mark.parametrize("bad", [dict(source_trust="trusted"), dict(etype="email"), dict(start=5, end=5),
                                 dict(start=-1, end=3, text="")])
def test_invalid_elements_are_rejected(bad):
    with pytest.raises(ValueError):
        _el(**bad)


def test_text_length_must_match_span():
    with pytest.raises(ValueError):
        _el(start=0, end=4, text="too long for span")


def test_element_id_is_stable_and_content_free():
    a = make_element_id("body", 3, 18, "CANARY")
    assert a == make_element_id("body", 3, 18, "CANARY")
    assert a != make_element_id("body", 3, 19, "CANARY")
    assert a != make_element_id("docx:comments", 3, 18, "CANARY")
    assert a != make_element_id("body", 3, 18, "EMAIL")
    # Same position, different matched text -> same id: the id carries no information about the value.
    assert _el(text="AAAAAAAAAAAAAAA").element_id == _el(text="BBBBBBBBBBBBBBB").element_id


def test_graph_add_get_and_duplicate_rejection():
    g = DisclosureGraph("abc")
    e = _el()
    g.add(e)
    assert len(g) == 1 and e.element_id in g and g.get(e.element_id) is e
    with pytest.raises(ValueError):
        g.add(_el())
    with pytest.raises(KeyError):
        g.get("E-missing")


def test_graph_lookups_and_order():
    g = DisclosureGraph("abc", [
        _el(start=40, end=55),
        _el(start=0, end=10, etype="EMAIL", sens="CONFIDENTIAL", text="a@b.test!!"),
        _el(start=5, end=9, etype="ORG", sens="INTERNAL", locator="docx:comments", text="Nort"),
    ])
    assert [e.start for e in g.elements] == [0, 40, 5]  # "body" sorts before "docx:comments"
    assert [e.element_type for e in g.by_type("EMAIL")] == ["EMAIL"]
    assert len(g.by_sensitivity("RESTRICTED")) == 1
    assert [e.element_type for e in g.at_locator("docx:comments")] == ["ORG"]
    assert g.max_sensitivity() == "RESTRICTED"
    assert g.counts()["by_sensitivity"] == {"CONFIDENTIAL": 1, "INTERNAL": 1, "RESTRICTED": 1}


def test_record_has_no_raw_text_or_entity_key():
    g = DisclosureGraph("deadbeef", [_el(entity_key="canary-secret-entity", owner="tenant:northbridge",
                                         provenance=("detector:CANARY-v1",))])
    blob = g.to_json()
    assert SECRET not in blob and "canary-secret-entity" not in blob
    assert SECRET not in repr(g.elements[0])
    rec = json.loads(blob)
    assert rec["record_version"] == "aman-disclosure-graph-v1"
    assert rec["source_sha256"] == "deadbeef"
    row = rec["elements"][0]
    assert row["sensitivity"] == "RESTRICTED" and row["owner"] == "tenant:northbridge"
    assert row["provenance"] == ["detector:CANARY-v1"] and row["length"] == 15
    assert "text" not in row and "entity_key" not in row


def test_annotations_are_merged_per_element():
    e = _el()
    g = DisclosureGraph("x", [e])
    rec = g.to_record({e.element_id: {"action": "DENY", "rule_id": "R-DENY-TYPE"}})
    assert rec["elements"][0]["action"] == "DENY"


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 1, "a": [2, 1]}) == canonical_json({"a": [2, 1], "b": 1}) == '{"a":[2,1],"b":1}'
    g1 = DisclosureGraph("x", [_el(), _el(start=20, end=35, text=SECRET)])
    g2 = DisclosureGraph("x", [_el(start=20, end=35, text=SECRET), _el()])
    assert g1.to_json() == g2.to_json()
