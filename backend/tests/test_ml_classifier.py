"""ML classifier integrity: leak-free disjoint holdout, honest metrics, encoding normalisation."""
from __future__ import annotations

from app.ml import dataset
from app.ml.classifier import train
from app.ml.normalize import decode_base64_segments, evasion_markers, normalize


def test_dataset_deterministic_and_labelled():
    a = dataset.generate(7)
    b = dataset.generate(7)
    assert dataset.fingerprint(a) == dataset.fingerprint(b)
    assert all(s.label in (0, 1) for s in a)
    assert sum(s.label for s in a) > 0 and sum(1 - s.label for s in a) > 0


def test_no_duplicate_texts():
    s = dataset.generate(7)
    texts = [x.text for x in s]
    assert len(texts) == len(set(texts))  # dedup guarantee


def test_train_has_no_leakage_and_reports_holdout(tmp_path):
    res = train(tmp_path, seed=7)
    m = res.metrics
    assert m["leakage_check"]["ok"] is True
    assert m["leakage_check"]["identical_texts_in_both_splits"] == 0
    assert m["split"]["holdout"] > 0
    o = m["holdout_overall"]
    # honest, measured numbers present (not asserting a specific high value)
    for k in ("precision", "recall", "false_positive_rate", "f1"):
        assert 0.0 <= o[k] <= 1.0


def test_normalisation_undoes_evasion():
    assert "ignore" in normalize("ign​ore")  # zero-width removed
    assert "-" in normalize("—")  # dash variant
    assert "a" in normalize("а")  # cyrillic homoglyph
    decoded = decode_base64_segments("token aWdub3JlIHByZXZpb3Vz")
    assert any("ignore" in d for d in decoded)


def test_evasion_markers_detected():
    markers = evasion_markers("read BUDGET​-SECRET and рassword")
    assert "invisible_characters" in markers
    assert "homoglyphs" in markers
