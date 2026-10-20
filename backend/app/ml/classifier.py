"""CPU-friendly injection-risk classifier: TF-IDF (word + char n-grams) + logistic regression.

Trained on the versioned synthetic dataset with a stratified train/holdout split. Evaluation is done
ONLY on the disjoint holdout set and reports precision, recall, false-positive rate and a confusion
matrix per stratum. The score is advisory: policy decisions never depend on it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline

from .dataset import DATASET_VERSION, Sample, fingerprint, generate
from .normalize import normalize

MODEL_VERSION = "aman-tfidf-logreg-2026.10-v1"


def _build_pipeline() -> Pipeline:
    word = TfidfVectorizer(preprocessor=normalize, analyzer="word", ngram_range=(1, 2),
                           min_df=2, sublinear_tf=True, lowercase=True)
    char = TfidfVectorizer(preprocessor=normalize, analyzer="char_wb", ngram_range=(3, 5),
                           min_df=2, sublinear_tf=True, lowercase=True)
    return Pipeline([
        ("features", FeatureUnion([("word", word), ("char", char)])),
        ("clf", LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced", solver="liblinear")),
    ])


@dataclass
class TrainResult:
    metrics: dict[str, Any]
    model_path: Path
    metrics_path: Path


def _rate_block(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": round(precision, 4), "recall": round(recall, 4),
        "false_positive_rate": round(fpr, 4), "f1": round(f1, 4), "support": int(len(y_true)),
    }


def train(model_dir: Path, seed: int = 7, test_size: float = 0.3, threshold: float = 0.5) -> TrainResult:
    samples: list[Sample] = generate(seed)
    texts = [s.text for s in samples]
    labels = np.array([s.label for s in samples])
    strata = [s.kind for s in samples]
    langs = [s.lang for s in samples]

    groups = np.array([s.group for s in samples])
    # Group-aware split: every variant of one base template stays on a single side, so the holdout
    # measures generalisation to UNSEEN templates rather than memorised near-duplicates.
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    tr_idx, te_idx = next(gss.split(texts, labels, groups))
    # Leakage guards: no identical text AND no shared template group across splits.
    overlap_text = {texts[i] for i in tr_idx} & {texts[i] for i in te_idx}
    overlap_group = {groups[i] for i in tr_idx} & {groups[i] for i in te_idx}
    leakage = sorted(overlap_text) + [f"group:{g}" for g in sorted(overlap_group)]

    pipe = _build_pipeline()
    pipe.fit([texts[i] for i in tr_idx], labels[tr_idx])

    proba = pipe.predict_proba([texts[i] for i in te_idx])[:, 1]
    y_true = labels[te_idx]
    y_pred = (proba >= threshold).astype(int)

    overall = _rate_block(y_true, y_pred)
    by_lang: dict[str, Any] = {}
    for lang in sorted(set(langs)):
        mask = np.array([langs[i] == lang for i in te_idx])
        if mask.any():
            by_lang[lang] = _rate_block(y_true[mask], y_pred[mask])
    by_kind: dict[str, Any] = {}
    for kind in sorted(set(strata)):
        mask = np.array([strata[i] == kind for i in te_idx])
        if mask.any():
            by_kind[kind] = _rate_block(y_true[mask], y_pred[mask])

    metrics = {
        "model_version": MODEL_VERSION,
        "dataset_version": DATASET_VERSION,
        "dataset_fingerprint": fingerprint(samples),
        "seed": seed,
        "threshold": threshold,
        "split": {"train": int(len(tr_idx)), "holdout": int(len(te_idx)),
                  "train_positives": int(labels[tr_idx].sum()), "holdout_positives": int(labels[te_idx].sum())},
        "leakage_check": {"identical_texts_in_both_splits": len(leakage), "ok": len(leakage) == 0},
        "holdout_overall": overall,
        "holdout_by_language": by_lang,
        "holdout_by_kind": by_kind,
        "note": "Metrics are measured on the disjoint holdout only and describe the ML model, not the "
                "heuristic signals. The classifier is advisory and never changes a policy decision.",
    }

    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "injection_clf.joblib"
    metrics_path = model_dir / "metrics.json"
    joblib.dump({"pipeline": pipe, "model_version": MODEL_VERSION, "threshold": threshold}, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    return TrainResult(metrics, model_path, metrics_path)


class RiskModel:
    """Loaded at runtime. If the artifact is missing the system still runs (heuristics only)."""

    def __init__(self, model_dir: Path):
        self.model_dir = model_dir
        self.available = False
        self._pipe = None
        self.model_version = None
        self.threshold = 0.5
        self.metrics: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        mp = self.model_dir / "injection_clf.joblib"
        if mp.exists():
            bundle = joblib.load(mp)
            self._pipe = bundle["pipeline"]
            self.model_version = bundle["model_version"]
            self.threshold = bundle.get("threshold", 0.5)
            self.available = True
        meta = self.model_dir / "metrics.json"
        if meta.exists():
            self.metrics = json.loads(meta.read_text(encoding="utf-8"))

    def score(self, text: str) -> dict[str, Any]:
        if not self.available:
            return {"available": False, "score": None, "model_version": None}
        p = float(self._pipe.predict_proba([text])[:, 1][0])
        return {"available": True, "score": round(p, 4), "model_version": self.model_version,
                "threshold": self.threshold, "flag": p >= self.threshold}
