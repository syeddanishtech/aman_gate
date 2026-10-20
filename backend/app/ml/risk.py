"""Combined advisory risk assessment: heuristics + optional ML. Never enforcing."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .classifier import RiskModel
from .heuristics import score as heuristic_score

_model: RiskModel | None = None


def get_model(model_dir: Path) -> RiskModel:
    global _model
    if _model is None:
        _model = RiskModel(model_dir)
    return _model


def reset_model() -> None:
    global _model
    _model = None


def assess(text: str, model_dir: Path) -> dict[str, Any]:
    heur = heuristic_score(text)
    ml = get_model(model_dir).score(text)
    parts = [heur["score"]]
    if ml.get("available") and ml.get("score") is not None:
        parts.append(ml["score"])
    combined = max(parts)  # advisory headline; conservative
    if combined >= 0.66:
        band = "high"
    elif combined >= 0.33:
        band = "medium"
    else:
        band = "low"
    return {
        "advisory": True,
        "enforcing": False,
        "combined_score": round(combined, 4),
        "band": band,
        "heuristic": heur,
        "ml": ml,
        "note": "Advisory signal only. The allow/deny/approval decision is made by deterministic policy.",
    }
