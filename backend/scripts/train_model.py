"""Train the advisory injection-risk classifier and write artifacts + dataset export.

Usage (from backend/):  python -m scripts.train_model
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.ml import dataset  # noqa: E402
from app.ml.classifier import train  # noqa: E402


def main() -> int:
    data_path = settings.model_dir / "dataset.jsonl"
    info = dataset.export_jsonl(data_path)
    print(f"[dataset] {info['count']} samples ({info['positives']} pos / {info['negatives']} neg), "
          f"fingerprint {info['fingerprint'][:16]}...")
    result = train(settings.model_dir)
    m = result.metrics
    o = m["holdout_overall"]
    print(f"[train] holdout n={m['split']['holdout']} precision={o['precision']} recall={o['recall']} "
          f"fpr={o['false_positive_rate']} f1={o['f1']}")
    print(f"[train] leakage ok={m['leakage_check']['ok']}")
    print(f"[train] model -> {result.model_path}")
    print(f"[train] metrics -> {result.metrics_path}")
    print(json.dumps(m["holdout_by_language"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
