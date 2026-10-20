"""Reset the demo DB, run every scenario as its designated actor, then write real evidence artifacts
(evidence_report.json, dashboard_metrics.json, audit_chain.json) to reports/. All numbers come from
code that actually executed here.

Usage (from backend/):  python -m scripts.generate_evidence
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.audit import event_to_dict, verify_chain  # noqa: E402
from app.bootstrap import reset_demo  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.ml.risk import get_model  # noqa: E402
from app.metrics import dashboard_metrics, evidence_report  # noqa: E402
from app.models import AuditEvent, User  # noqa: E402
from app.security import Identity  # noqa: E402
from app import scenarios  # noqa: E402


def main() -> int:
    reset_demo()
    db = SessionLocal()
    for sc in scenarios.SCENARIOS:
        u = db.execute(select(User).where(User.username == sc.actor_username)).scalar_one()
        actor = Identity(u.id, u.username, u.display_name, u.role, u.tenant_id)
        scenarios.run_scenario_pair(db, actor, sc.id)

    model = get_model(settings.model_dir)
    evidence = evidence_report(db, {"available": model.available, **model.metrics} if model.available else None)
    dash = dashboard_metrics(db)
    events = db.execute(select(AuditEvent).order_by(AuditEvent.seq.asc())).scalars().all()
    chain = {"verification": verify_chain(db), "events": [event_to_dict(e) for e in events]}

    out_dir = settings.frontend_dist.parent.parent / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evidence_report.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (out_dir / "dashboard_metrics.json").write_text(json.dumps(dash, indent=2), encoding="utf-8")
    (out_dir / "audit_chain.json").write_text(json.dumps(chain, indent=2), encoding="utf-8")
    db.close()

    ab = evidence["attack_block"]
    lr = evidence["legitimate_requests"]
    print(f"[evidence] scenarios run: {evidence['scenario_runs_counted']}")
    print(f"[evidence] attack-block: {ab['blocked']}/{ab['attempts']} = {ab['attempt_block_pct']}% "
          f"(false allows: {ab['false_allows']})")
    print(f"[evidence] legit success: {lr['succeeded']}/{lr['requests']} = {lr['success_pct']}% "
          f"(false blocks: {evidence['false_blocks']['legitimate_actions_denied']})")
    print(f"[evidence] decision latency p50/p95: {evidence['latency_ms']['p50']}/{evidence['latency_ms']['p95']} ms")
    print(f"[evidence] audit chain valid: {chain['verification']['valid']} ({chain['verification']['checked']})")
    print(f"[evidence] wrote artifacts to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
