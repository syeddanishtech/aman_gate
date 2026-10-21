"""AMAN Gate API. All enforcement lives behind these routes; the frontend only renders decisions."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import gateway, metrics, policy, scenarios
from .audit import event_to_dict, verify_chain
from .bootstrap import ensure_seeded, reset_demo
from .config import settings
from .db import get_db
from .ml.risk import assess, get_model
from .models import Approval, AuditEvent, Document, Report, Run, User
from .schemas import ApprovalDecisionRequest, LoginRequest, ScenarioRunRequest, ToolCallRequest
from .security import Identity, current_identity, issue_token, require_roles, verify_password


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate()
    ensure_seeded()
    # AMAN Gate 2.0 tables live on the shared Base but outside the 1.0 bootstrap; create them here (idempotent).
    from .privacy.models import create_privacy_schema
    from .privacy.routes import create_analysis_schema
    from .privacy.vault import create_vault_schema
    from .bridge.models import create_bridge_schema
    create_privacy_schema()
    create_analysis_schema()
    create_vault_schema()
    create_bridge_schema()
    yield


app = FastAPI(title="AMAN Gate API", version="0.1.0", lifespan=lifespan,
              description="Sovereign AI Agent Security Gateway - local lab prototype, synthetic data only.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["authorization", "content-type"],
)

# AMAN Gate 2.0 routers (Privacy Shield, Safe Cloud Bridge, Output Assurance). Each is a self-contained
# APIRouter the work packages exposed; the Boss wires them here so no package edits main.py directly.
from .privacy.routes import router as privacy_router  # noqa: E402
from .bridge.routes import router as bridge_router  # noqa: E402
from .assurance.routes import router as assurance_router  # noqa: E402

app.include_router(privacy_router)
app.include_router(bridge_router)
app.include_router(assurance_router)


@app.exception_handler(gateway.GatewayError)
async def _gateway_error(_: Request, exc: gateway.GatewayError):
    return JSONResponse(status_code=exc.status, content={"detail": {"code": exc.code, "message": exc.message}})


# ---------------------------------------------------------------- meta
@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "env": settings.env, "demo": settings.is_demo,
            "baseline_lab_enabled": settings.enable_baseline_lab}


@app.get("/api/meta")
def meta(db: Session = Depends(get_db)) -> dict[str, Any]:
    model = get_model(settings.model_dir)
    return {
        "product": "AMAN Gate", "tagline": "Trust the task. Verify every action.",
        "university": "Northbridge University (fictional)",
        "data_notice": "Synthetic data - Local-only security demonstration.",
        "demo": settings.is_demo, "baseline_lab_enabled": settings.enable_baseline_lab,
        "ml_model_available": model.available, "ml_model_version": model.model_version,
        "roles": ["procurement_officer", "junior_clerk", "finance_manager", "security_analyst"],
    }


# ---------------------------------------------------------------- auth
@app.post("/api/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if user is None or not user.active or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail={"code": "INVALID_CREDENTIALS"})
    token = issue_token(user)
    return {"access_token": token, "token_type": "bearer", "expires_in": settings.jwt_ttl_seconds,
            "user": {"user_id": user.id, "username": user.username, "display_name": user.display_name,
                     "role": user.role, "tenant_id": user.tenant_id}}


@app.get("/api/auth/demo-users")
def demo_users(db: Session = Depends(get_db)) -> dict[str, Any]:
    if not settings.demo_quick_login:
        raise HTTPException(status_code=404, detail={"code": "DISABLED"})
    rows = db.execute(select(User).where(User.tenant_id == settings.tenant_id)).scalars().all()
    return {
        "notice": "NONPRODUCTION demo accounts. All share the demo password below.",
        "password": settings.demo_password,
        "users": [{"username": u.username, "display_name": u.display_name, "role": u.role} for u in rows],
    }


@app.get("/api/me")
def me(identity: Identity = Depends(current_identity)) -> dict[str, Any]:
    return {"user_id": identity.user_id, "username": identity.username,
            "display_name": identity.display_name, "role": identity.role, "tenant_id": identity.tenant_id}


@app.post("/api/demo/reset")
def demo_reset(identity: Identity = Depends(require_roles("security_analyst"))) -> dict[str, Any]:
    if not settings.is_demo:
        raise HTTPException(status_code=403, detail={"code": "RESET_DISABLED_IN_PRODUCTION"})
    reset_demo()
    return {"status": "reset", "by": identity.username}


# ---------------------------------------------------------------- documents
@app.get("/api/documents")
def list_documents(identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Registry view. Returns metadata + whether THIS user may read each doc; never returns content here."""
    docs = db.execute(select(Document).where(Document.tenant_id == identity.tenant_id)
                      .order_by(Document.id)).scalars().all()
    out = []
    for d in docs:
        dec, _ = policy.check_document_access(db, identity, d.id)
        out.append({"document_id": d.id, "title": d.title, "doc_type": d.doc_type,
                    "classification": d.classification, "trust_label": d.trust_label, "sha256": d.sha256,
                    "size_bytes": d.size_bytes, "source": d.source, "lab_fixture": d.lab_fixture,
                    "readable": dec.allowed, "acl_reason": dec.reason_codes[0] if dec.reason_codes else None})
    return {"documents": out}


@app.get("/api/documents/{document_id}")
def read_document(document_id: str, identity: Identity = Depends(current_identity),
                  db: Session = Depends(get_db)) -> dict[str, Any]:
    """Content retrieval goes through the SAME gateway/ACL path as the tool call."""
    res = gateway.execute_tool(db, identity, "read_document", {"document_id": document_id},
                               mode="gated", source="ui_document_view")
    if res.decision != "ALLOW":
        raise HTTPException(status_code=403, detail={"code": res.reason_codes[0] if res.reason_codes else "DENIED",
                                                     "message": res.explanation, "event_id": res.event["event_id"],
                                                     "policy_id": res.policy_id})
    return {"document": res.output, "risk": res.risk, "event_id": res.event["event_id"]}


@app.post("/api/risk/assess")
def risk_assess(body: dict[str, Any], identity: Identity = Depends(current_identity)) -> dict[str, Any]:
    text = str(body.get("text", ""))[:20000]
    return assess(text, settings.model_dir)


# ---------------------------------------------------------------- tool gateway
@app.post("/api/tools/invoke")
def invoke_tool(body: ToolCallRequest, identity: Identity = Depends(current_identity),
                db: Session = Depends(get_db)) -> dict[str, Any]:
    res = gateway.execute_tool(db, identity, body.tool, body.args, mode="gated", run_id=body.run_id,
                               source="ui_tool", idempotency_key=body.idempotency_key)
    return {"decision": res.decision, "policy_id": res.policy_id, "reason_codes": res.reason_codes,
            "resource_ids": res.resource_ids, "explanation": res.explanation, "output": _strip_content(res.output),
            "risk": res.risk, "event_id": res.event["event_id"], "approval_id": res.approval_id,
            "decision_latency_ms": res.decision_latency_ms}


def _strip_content(output: dict | None) -> dict | None:
    """Full document content is allowed in the direct read endpoint but not echoed through generic tool output."""
    if not output:
        return output
    if "content" in output:
        safe = dict(output)
        safe.pop("content")
        return safe
    return output


# ---------------------------------------------------------------- tools catalog & policies
@app.get("/api/policies")
def get_policies(identity: Identity = Depends(current_identity)) -> dict[str, Any]:
    return {"policy_version": policy.POLICY_VERSION, "policies": policy.describe_policies(),
            "tools": [{"name": t.name, "roles": sorted(t.allowed_roles), "sensitivity": t.sensitivity,
                       "requires_approval": t.requires_approval, "description": t.description}
                      for t in policy.TOOLS.values()],
            "allowed_destinations": policy.ALLOWED_DESTINATIONS}


# ---------------------------------------------------------------- reports
@app.get("/api/reports")
def my_reports(identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> dict[str, Any]:
    reps = db.execute(select(Report).where(Report.owner_user_id == identity.user_id)
                      .order_by(desc(Report.created_at))).scalars().all()
    return {"reports": [{"report_id": r.id, "classification": r.classification, "sha256": r.sha256,
                         "source_document_ids": r.source_document_ids, "created_at": r.created_at.isoformat()}
                        for r in reps]}


# ---------------------------------------------------------------- approvals
@app.get("/api/approvals")
def list_approvals(identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> dict[str, Any]:
    gateway.expire_due(db)
    q = select(Approval).where(Approval.tenant_id == identity.tenant_id).order_by(desc(Approval.created_at))
    rows = db.execute(q).scalars().all()
    return {"approvals": [gateway._approval_dict(a) for a in rows],
            "can_decide": identity.role == "finance_manager"}


@app.post("/api/approvals/{approval_id}/decision")
def decide(approval_id: str, body: ApprovalDecisionRequest,
           identity: Identity = Depends(require_roles("finance_manager")),
           db: Session = Depends(get_db)) -> dict[str, Any]:
    return gateway.decide_approval(db, identity, approval_id, body.approve, body.note)


@app.post("/api/approvals/{approval_id}/execute")
def execute(approval_id: str, identity: Identity = Depends(current_identity),
            db: Session = Depends(get_db)) -> dict[str, Any]:
    return gateway.execute_approved(db, identity, approval_id)


# ---------------------------------------------------------------- scenarios / replay
@app.get("/api/scenarios")
def get_scenarios(identity: Identity = Depends(current_identity)) -> dict[str, Any]:
    return {"scenarios": scenarios.list_scenarios()}


@app.post("/api/scenarios/run")
def run_scenario(body: ScenarioRunRequest, identity: Identity = Depends(current_identity),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    sc = scenarios.SCENARIO_INDEX.get(body.scenario_id)
    if sc is None:
        raise HTTPException(status_code=404, detail={"code": "SCENARIO_NOT_FOUND"})
    # The scenario is executed AS its designated actor (server-side identity), not as the caller, so the
    # role-switch scenario is meaningful. The caller must be authenticated to trigger a run.
    actor_user = db.execute(select(User).where(User.username == sc.actor_username)).scalar_one()
    actor = Identity(actor_user.id, actor_user.username, actor_user.display_name, actor_user.role,
                     actor_user.tenant_id)
    return scenarios.run_scenario_pair(db, actor, body.scenario_id)


@app.get("/api/runs")
def list_runs(identity: Identity = Depends(current_identity), db: Session = Depends(get_db),
              limit: int = 50) -> dict[str, Any]:
    rows = db.execute(select(Run).order_by(desc(Run.created_at)).limit(min(limit, 200))).scalars().all()
    return {"runs": [{"run_id": r.id, "scenario_id": r.scenario_id, "pair_id": r.pair_id, "mode": r.mode,
                      "summary": r.summary, "duration_ms": r.duration_ms,
                      "created_at": r.created_at.isoformat()} for r in rows]}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, identity: Identity = Depends(current_identity),
            db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(Run, run_id)
    if r is None:
        raise HTTPException(status_code=404, detail={"code": "RUN_NOT_FOUND"})
    return {"run_id": r.id, "scenario_id": r.scenario_id, "pair_id": r.pair_id, "mode": r.mode,
            "input": r.input, "snapshot": r.snapshot, "summary": r.summary, "duration_ms": r.duration_ms,
            "created_at": r.created_at.isoformat()}


# ---------------------------------------------------------------- audit & evidence
@app.get("/api/audit/events")
def audit_events(identity: Identity = Depends(current_identity), db: Session = Depends(get_db),
                 decision: str | None = None, mode: str | None = None, run_id: str | None = None,
                 limit: int = 100, offset: int = 0) -> dict[str, Any]:
    q = select(AuditEvent)
    if decision:
        q = q.where(AuditEvent.decision == decision)
    if mode:
        q = q.where(AuditEvent.mode == mode)
    if run_id:
        q = q.where(AuditEvent.run_id == run_id)
    q = q.order_by(desc(AuditEvent.seq)).limit(min(limit, 500)).offset(max(offset, 0))
    rows = db.execute(q).scalars().all()
    return {"events": [event_to_dict(e) for e in rows]}


@app.get("/api/audit/verify")
def audit_verify(identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> dict[str, Any]:
    return verify_chain(db)


@app.get("/api/audit/export")
def audit_export(identity: Identity = Depends(require_roles("security_analyst")),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(AuditEvent).order_by(AuditEvent.seq.asc())).scalars().all()
    return {"chain": verify_chain(db), "events": [event_to_dict(e) for e in rows]}


@app.get("/api/metrics")
def get_metrics(identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> dict[str, Any]:
    return metrics.dashboard_metrics(db)


@app.get("/api/ml/metrics")
def ml_metrics(identity: Identity = Depends(current_identity)) -> dict[str, Any]:
    model = get_model(settings.model_dir)
    return {"available": model.available, "model_version": model.model_version, "metrics": model.metrics}


@app.get("/api/evidence/report")
def evidence(identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> dict[str, Any]:
    model = get_model(settings.model_dir)
    return metrics.evidence_report(db, {"available": model.available, **model.metrics} if model.available
                                   else None)


# ---------------------------------------------------------------- static frontend (optional)
_dist = settings.frontend_dist
if _dist.exists():
    app.mount("/assets", StaticFiles(directory=str(_dist / "assets")), name="assets")

    @app.get("/")
    def _index() -> FileResponse:
        return FileResponse(str(_dist / "index.html"))
