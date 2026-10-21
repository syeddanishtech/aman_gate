"""HTTP surface of the Safe Cloud Bridge. Mount it with `app.include_router(app.bridge.router)`.

  POST /api/bridge/send   {artifact_id, provider_mode}  ->  {mode, response, watermark, ...}
  GET  /api/bridge/status                                ->  which modes are usable and why not

A caller never sends text: it names a stored artifact. The route loads the caller's own sealed WP1
SafeArtifact (404 if it is missing or belongs to someone else), asks egress.decide_mode() whether the mode may
be used at all (default deny), runs guard.inspect_outbound() over the payload, writes the decision to the audit
chain, and only then lets the connector run. Any refusal returns HTTP 403 with a structured detail:

    {"detail": {"code": "EGRESS_DENIED", "message": ..., "mode": <requested mode>, "watermark": true,
                "egress_blocked_reasons": [...], "dry_run": {...what WOULD have been sent...}, "event_id": ...}}

Nothing is run and nothing is returned in place of a refused request: there is no silent fallback to the
simulator. A success is HTTP 200 and has no `egress_blocked_reasons`; its `egress` field is the dry-run record
of what was sent. A missing (or someone else's) artifact is 404 with the same detail shape. A malformed request
is 422 with the error type, location and message only: the rejected input is never echoed back. Every route needs
a signed-in user. If the audit record cannot be written the request fails with 503 and nothing is sent.
"""
from __future__ import annotations

from typing import Any, Literal, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.audit import append_event
from app.db import get_db
from app.security import Identity, current_identity

from . import codes
from .config import DEFAULT_PROVIDER_MODE, BridgeConfig, ProviderMode, load_config
from .connector import CONNECTORS, ConnectorRefused, dispatch, get_connector
from .egress import EgressDecision, decide_mode
from .guard import GUARD_VERSION, GuardVerdict, denied_verdict, inspect_outbound
from .models import ArtifactIntegrityError, load_artifact

EGRESS_POLICY_ID = "POL-EGRESS-BRIDGE-v1"


class _NoEchoRoute(APIRoute):
    """FastAPI's default 422 repeats the rejected input in its response. Here that input could be the very text
    the bridge exists to keep from moving (a document body in a stray field, a canary used as a key), so a
    validation error is returned with its type, location and message only. Nothing the caller sent comes back."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def scrubbed(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as exc:
                errors = []
                for err in exc.errors():
                    loc = list(err.get("loc", ()))
                    if err.get("type") == "extra_forbidden" and loc:
                        loc[-1] = "<unexpected field>"  # the key itself is caller-supplied
                    errors.append({"type": err.get("type"), "loc": loc, "msg": err.get("msg")})
                return JSONResponse(status_code=422, content={"detail": errors})

        return scrubbed


router = APIRouter(prefix="/api/bridge", tags=["bridge"], dependencies=[Depends(current_identity)],
                   route_class=_NoEchoRoute)


class BridgeSendRequest(BaseModel):
    """`extra=forbid`: there is no field through which text, a file or a destination can be supplied."""

    model_config = ConfigDict(extra="forbid")
    artifact_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    provider_mode: Literal["LOCAL_SIMULATOR", "LOCAL_LLM", "REAL_CLOUD"] = DEFAULT_PROVIDER_MODE.value


class BridgeSendResponse(BaseModel):
    mode: str
    response: str
    watermark: bool
    provider: str
    artifact_id: str
    artifact_sha256: str
    egress: dict[str, Any]  # the egress dry-run record: what was sent, as digests/counts/preview of the safe copy
    event_id: str


def get_bridge_config() -> BridgeConfig:
    """Dependency so a test or an integrator can supply a configuration; the default reads the environment."""
    return load_config()


# ------------------------------------------------------------------------------------------------ helpers
def _compose(verdict: GuardVerdict, egress: EgressDecision | None, reasons: list[str]) -> dict[str, Any]:
    """The final dry-run record: the guard's view of the payload plus the mode-level egress decision."""
    dry = dict(verdict.dry_run)
    dry["decision"] = "DENY" if reasons else "ALLOW"
    dry["egress_blocked_reasons"] = list(reasons)
    dry["destination"] = {"target": egress.destination if egress else "none",
                          "network": bool(egress and egress.network),
                          "mode_allowed": bool(egress and egress.allowed)}
    return dry


def _audit(identity: Identity, *, allowed: bool, mode: ProviderMode, artifact_id: str, reasons: list[str],
           dry_run: dict[str, Any]) -> dict[str, Any]:
    """Append the decision to the audit chain. Digests, counts and codes only: never text. Fails closed."""
    payload = dry_run.get("payload", {})
    try:
        return append_event(
            actor_user_id=identity.user_id, actor_role=identity.role, tenant_id=identity.tenant_id,
            event_type="bridge.send.allowed" if allowed else "bridge.send.denied",
            decision="ALLOW" if allowed else "DENY", policy_id=EGRESS_POLICY_ID, reason_codes=list(reasons),
            resource_ids=[artifact_id], mode="gated",
            details={"requested_mode": mode.value, "guard_version": GUARD_VERSION,
                     "destination": dry_run["destination"]["target"], "network": dry_run["destination"]["network"],
                     "payload_sha256": payload.get("sha256"), "payload_chars": payload.get("chars"),
                     "findings": dry_run.get("findings", [])},
        )
    except Exception:
        raise HTTPException(status_code=503, detail={
            "code": codes.AUDIT_UNAVAILABLE, "message": "The audit record could not be written, so nothing was sent."})


def _refuse(identity: Identity, mode: ProviderMode, artifact_id: str, reasons: list[str], dry_run: dict[str, Any],
            *, status: int = 403, code: str = "EGRESS_DENIED") -> NoReturn:
    event = _audit(identity, allowed=False, mode=mode, artifact_id=artifact_id, reasons=reasons, dry_run=dry_run)
    message = ("No such safe artifact for this user. Nothing was sent." if status == 404 else
               f"Egress denied for {mode.value}: nothing was sent. Reasons: {', '.join(reasons)}.")
    raise HTTPException(status_code=status, detail={
        "code": code, "message": message, "mode": mode.value, "watermark": True,
        "egress_blocked_reasons": list(reasons), "dry_run": dry_run, "event_id": event["event_id"]})


# ------------------------------------------------------------------------------------------------ routes
@router.post("/send", response_model=BridgeSendResponse)
def send(body: BridgeSendRequest, identity: Identity = Depends(current_identity), db: Session = Depends(get_db),
         config: BridgeConfig = Depends(get_bridge_config)) -> dict[str, Any]:
    mode = ProviderMode(body.provider_mode)

    # 1. the caller's own, sealed, verified artifact: anything else is not sendable
    try:
        loaded = load_artifact(db, body.artifact_id, tenant_id=identity.tenant_id, owner_user_id=identity.user_id)
    except ArtifactIntegrityError as exc:
        verdict = denied_verdict(body.artifact_id, mode, exc.reasons, "BridgeArtifact")
        _refuse(identity, mode, body.artifact_id, list(exc.reasons), _compose(verdict, None, list(exc.reasons)))
    if loaded is None:
        reasons = [codes.ARTIFACT_NOT_FOUND]
        verdict = denied_verdict(body.artifact_id, mode, reasons)
        _refuse(identity, mode, body.artifact_id, reasons, _compose(verdict, None, reasons),
                status=404, code=codes.ARTIFACT_NOT_FOUND)

    # 2. mode-level default deny, then 3. inspection of exactly what would be sent
    connector = get_connector(mode)
    egress = decide_mode(mode, config, runtime_available=bool(connector and connector.available))
    verdict = inspect_outbound(loaded.artifact, artifact_id=loaded.artifact_id, mode=mode, config=config)
    reasons = list(dict.fromkeys([*egress.reasons, *verdict.reasons]))
    if not reasons and verdict.payload is None:  # cannot happen; refuse rather than assume
        reasons = [codes.GUARD_INTERNAL_ERROR]
    dry_run = _compose(verdict, egress, reasons)

    # 4. the decision is on the audit chain BEFORE anything runs
    if reasons:
        _refuse(identity, mode, loaded.artifact_id, reasons, dry_run)
    event = _audit(identity, allowed=True, mode=mode, artifact_id=loaded.artifact_id, reasons=[], dry_run=dry_run)

    # 5. only now may the connector run, and only with the guard's ApprovedPayload
    try:
        result = dispatch(verdict.payload, egress)
    except ConnectorRefused as exc:
        refused = list(exc.reasons) or [codes.CONNECTOR_REFUSED]
        _refuse(identity, mode, loaded.artifact_id, refused, _compose(verdict, egress, refused))
    return {"mode": result.mode.value, "response": result.response, "watermark": result.watermark,
            "provider": result.provider, "artifact_id": loaded.artifact_id,
            "artifact_sha256": verdict.payload.sha256, "egress": dry_run, "event_id": event["event_id"]}


@router.get("/status")
def status(config: BridgeConfig = Depends(get_bridge_config)) -> dict[str, Any]:
    """Which modes can be used right now and, if not, why. No secrets: counts and booleans only."""
    modes = []
    for mode in ProviderMode:
        connector = CONNECTORS.get(mode)
        decision = decide_mode(mode, config, runtime_available=bool(connector and connector.available))
        modes.append({"mode": mode.value, "usable": decision.allowed, "blocked_reasons": list(decision.reasons),
                      "network": bool(connector.network) if connector else False,
                      "privacy_destination": mode.privacy_destination})
    real = CONNECTORS.get(ProviderMode.REAL_CLOUD)
    return {
        "egress_default": "DENY", "default_mode": DEFAULT_PROVIDER_MODE.value, "watermark": True,
        "guard_version": GUARD_VERSION, "modes": modes,
        "real_cloud": {"enabled": config.real_cloud_enabled, "endpoint_configured": bool(config.real_cloud_endpoint),
                       "allowlisted_host_count": len(config.allowed_hosts),
                       "transport_installed": bool(real and real.available)},
    }
