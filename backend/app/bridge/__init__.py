"""Safe Cloud Bridge (AMAN Gate 2.0, WP2): lets a user hand ONLY a sanitized artifact to an AI model.

The provider is not the security boundary. Four deterministic layers sit in front of it, and the default
provider is a local simulator that never touches a network:

  models.py     only a WP1 SafeArtifact that is exported and passes the independent verifier again is stored,
                sealed with an HMAC; the HTTP API has no field that takes text.
  egress.py     default DENY per provider mode; REAL_CLOUD additionally needs an exact-host https allowlist.
  guard.py      outbound inspection of exactly what would be sent (canary, RESTRICTED values, residual sensitive
                values, raw-file / untransformed-source indicators), producing an egress dry-run record.
  connector.py  LOCAL_SIMULATOR answers from the sanitized text alone; LOCAL_LLM and REAL_CLOUD are stubs that
                refuse. No network library is imported anywhere in this package.

Wiring (done at integration, not here):  `app.include_router(app.bridge.router)`, and have whatever produces a
safe artifact call `app.bridge.register_artifact(session, artifact, tenant_id=..., actor_user_id=...)` with the
SafeArtifact from `app.privacy.pipeline.protect_text / protect_document`; its `.id` is the `artifact_id`
accepted by POST /api/bridge/send.
"""
from .config import BridgeConfig, ProviderMode, load_config
from .guard import ApprovedPayload, GuardVerdict, inspect_outbound
from .models import ArtifactRefused, BridgeArtifact, create_bridge_schema, load_artifact, register_artifact
from .routes import router

__all__ = [
    "ApprovedPayload", "ArtifactRefused", "BridgeArtifact", "BridgeConfig", "GuardVerdict", "ProviderMode",
    "create_bridge_schema", "inspect_outbound", "load_artifact", "load_config", "register_artifact", "router",
]
