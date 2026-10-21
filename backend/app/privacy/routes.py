"""HTTP surface of the Document Privacy Shield (AMAN Gate 2.0, T1 integration).

  POST /api/privacy/analyze   {document_id, destination?}  -> AnalyzeResponse
  GET  /api/privacy/artifacts/{id}                          -> ArtifactResponse

The caller's role and tenant come from `current_identity` (re-read from the DB every call); the request
can never supply a role. The source document is read THROUGH the existing AMAN 1.0 ACL path
(`app.policy.check_document_access`), so a user without the grant cannot analyze it or see its original.

`analyze` runs the WP1 engine locally, then (only for an EXPORT_ALLOWED artifact) registers the sanitized
copy in the bridge store (WP2) and vaults its rehydration table (WP3), so the same artifact id flows into
`/api/bridge/send` and `/api/assurance/check`. A `privacy.analyzed` audit event is appended with digests
and counts only — never a raw value or the canary. A small `PrivacyAnalysis` link row maps the artifact id
back to its source document so `GET /artifacts/{id}` can rebuild the original/safe previews for a granted
caller (it re-reads through the ACL and re-runs the deterministic engine; no raw original is ever stored).

Honest engine limits (reflected in the UI): PERSON/ORG are matched from a fixed institution vocabulary,
not general name recognition; task and role do not change what is removed; pseudonyms are reversible
through the local vault; any embedded image blocks export (no logo recognition).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.audit import append_event
from app.db import Base, engine, get_db
from app import policy as acl
from app.security import Identity, current_identity

from .pipeline import protect_text
from .policy import PRIVACY_POLICY_ID
from .sanitize import SafeArtifact

ANALYZE_TASK = "procurement_document_review"
ANALYZE_DESTINATION = "local_simulator"  # LOCAL class: RESTRICTED values are redacted, not denied


class PrivacyAnalysis(Base):
    """Owner-scoped link: artifact id -> source document, so the previews can be rebuilt. No raw values."""

    __tablename__ = "privacy_analyses"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    owner_user_id: Mapped[str] = mapped_column(String(64), index=True)
    document_id: Mapped[str] = mapped_column(String(64))
    safe_artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    privacy_decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vault_session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    export_status: Mapped[str] = mapped_column(String(24))
    findings_count: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime)


def create_analysis_schema() -> None:
    Base.metadata.create_all(engine, tables=[PrivacyAnalysis.__table__])


router = APIRouter(prefix="/api/privacy", tags=["privacy"], dependencies=[Depends(current_identity)])


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: str = Field(min_length=1, max_length=64)
    # Optional hint; the engine only distinguishes LOCAL vs EXTERNAL. Analysis always targets LOCAL review.
    destination: str | None = Field(default=None, max_length=64)


def _acl_or_403(db: Session, identity: Identity, document_id: str):
    decision, doc = acl.check_document_access(db, identity, document_id)
    if not decision.allowed or doc is None:
        raise HTTPException(status_code=403, detail={
            "code": decision.reason_codes[0] if decision.reason_codes else "ACL_DENIED",
            "message": decision.explanation, "policy_id": decision.policy_id})
    return doc


def _elements_view(artifact: SafeArtifact) -> list[dict[str, Any]]:
    """Map the decision record's element rows to the UI contract's DisclosureElement shape (no raw values)."""
    out: list[dict[str, Any]] = []
    for row in artifact.decision_record.get("elements", []):
        out.append({
            "id": row["element_id"],
            "type": row["element_type"],
            "page": 0,  # text documents have no pages; PDF page mapping is a Phase-2 concern
            "sensitivity": str(row["sensitivity"]).lower(),
            "source_trust": row["source_trust"],
            "action": str(row["action"]).lower(),
        })
    return out


@router.post("/analyze")
def analyze(body: AnalyzeRequest, identity: Identity = Depends(current_identity),
            db: Session = Depends(get_db)) -> dict[str, Any]:
    doc = _acl_or_403(db, identity, body.document_id)

    # Deterministic local sanitize + independent verification (role from the DB identity, never the request).
    artifact = protect_text(doc.content, task=ANALYZE_TASK, role=identity.role, destination=ANALYZE_DESTINATION,
                            source_trust=getattr(doc, "trust_label", "unknown"))
    rec = artifact.decision_record

    # Persist the decision record (no raw values) regardless of outcome.
    from .models import store_decision
    pd = store_decision(db, artifact, tenant_id=identity.tenant_id, actor_user_id=identity.user_id)

    safe_artifact_id: str | None = None
    vault_session_id: str | None = None
    block_reasons = list(rec.get("block_reasons", []))

    if artifact.export_allowed:
        # WP2: store exactly what may be sent (re-verified inside register_artifact); gives the SA- id.
        from app.bridge.models import register_artifact
        sa = register_artifact(db, artifact, tenant_id=identity.tenant_id, actor_user_id=identity.user_id,
                               privacy_decision_id=pd.id)
        safe_artifact_id = sa.id
        # WP3: vault the rehydration table under the same artifact id so assurance can open_context(artifact_id).
        try:
            from app.privacy.vault import create_vault_schema, store_artifact
            create_vault_schema()
            info = store_artifact(db, artifact, tenant_id=identity.tenant_id, owner_user_id=identity.user_id,
                                  owner_role=identity.role, artifact_id=safe_artifact_id)
            vault_session_id = info.session_id
        except Exception:
            vault_session_id = None  # no reversible tokens / vault unavailable: rehydration simply won't be offered

    link = PrivacyAnalysis(
        id=f"PA-{uuid.uuid4().hex[:16]}", tenant_id=identity.tenant_id, owner_user_id=identity.user_id,
        document_id=body.document_id, safe_artifact_id=safe_artifact_id, privacy_decision_id=pd.id,
        vault_session_id=vault_session_id, export_status=artifact.export_status,
        findings_count=rec["summary"]["elements_found"],
        created_at=datetime.now(timezone.utc).replace(tzinfo=None))
    db.add(link)
    db.commit()

    append_event(
        actor_user_id=identity.user_id, actor_role=identity.role, tenant_id=identity.tenant_id,
        event_type="privacy.analyzed", decision="ALLOW" if artifact.export_allowed else "DENY",
        policy_id=PRIVACY_POLICY_ID, reason_codes=block_reasons,
        resource_ids=[body.document_id, *( [safe_artifact_id] if safe_artifact_id else [] )], mode="gated",
        details={"export_status": artifact.export_status, "elements_found": rec["summary"]["elements_found"],
                 "max_sensitivity": rec["summary"]["max_sensitivity"], "by_action": rec["summary"]["by_action"],
                 "source_sha256": rec["source"]["sha256"], "artifact_sha256": artifact.sha256,
                 "privacy_decision_id": pd.id})

    decision = "READY_FOR_REVIEW" if artifact.export_allowed else "BLOCKED"
    resp: dict[str, Any] = {
        "disclosure": {"elements": _elements_view(artifact), "findings_count": rec["summary"]["elements_found"]},
        "safe_artifact_id": safe_artifact_id or "",
        "decision": decision,
    }
    if not artifact.export_allowed:
        resp["blocked_reason"] = block_reasons[0] if block_reasons else "EXPORT_BLOCKED"
    return resp


@router.get("/artifacts/{artifact_id}")
def get_artifact(artifact_id: str, identity: Identity = Depends(current_identity),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    link = db.query(PrivacyAnalysis).filter(
        PrivacyAnalysis.safe_artifact_id == artifact_id,
        PrivacyAnalysis.tenant_id == identity.tenant_id,
        PrivacyAnalysis.owner_user_id == identity.user_id).one_or_none()
    if link is None:
        raise HTTPException(status_code=404, detail={"code": "ARTIFACT_NOT_FOUND",
                                                     "message": "No such analysis for this user."})

    # Re-read through the ACL; a caller who may not read the document never receives its original.
    decision, doc = acl.check_document_access(db, identity, link.document_id)
    can_see_original = decision.allowed and doc is not None

    safe_copy_preview = ""
    findings: list[dict[str, Any]] = []
    original_preview = doc.content if can_see_original else ""

    if doc is not None:
        artifact = protect_text(doc.content, task=ANALYZE_TASK, role=identity.role,
                                destination=ANALYZE_DESTINATION, source_trust=getattr(doc, "trust_label", "unknown"))
        safe_copy_preview = artifact.text
        replacements = {r["element_id"]: r.get("replacement")
                        for r in artifact.decision_record.get("elements", [])}
        graph = artifact.source_graph
        if graph is not None:
            for el in graph.elements:
                if el.locator != "body":
                    continue
                finding = {
                    "id": el.element_id, "type": el.element_type, "page": 0,
                    "sensitivity": el.sensitivity.lower(),
                    "action": str(replacements_action(artifact, el.element_id)).lower(),
                    "start": el.start, "end": el.end,
                    "replacement": replacements.get(el.element_id),
                }
                if can_see_original:
                    finding["original"] = el.text  # raw value, only ever to an ACL-granted caller
                findings.append(finding)

    return {"original_preview": original_preview, "safe_copy_preview": safe_copy_preview, "findings": findings}


def replacements_action(artifact: SafeArtifact, element_id: str) -> str:
    for r in artifact.decision_record.get("elements", []):
        if r["element_id"] == element_id:
            return r.get("action", "")
    return ""


__all__ = ["router", "PrivacyAnalysis", "create_analysis_schema"]
