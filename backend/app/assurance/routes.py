"""POST /api/assurance/check: validate a model reply and locally restore what the caller may see.

The caller's role and tenant come from `current_identity` (re-read from the database on every call). The
request body can name a vault session or artifact and a purpose, but never a role: a role in the body is
rejected (extra fields are forbidden) and nothing in the body can widen what the caller may restore.

The body is read and validated here rather than by FastAPI's own body binding because FastAPI's default
422 response echoes the offending input back (a rejected request containing the canary would reflect it)
and fails outright on JSON containing a lone surrogate. Errors from this route name the field and the kind
of problem, never the value.

Status codes: 401 no/invalid token; 404 unknown session (another tenant's session looks identical);
410 expired session; 413 body too large; 422 unusable input; 503 the audit trail could not be written
(fail closed: an unaudited disclosure is not returned). A reply that is blocked or only partly restored is
still a 200: the verdict is in the body.
"""
from __future__ import annotations

import json
from typing import Any, Iterator

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session

from app.audit import append_event
from app.db import get_db
from app.privacy.vault import DEFAULT_PURPOSE, VaultAccessError, create_vault_schema, open_context
from app.security import Identity, current_identity

from .check import ASSURANCE_POLICY_ID, MAX_REPLY_CHARS, MAX_SOURCE_CHARS, AssuranceInputError, check_response

router = APIRouter(prefix="/api/assurance", tags=["assurance"])

# Reply + optional source text, with room for JSON escaping (up to 6 bytes per character as \uXXXX).
MAX_BODY_BYTES = 4_000_000


class AssuranceCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response: str = Field(max_length=MAX_REPLY_CHARS, description="The model reply to check.")
    session_id: str | None = Field(default=None, pattern=r"^VS-[0-9a-f]{32}$",
                                   description="Vault session issued for the artifact the model was shown.")
    artifact_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$",
                                    description="Alternative to session_id: the artifact handle the session was stored under.")
    purpose: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.\-]{2,63}$",
                                description="Declared purpose of the restoration; defaults to display_to_requester.")
    source_text: str | None = Field(default=None, max_length=MAX_SOURCE_CHARS,
                                    description="Optional safe copy for grounding hints; verified against the session's digest.")


def get_vault_db() -> Iterator[Session]:
    create_vault_schema()  # idempotent; the vault tables are not part of db.create_schema()
    yield from get_db()


def _error(status: int, code: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message, **extra})


async def _read_body(request: Request) -> bytes:
    """The raw request body, bounded. Declared after current_identity, so unauthenticated callers never get here."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _error(413, "REQUEST_TOO_LARGE", f"The request body is limited to {MAX_BODY_BYTES} bytes.")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise _error(413, "REQUEST_TOO_LARGE", f"The request body is limited to {MAX_BODY_BYTES} bytes.")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse(body: bytes) -> AssuranceCheckRequest:
    try:
        payload = json.loads(body)
    except (ValueError, RecursionError):
        raise _error(422, "INVALID_JSON", "The request body is not valid JSON.") from None
    try:
        return AssuranceCheckRequest.model_validate(payload)
    except ValidationError as exc:
        known = set(AssuranceCheckRequest.model_fields)
        errors = []
        for e in exc.errors(include_input=False, include_url=False, include_context=False):
            head = e["loc"][0] if e["loc"] else None
            # An unknown field is reported as such, without its (caller-chosen) name.
            errors.append({"field": head if head in known else "(unknown)", "type": e["type"]})
        raise _error(422, "INVALID_REQUEST", "The request body failed validation.", errors=errors) from None


@router.post("/check", openapi_extra={"requestBody": {
    "required": True, "content": {"application/json": {"schema": AssuranceCheckRequest.model_json_schema()}}}})
def check(identity: Identity = Depends(current_identity), body: bytes = Depends(_read_body),
          db: Session = Depends(get_vault_db)) -> dict[str, Any]:
    req = _parse(body)
    purpose = req.purpose or DEFAULT_PURPOSE
    try:
        ctx = open_context(db, tenant_id=identity.tenant_id, session_id=req.session_id, artifact_id=req.artifact_id)
    except VaultAccessError as exc:
        if exc.code == "SESSION_EXPIRED":
            raise _error(410, "VAULT_SESSION_EXPIRED", "The vault session has expired; re-protect the document.") from None
        raise _error(404, "VAULT_SESSION_NOT_FOUND", "No such vault session.") from None
    try:
        result = check_response(req.response, ctx=ctx, role=identity.role, purpose=purpose,
                                grounding_text=req.source_text)
    except AssuranceInputError as exc:
        raise _error(422, exc.code, "The reply cannot be checked as submitted.") from None
    try:  # audit before disclosure: if the event cannot be recorded, nothing is returned
        append_event(
            actor_user_id=identity.user_id, actor_role=identity.role, event_type="assurance.check",
            decision=result.audit_decision, policy_id=ASSURANCE_POLICY_ID, reason_codes=result.reason_codes,
            # mode="system" keeps these out of the AMAN 1.0 KPIs (/api/metrics counts mode="gated" tool decisions)
            resource_ids=[ctx.session_id] if ctx is not None else [], mode="system",
            tenant_id=identity.tenant_id, details=result.audit_details())
    except Exception:
        raise _error(503, "AUDIT_UNAVAILABLE", "The audit trail could not be written; no output was released.") from None
    return result.to_response()
