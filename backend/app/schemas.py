"""Request/response models for the HTTP API (separate from the internal tool-arg policy models)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]


class ToolCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str = Field(max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    run_id: str | None = Field(default=None, max_length=64)
    idempotency_key: str | None = Field(default=None, max_length=128)


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool
    note: str | None = Field(default=None, max_length=256)


class ScenarioRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str = Field(max_length=64)
