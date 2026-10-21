"""Safe Cloud Bridge configuration. Every default is the safest one: the local simulator is the only usable
provider, LOCAL_LLM and REAL_CLOUD are off, and the egress allowlist is empty.

The environment is read when `load_config()` is called, not at import time, so an operator change (or a test)
takes effect without re-importing anything. An unset, empty or unparsable value always means "off"/"empty".

  AMAN_BRIDGE_REAL_CLOUD_ENABLED   "true" to even consider REAL_CLOUD (anything else: refused)
  AMAN_BRIDGE_REAL_CLOUD_ENDPOINT  the one destination URL REAL_CLOUD may use (https only, see egress.py)
  AMAN_BRIDGE_ALLOWED_HOSTS        comma-separated exact host names the endpoint's host must be one of
  AMAN_BRIDGE_LOCAL_LLM_ENABLED    "true" to consider LOCAL_LLM (this build ships no local model runtime)
  AMAN_BRIDGE_MAX_OUTBOUND_CHARS   cap on the size of one outbound payload
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from app.privacy.policy import destination_class as _privacy_destination_class

ENV_REAL_CLOUD_ENABLED = "AMAN_BRIDGE_REAL_CLOUD_ENABLED"
ENV_REAL_CLOUD_ENDPOINT = "AMAN_BRIDGE_REAL_CLOUD_ENDPOINT"
ENV_ALLOWED_HOSTS = "AMAN_BRIDGE_ALLOWED_HOSTS"
ENV_LOCAL_LLM_ENABLED = "AMAN_BRIDGE_LOCAL_LLM_ENABLED"
ENV_MAX_OUTBOUND_CHARS = "AMAN_BRIDGE_MAX_OUTBOUND_CHARS"

MAX_OUTBOUND_CHARS = 200_000
_MAX_OUTBOUND_CEILING = 2_000_000  # WP1's own text limit; the bridge never raises its cap above it

# A host name as the allowlist accepts it: lower-case, dotted (at least two labels), ASCII letters/digits/hyphen.
HOST_RE = re.compile(r"^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class ProviderMode(str, Enum):
    LOCAL_SIMULATOR = "LOCAL_SIMULATOR"  # default: deterministic responder inside this process, no network code
    LOCAL_LLM = "LOCAL_LLM"  # optional on-device model: stubbed off in this build
    REAL_CLOUD = "REAL_CLOUD"  # opt-in external provider: disabled by default, allowlist-only, no transport shipped

    @property
    def privacy_destination(self) -> str:
        """The `destination` to pass to the Privacy Shield when preparing an artifact for this mode."""
        return {"LOCAL_SIMULATOR": "local_simulator", "LOCAL_LLM": "local_llm"}.get(self.value, "real_cloud")

    @property
    def destination_class(self) -> str:
        """LOCAL or EXTERNAL, by the same rule WP1 uses (an unknown name is EXTERNAL)."""
        return _privacy_destination_class(self.privacy_destination)


DEFAULT_PROVIDER_MODE = ProviderMode.LOCAL_SIMULATOR


@dataclass(frozen=True)
class BridgeConfig:
    real_cloud_enabled: bool = False
    real_cloud_endpoint: str | None = None
    allowed_hosts: frozenset[str] = frozenset()
    local_llm_enabled: bool = False
    max_outbound_chars: int = MAX_OUTBOUND_CHARS


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def _int_in_range(value: str | None, default: int, lo: int, hi: int) -> int:
    try:
        n = int((value or "").strip())
    except ValueError:
        return default
    return n if lo <= n <= hi else default


def _hosts(value: str | None) -> frozenset[str]:
    """Exact host names only. Anything that is not a plain lower-case dotted name (a wildcard, an IP literal's
    odd forms, a URL, a port) is dropped, which can only make the allowlist smaller."""
    items = (part.strip() for part in (value or "").split(","))
    return frozenset(h for h in items if HOST_RE.fullmatch(h))


def load_config(environ: Mapping[str, str] | None = None) -> BridgeConfig:
    env = os.environ if environ is None else environ
    endpoint = (env.get(ENV_REAL_CLOUD_ENDPOINT) or "").strip() or None
    return BridgeConfig(
        real_cloud_enabled=_flag(env.get(ENV_REAL_CLOUD_ENABLED)),
        real_cloud_endpoint=endpoint,
        allowed_hosts=_hosts(env.get(ENV_ALLOWED_HOSTS)),
        local_llm_enabled=_flag(env.get(ENV_LOCAL_LLM_ENABLED)),
        max_outbound_chars=_int_in_range(env.get(ENV_MAX_OUTBOUND_CHARS), MAX_OUTBOUND_CHARS, 1, _MAX_OUTBOUND_CEILING),
    )
