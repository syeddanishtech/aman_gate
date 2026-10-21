"""Egress policy for the Safe Cloud Bridge. The default answer is DENY.

Two questions are answered here, both deterministically and without a model:

  1. decide_mode()        may this provider mode be used at all, given the configuration?
                          LOCAL_SIMULATOR is the only mode that is allowed out of the box.
  2. check_destination()  is this URL an acceptable REAL_CLOUD destination?  Only an https URL whose host is
                          an exact member of the operator's allowlist, with no credentials, query, fragment,
                          non-443 port, IP literal or local/internal name. There are no wildcards and no
                          suffix matching, so `allowed.example.com.evil.test` and `evil-allowed.example.com`
                          do not match `allowed.example.com`.

REAL_CLOUD is documented and policed here but DISABLED: this build ships no network transport at all (see
connector.py). A future transport must pin the resolved address, refuse redirects, verify TLS, cap the
response and apply this same allowlist again at connect time.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Collection

from . import codes
from .config import HOST_RE, BridgeConfig, ProviderMode

MAX_URL_CHARS = 2048
# Printable ASCII URL characters only: no whitespace, control characters, backslash, quotes or angle brackets.
_URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")
_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*/?)?$")
_HEX_LABEL = re.compile(r"^0x[0-9a-f]*$")
# Last labels that mean "this machine or a private network". Refused even if somebody puts them on the allowlist.
_LOCAL_LABELS = frozenset({"localhost", "local", "localdomain", "internal", "intranet", "lan", "home", "corp",
                           "private"})


@dataclass(frozen=True)
class DestinationCheck:
    ok: bool
    reasons: tuple[str, ...] = ()
    url: str | None = None  # the normalized URL, only when ok
    host: str | None = None


def _refuse(code: str) -> DestinationCheck:
    return DestinationCheck(False, (code,))


def _looks_like_ip(host: str) -> bool:
    """An IP literal in any spelling a resolver might accept: dotted, all-numeric labels, or 0x-style labels."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return all(label.isdigit() for label in labels) or any(_HEX_LABEL.fullmatch(label) for label in labels)


def check_destination(url: object, allowed_hosts: Collection[str]) -> DestinationCheck:
    """Accept a URL only if every rule holds. The first failing rule is reported."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS or not _URL_CHARS.fullmatch(url):
        return _refuse(codes.DESTINATION_INVALID)
    if not url.startswith("https://"):  # strict and case-sensitive: http, ftp, ws, scheme-relative, HTTPS://
        return _refuse(codes.DESTINATION_SCHEME_NOT_HTTPS)
    rest = url[len("https://"):]
    cut = min((i for i in (rest.find(c) for c in "/?#") if i != -1), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        return _refuse(codes.DESTINATION_HAS_CREDENTIALS)
    if "?" in tail or "#" in tail:
        return _refuse(codes.DESTINATION_HAS_QUERY_OR_FRAGMENT)
    if authority.startswith("["):  # bracketed IPv6 literal
        return _refuse(codes.DESTINATION_HOST_IS_IP_LITERAL)
    host, colon, port = authority.partition(":")
    if colon and port != "443":
        return _refuse(codes.DESTINATION_PORT_NOT_ALLOWED)
    if _looks_like_ip(host):
        return _refuse(codes.DESTINATION_HOST_IS_IP_LITERAL)
    if host.rsplit(".", 1)[-1] in _LOCAL_LABELS:
        return _refuse(codes.DESTINATION_HOST_LOCAL)
    if not HOST_RE.fullmatch(host):  # upper case, single label, underscore, empty, trailing dot, ...
        return _refuse(codes.DESTINATION_INVALID)
    if tail and (not _PATH_RE.fullmatch(tail) or any(seg in (".", "..") for seg in tail.split("/"))):
        return _refuse(codes.DESTINATION_INVALID)
    if host not in allowed_hosts:
        return _refuse(codes.DESTINATION_HOST_NOT_ALLOWLISTED)
    return DestinationCheck(True, (), f"https://{host}{tail}", host)


@dataclass(frozen=True)
class EgressDecision:
    """The mode-level verdict. `allowed` False always comes with at least one reason."""

    mode: ProviderMode | None
    allowed: bool
    reasons: tuple[str, ...]
    destination: str  # what this decision would talk to: "in-process:..." or the allowlisted URL; "none" if denied
    network: bool  # True only for an allowed destination that would be reached over a network


def _deny(mode: ProviderMode | None, reasons: list[str]) -> EgressDecision:
    return EgressDecision(mode, False, tuple(dict.fromkeys(reasons)), "none", False)


def decide_mode(mode: ProviderMode | str, config: BridgeConfig, *, runtime_available: bool) -> EgressDecision:
    """Default deny. `runtime_available` says whether a connector able to carry out this mode is installed."""
    try:
        mode = ProviderMode(mode)
    except ValueError:
        return _deny(None, [codes.EGRESS_DEFAULT_DENY, codes.UNKNOWN_PROVIDER_MODE])

    if mode is ProviderMode.LOCAL_SIMULATOR:
        if not runtime_available:  # the in-process responder is missing: nothing to run, so nothing is allowed
            return _deny(mode, [codes.EGRESS_DEFAULT_DENY])
        return EgressDecision(mode, True, (), "in-process:local-simulator", False)

    if mode is ProviderMode.LOCAL_LLM:
        if not config.local_llm_enabled:
            return _deny(mode, [codes.LOCAL_LLM_NOT_CONFIGURED])
        if not runtime_available:
            return _deny(mode, [codes.LOCAL_LLM_RUNTIME_UNAVAILABLE])
        return EgressDecision(mode, True, (), "in-process:local-llm", False)

    # REAL_CLOUD: every condition below must hold, and any one that does not is reported.
    blockers: list[str] = []
    destination: DestinationCheck | None = None
    if not config.real_cloud_enabled:
        blockers.append(codes.REAL_CLOUD_NOT_ENABLED)
    else:
        if not config.real_cloud_endpoint:
            blockers.append(codes.REAL_CLOUD_ENDPOINT_MISSING)
        else:
            destination = check_destination(config.real_cloud_endpoint, config.allowed_hosts)
            if not destination.ok:
                blockers += [codes.REAL_CLOUD_ENDPOINT_NOT_ALLOWLISTED, *destination.reasons]
        if not runtime_available:
            blockers.append(codes.REAL_CLOUD_TRANSPORT_UNAVAILABLE)
    if blockers or destination is None or destination.url is None:
        return _deny(mode, [codes.EGRESS_DEFAULT_DENY, *blockers])
    return EgressDecision(mode, True, (), destination.url, True)
