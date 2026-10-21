"""Outbound inspection: the last deterministic step before anything may leave the function.

inspect_outbound() is the single gate between a stored artifact and a connector. It does not trust the
sanitizer, the verifier or the database: it re-derives everything it needs from the payload itself, and it
fails closed (any doubt, any error, any unexpected type is a denial). It checks that

  * the payload is a WP1 SafeArtifact that was exported, independently verified and recorded with the current
    decision-record version, and that its text still has the digest the record and the artifact claim;
  * the text is within the size cap, and an artifact prepared for a LOCAL destination is not being sent to an
    EXTERNAL one (it was approved under a weaker policy);
  * it is not a raw file (PDF/DOCX container), nor the untransformed source text of a record that says it was
    transformed, nor does it contain a value from a local original table the caller still holds;
  * the detectors, run again over what would actually be sent, find no canary, no RESTRICTED element and
    nothing the privacy policy would still transform (a person, an organisation, an e-mail address, ...). The
    canary is also looked for by a second, detector-independent literal check on the squashed text.

Only if every check holds does it hand back an ApprovedPayload. That object can only be created here, and it
is the only thing a connector will accept, so a payload that was not inspected cannot be sent by accident.
(It is a capability token against mistakes, not a sandbox: code running in this process can always import the
private issuer. The real boundary is that nothing in this build can open a socket.)

The dry-run record says what WOULD be sent: digest, sizes, placeholder counts and, for an allowed payload, a
short preview of the sanitized text. For a denied payload it carries no text, no matched value and no offset.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.privacy.detectors import TOKEN_RE, detect, fold, squash
from app.privacy.policy import DECISION_RECORD_VERSION, DEFAULT_POLICY, EXPORT_ALLOWED, Action
from app.privacy.sanitize import SafeArtifact, sha256_text
from app.privacy.verify import CHECKS as VERIFIER_CHECKS

from . import codes
from .config import BridgeConfig, ProviderMode

GUARD_VERSION = "aman-egress-guard-v1"
DRY_RUN_VERSION = "aman-egress-dryrun-v1"
PREVIEW_CHARS = 200

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CANARY_FAMILY = "labcanary"  # squash("LAB-CANARY-7731") starts with this, whatever the separators or case
_RAW_CONTAINER_MARKERS = ("<w:document", "<w:body", "word/document.xml", "[content_types].xml", "/type /catalog")

_ISSUER = object()  # private: only inspect_outbound hands this to ApprovedPayload


@dataclass(frozen=True)
class ApprovedPayload:
    """Sanitized text that passed inspect_outbound for one provider mode. Connectors accept nothing else."""

    artifact_id: str
    mode: ProviderMode
    text: str = field(repr=False)
    sha256: str
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer is not _ISSUER:
            raise TypeError("an ApprovedPayload can only be issued by guard.inspect_outbound")
        if not self.verify():
            raise ValueError("approved payload text does not match its digest")

    def verify(self) -> bool:
        """The text still hashes to the digest it was approved under (re-checked by every connector)."""
        return isinstance(self.text, str) and sha256_text(self.text) == self.sha256


@dataclass(frozen=True)
class GuardVerdict:
    allowed: bool
    reasons: tuple[str, ...]
    dry_run: dict[str, Any]
    payload: ApprovedPayload | None  # set if and only if allowed


# ---------------------------------------------------------------------------------------------------- helpers
def _collapse(text: str) -> str:
    return " ".join(fold(text).split())


def _placeholder_counts(text: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for tok in TOKEN_RE.findall(text):
        inner = tok[1:-1]
        counts[inner if inner.startswith("REDACTED:") else inner.rsplit("_", 1)[0]] += 1
    return dict(sorted(counts.items()))


def _raw_container_markers(text: str) -> bool:
    if text.startswith("%PDF-") or text.startswith("PK\x03\x04") or "\x00" in text:
        return True
    lowered = text.lower()
    return any(marker in lowered for marker in _RAW_CONTAINER_MARKERS)


def _rescan(text: str) -> list[tuple[str, str, Action]]:
    """(type, sensitivity, action) of everything the detectors still find in the text that would be sent.
    Placeholders become line breaks (as in the verifier) so a label before a redacted value cannot reach over it."""
    graph = detect(TOKEN_RE.sub("\n", text), locator="outbound", vocabulary=DEFAULT_POLICY.vocabulary)
    found = []
    for el in graph:
        if el.element_type == "TOKEN_LOOKALIKE":
            continue
        action, _rule = DEFAULT_POLICY.action_for(el, destination_class="EXTERNAL")
        found.append((el.element_type, el.sensitivity, action))
    return found


def _verification_evidence(record: Any) -> bool:
    """The record must say the independent verifier ran every check and found nothing."""
    ver = record.get("verification") if isinstance(record, dict) else None
    if not isinstance(ver, dict) or ver.get("passed") is not True or ver.get("findings"):
        return False
    return set(VERIFIER_CHECKS).issubset(ver.get("checks_run") or ())


def _record_destination_class(record: Any) -> str | None:
    try:
        cls = record["request"]["destination_class"]
    except (KeyError, TypeError):
        return None
    return cls if cls in ("LOCAL", "EXTERNAL") else None


def _safe_id(artifact_id: object) -> str | None:
    return artifact_id if isinstance(artifact_id, str) and _ID_RE.fullmatch(artifact_id) else None


def _mode_name(mode: object) -> str:
    try:
        return ProviderMode(mode).value
    except ValueError:
        return "UNKNOWN"


def _dry_run(*, allowed: bool, mode: object, artifact_id: object, reasons: list[str], received_type: str,
             checks: list[dict[str, Any]], findings: list[dict[str, Any]], text: str | None,
             sha256: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "artifact_id": _safe_id(artifact_id),
        "received_type": received_type[:64],
        "contents": "sanitized text only; the original document and the rehydration table are never included",
    }
    if text is not None:
        payload.update({"sha256": sha256, "chars": len(text), "lines": len(text.splitlines()),
                        "placeholders": _placeholder_counts(text)})
        if allowed:
            payload["text_preview"] = text[:PREVIEW_CHARS]
    return {
        "record_version": DRY_RUN_VERSION,
        "guard_version": GUARD_VERSION,
        "decision": "ALLOW" if allowed else "DENY",
        "requested_mode": _mode_name(mode),
        "egress_blocked_reasons": list(reasons),
        "payload": payload,
        "checks": checks,
        "findings": findings,
    }


def denied_verdict(artifact_id: object, mode: object, reasons: Iterable[str],
                   received_type: str = "none") -> GuardVerdict:
    """A denial for a payload that could not be inspected (missing, tampered, wrong type, internal error)."""
    rs = list(dict.fromkeys(reasons))
    dry = _dry_run(allowed=False, mode=mode, artifact_id=artifact_id, reasons=rs, received_type=received_type,
                   checks=[], findings=[], text=None, sha256=None)
    return GuardVerdict(False, tuple(rs), dry, None)


# ---------------------------------------------------------------------------------------------------- the gate
def inspect_outbound(candidate: object, *, artifact_id: object, mode: ProviderMode | str,
                     config: BridgeConfig | None = None, known_originals: Iterable[str] = ()) -> GuardVerdict:
    """Inspect `candidate` for sending in `mode`. Never raises: an internal error is a denial.

    `known_originals` is optional: raw values from a local rehydration table that the caller still holds.
    They are only compared with the text and never stored or reported."""
    try:
        return _inspect(candidate, artifact_id, mode, config or BridgeConfig(), tuple(known_originals))
    except Exception:  # fail closed
        return denied_verdict(artifact_id, mode, [codes.GUARD_INTERNAL_ERROR], type(candidate).__name__)


def _inspect(candidate: object, artifact_id: object, mode: object, cfg: BridgeConfig,
             known_originals: tuple[str, ...]) -> GuardVerdict:
    try:
        pmode: ProviderMode | None = ProviderMode(mode)
    except ValueError:
        pmode = None
    if not isinstance(candidate, SafeArtifact):  # raw text, bytes, a dict, a document row, ...: not sendable
        return denied_verdict(artifact_id, mode, [codes.PAYLOAD_NOT_SAFE_ARTIFACT], type(candidate).__name__)

    reasons: list[str] = []
    checks: list[dict[str, Any]] = [{"check": "SAFE_ARTIFACT_TYPE", "ok": True}]

    def check(name: str, ok: bool, code: str) -> bool:
        checks.append({"check": name, "ok": bool(ok)})
        if not ok and code not in reasons:
            reasons.append(code)
        return bool(ok)

    text, record = candidate.text, candidate.decision_record
    if not isinstance(text, str) or not isinstance(record, dict):
        return denied_verdict(artifact_id, mode, [codes.ARTIFACT_RECORD_INVALID], "SafeArtifact")

    check("MODE_KNOWN", pmode is not None, codes.UNKNOWN_PROVIDER_MODE)
    check("EXPORT_ALLOWED", candidate.export_allowed and record.get("export_status") == EXPORT_ALLOWED
          and not record.get("block_reasons"), codes.ARTIFACT_NOT_EXPORTABLE)
    check("VERIFIED_BY_INDEPENDENT_VERIFIER", _verification_evidence(record), codes.ARTIFACT_NOT_VERIFIED)
    dest_class = _record_destination_class(record)
    check("RECORD_VALID", record.get("record_version") == DECISION_RECORD_VERSION and record.get("inspected") is True
          and dest_class is not None, codes.ARTIFACT_RECORD_INVALID)
    digest = sha256_text(text)
    recorded = record.get("artifact", {}).get("sha256") if isinstance(record.get("artifact"), dict) else None
    check("DIGEST_MATCHES", digest == candidate.sha256 == recorded, codes.ARTIFACT_DIGEST_MISMATCH)
    check("WITHIN_SIZE_LIMIT", len(text) <= cfg.max_outbound_chars, codes.PAYLOAD_TOO_LARGE)
    check("DESTINATION_BINDING", not (pmode is ProviderMode.REAL_CLOUD and dest_class != "EXTERNAL"),
          codes.ARTIFACT_DESTINATION_MISMATCH)

    # raw-original indicators ----------------------------------------------------------------------------
    check("NOT_A_RAW_FILE_CONTAINER", not _raw_container_markers(text), codes.RAW_FILE_CONTAINER_DETECTED)
    source = record.get("source", {}).get("sha256") if isinstance(record.get("source"), dict) else None
    elements = record.get("elements") if isinstance(record.get("elements"), list) else []
    transformed = any(isinstance(r, dict) and r.get("action") not in (None, Action.KEEP.value) for r in elements)
    check("NOT_THE_UNTRANSFORMED_SOURCE", not (source and digest == source and transformed),
          codes.RAW_SOURCE_TEXT_DETECTED)
    if known_originals:
        view, flat = _collapse(text), squash(text)
        leaked = any((_collapse(v) and _collapse(v) in view) or (len(squash(v)) >= 4 and squash(v) in flat)
                     for v in known_originals if isinstance(v, str))
        check("NO_KNOWN_ORIGINAL_VALUE", not leaked, codes.ORIGINAL_VALUE_PRESENT)

    # re-scan of exactly what would be sent --------------------------------------------------------------
    found = _rescan(text)
    canary = any(t == "CANARY" for t, _s, _a in found) or _CANARY_FAMILY in squash(text)
    restricted = any(s == "RESTRICTED" and t != "CANARY" for t, s, _a in found)
    residual = any(s != "RESTRICTED" and a is not Action.KEEP for _t, s, a in found)
    check("NO_CANARY", not canary, codes.CANARY_DETECTED)
    check("NO_RESTRICTED_ELEMENT", not restricted, codes.RESTRICTED_ELEMENT_DETECTED)
    check("NO_RESIDUAL_SENSITIVE_ELEMENT", not residual, codes.RESIDUAL_SENSITIVE_DETECTED)
    by_kind = Counter((t, s) for t, s, a in found if s == "RESTRICTED" or a is not Action.KEEP)
    findings = [{"type": t, "sensitivity": s, "count": n} for (t, s), n in sorted(by_kind.items())]
    if canary and not any(f["type"] == "CANARY" for f in findings):  # caught only by the literal check
        findings.append({"type": "CANARY", "sensitivity": "RESTRICTED", "count": 1})

    allowed = not reasons
    dry = _dry_run(allowed=allowed, mode=mode, artifact_id=artifact_id, reasons=reasons, received_type="SafeArtifact",
                   checks=checks, findings=findings, text=text, sha256=digest)
    payload = None
    if allowed:
        payload = ApprovedPayload(_safe_id(artifact_id) or "", pmode, text, digest, _ISSUER)  # type: ignore[arg-type]
    return GuardVerdict(allowed, tuple(reasons), dry, payload)
