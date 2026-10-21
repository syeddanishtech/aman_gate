"""Independent verification of a SafeArtifact before it may leave the machine.

The sanitizer's own bookkeeping is not trusted. verify_artifact re-derives what it needs from the
artifact text itself:

  1. EXPORTABLE         a blocked artifact never passes (it has nothing to export).
  2. DIGEST             SHA-256 of the text matches the artifact and its record.
  3. REEXTRACT          the text is pushed back through the extractor as raw bytes (a second parse of
                        the product, as a downstream reader would see it). Failure to re-extract fails.
  4. RECORD_MATCHES_GRAPH, RECORD_POLICY
                        the decision record covers exactly the original graph and every recorded action
                        is the one the policy dictates; a RESTRICTED element must be redacted, never
                        pseudonymized or kept.
  5. VALUE_SURVIVAL     no original sensitive value is still present, tested on the folded text (case,
                        width, digit-script, zero-width and dash variants) and on a letters-and-digits-only
                        "squashed" view that defeats inserted separators.
  6. RESIDUAL_SCAN      the detectors are run again over the artifact; any finding the policy would
                        transform (and any RESTRICTED finding at all) is a failure.
  7. TOKEN_INTEGRITY    every placeholder-shaped string in the artifact was issued by the sanitizer.

Any failure, and any internal error, is fail closed. Findings name the offending element id and type,
never the value.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .detectors import TOKEN_RE, detect, fold, squash
from .extract import STATUS_OK, extract_text_bytes
from .graph import DisclosureElement, DisclosureGraph, sensitivity_rank
from .policy import DEFAULT_POLICY, Action, PrivacyPolicy
from .sanitize import SafeArtifact

CHECKS = ("EXPORTABLE", "DIGEST", "REEXTRACT", "RECORD_MATCHES_GRAPH", "RECORD_POLICY", "VALUE_SURVIVAL",
          "RESIDUAL_SCAN", "TOKEN_INTEGRITY")
_REDACTING = frozenset({"REDACT", "OMIT", "DENY"})


@dataclass(frozen=True)
class VerifyFinding:
    check: str
    code: str
    element_id: str | None = None
    element_type: str | None = None
    sensitivity: str | None = None

    def to_record(self) -> dict[str, Any]:
        return {"check": self.check, "code": self.code, "element_id": self.element_id,
                "element_type": self.element_type, "sensitivity": self.sensitivity}


@dataclass(frozen=True)
class VerifyResult:
    passed: bool
    findings: tuple[VerifyFinding, ...] = ()
    checks_run: tuple[str, ...] = ()

    @property
    def offending_element_id(self) -> str | None:
        """Id of the most severe offending element (RESTRICTED first), or None."""
        return next((f.element_id for f in self.findings if f.element_id), None)

    def to_record(self) -> dict[str, Any]:
        return {"passed": self.passed, "checks_run": list(self.checks_run),
                "offending_element_id": self.offending_element_id,
                "findings": [f.to_record() for f in self.findings]}


def _collapse(s: str) -> str:
    return " ".join(fold(s).split())


def _finding(check: str, code: str, el: DisclosureElement | None = None) -> VerifyFinding:
    if el is None:
        return VerifyFinding(check, code)
    return VerifyFinding(check, code, el.element_id, el.element_type, el.sensitivity)


def _severity(f: VerifyFinding) -> int:
    return 3 - sensitivity_rank(f.sensitivity) if f.sensitivity else 4


def verify_artifact(artifact: SafeArtifact, original_graph: DisclosureGraph | None,
                    policy: PrivacyPolicy = DEFAULT_POLICY) -> VerifyResult:
    """Return passed=True only if every check holds. Never raises; errors are failures."""
    try:
        return _verify(artifact, original_graph, policy)
    except Exception:  # fail closed
        return VerifyResult(False, (VerifyFinding("VERIFIER", "VERIFIER_ERROR"),), ())


def _verify(artifact: SafeArtifact, graph: DisclosureGraph | None, policy: PrivacyPolicy) -> VerifyResult:
    findings: list[VerifyFinding] = []
    ran: list[str] = []
    rec = artifact.decision_record

    def done() -> VerifyResult:
        ordered = tuple(sorted(findings, key=_severity))  # stable: RESTRICTED first, then check order
        return VerifyResult(not ordered, ordered, tuple(ran))

    # 1. exportable ------------------------------------------------------------------------------
    ran.append("EXPORTABLE")
    if not artifact.export_allowed:
        blocking = rec.get("blocking_element_ids") or [None]
        el = graph.get(blocking[0]) if graph is not None and blocking[0] in graph else None
        findings.append(VerifyFinding("EXPORTABLE", "ARTIFACT_NOT_EXPORTABLE",
                                      blocking[0], el.element_type if el else None, el.sensitivity if el else None))
        return done()
    if graph is None:
        findings.append(_finding("RECORD_MATCHES_GRAPH", "GRAPH_MISSING"))
        return done()

    # 2. digest ----------------------------------------------------------------------------------
    ran.append("DIGEST")
    try:
        raw = artifact.text.encode("utf-8")
    except UnicodeEncodeError:  # cannot be exported or hashed at all
        ran.append("REEXTRACT")
        findings.append(_finding("REEXTRACT", "REEXTRACT_FAILED"))
        return done()
    if hashlib.sha256(raw).hexdigest() != artifact.sha256 or rec.get("artifact", {}).get("sha256") != artifact.sha256:
        findings.append(_finding("DIGEST", "DIGEST_MISMATCH"))

    # 3. independent re-extraction ---------------------------------------------------------------
    ran.append("REEXTRACT")
    again = extract_text_bytes(raw)
    if again.status != STATUS_OK:
        findings.append(_finding("REEXTRACT", "REEXTRACT_FAILED"))
        return done()
    extracted = again.body_text
    views = {_collapse(artifact.text), _collapse(extracted)}
    squashed = {squash(artifact.text), squash(extracted)}

    # 4. record vs graph vs policy ---------------------------------------------------------------
    dest_class = rec["request"]["destination_class"]
    rows = {r["element_id"]: r for r in rec["elements"]}
    carried = {s["locator"]: s["carried"] for s in rec["source"]["segments"]}
    ran += ["RECORD_MATCHES_GRAPH", "RECORD_POLICY", "VALUE_SURVIVAL"]
    if set(rows) != {e.element_id for e in graph}:
        findings.append(_finding("RECORD_MATCHES_GRAPH", "RECORD_GRAPH_MISMATCH"))
    original_by_value: dict[str, DisclosureElement] = {}
    for el in graph.elements:
        row = rows.get(el.element_id)
        if row is None:
            continue
        recorded = row["action"]
        expected, _rule = policy.action_for(el, destination_class=dest_class)
        if el.sensitivity == "RESTRICTED" and recorded not in _REDACTING:
            findings.append(_finding("RECORD_POLICY", "RESTRICTED_NOT_REDACTED", el))
        if expected is Action.DENY:
            findings.append(_finding("RECORD_POLICY", "DENIED_ELEMENT_IN_EXPORT", el))
        elif recorded != expected.value and not (recorded == "OMIT" and not carried.get(el.locator, True)):
            findings.append(_finding("RECORD_POLICY", "RECORD_POLICY_MISMATCH", el))
        if el.element_type == "TOKEN_LOOKALIKE":
            continue  # handled by TOKEN_INTEGRITY: the artifact legitimately contains real placeholders
        original_by_value.setdefault(_collapse(el.text), el)
        if recorded != Action.KEEP.value:
            v, s = _collapse(el.text), squash(el.text)
            if (v and any(v in view for view in views)) or (len(s) >= 4 and any(s in sq for sq in squashed)):
                findings.append(_finding("VALUE_SURVIVAL", "VALUE_SURVIVED", el))

    # 5. residual scan: the detectors again, over what is actually leaving ------------------------
    ran.append("RESIDUAL_SCAN")
    # Placeholders become line breaks so a label before a redacted value cannot reach across it.
    scan_view = TOKEN_RE.sub("\n", extracted)
    for r in detect(scan_view, locator="artifact", vocabulary=policy.vocabulary):
        if r.element_type == "TOKEN_LOOKALIKE":
            continue
        action, _ = policy.action_for(r, destination_class=dest_class)
        if r.sensitivity == "RESTRICTED" or action is not Action.KEEP:
            known = original_by_value.get(_collapse(r.text))
            findings.append(_finding("RESIDUAL_SCAN", "RESIDUAL_DETECTED", known or r))

    # 6. token integrity ------------------------------------------------------------------------
    ran.append("TOKEN_INTEGRITY")
    issued = {r["replacement"] for r in rec["elements"] if r.get("replacement")}
    if any(tok not in issued for tok in TOKEN_RE.findall(extracted)):
        findings.append(_finding("TOKEN_INTEGRITY", "FORGED_TOKEN"))

    return done()
