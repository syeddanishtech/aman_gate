"""Deterministic sanitizer: text (or already-extracted segments) in, SafeArtifact out.

The transformation applied to each finding is decided by PrivacyPolicy (see policy.py); this module only
carries it out. Guarantees:

  * Deterministic: the same input, task, role, destination and policy give byte-identical text, record
    and digest. There is no clock, randomness or secret in the output.
  * Pseudonyms are entity-consistent within ONE document ("Ayesha Khan" and "ayesha  khan" both become
    [PERSON_01]) and distinct across entities ([PERSON_02] for someone else). Numbering restarts per
    document, so tokens carry no cross-document linkage.
  * RESTRICTED findings are redacted irreversibly or block the export. They are never pseudonymized,
    generalized or kept (also asserted here, independently of the policy table).
  * Fail closed: any problem (unknown role, no task, oversized input, internal error, a DENY finding)
    yields EXPORT_BLOCKED with empty text. A blocked artifact never carries partially sanitized text.

sanitize_text is the single-string entry point. sanitize_segments handles the multi-part output of
extract.py: body segments become the artifact; every other segment (metadata, comments, tracked
deletions, hidden text, links) is scanned for findings but never carried into the artifact.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .detectors import TOKEN_RE, detect, fold
from .graph import BODY_KIND, DisclosureElement, DisclosureGraph, TextSegment, canonical_json
from .policy import (
    DECISION_RECORD_VERSION,
    DEFAULT_POLICY,
    EXPORT_ALLOWED,
    EXPORT_BLOCKED,
    GENERALIZED_LABEL,
    HIDDEN_CONTENT_KINDS,
    MAX_TASK_CHARS,
    PSEUDONYM_CLASS,
    Action,
    PrivacyPolicy,
    destination_class,
)

_RULE_TO_REASON = {
    "R-DENY-TYPE": "DENIED_ELEMENT_TYPE",
    "R-RESTRICTED-EXTERNAL": "RESTRICTED_EXTERNAL_DESTINATION",
    "R-UNKNOWN-FAILCLOSED": "UNKNOWN_FAILCLOSED",
}
_RESTRICTED_OK_ACTIONS = frozenset({Action.REDACT, Action.OMIT, Action.DENY})


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


EMPTY_SHA256 = sha256_text("")


@dataclass(frozen=True)
class SafeArtifact:
    """The only thing that may be handed to an AI: sanitized text, plus the record of how it was made."""

    export_status: str  # EXPORT_ALLOWED | EXPORT_BLOCKED
    text: str  # sanitized text; "" whenever the export is blocked
    sha256: str  # SHA-256 of `text` (UTF-8)
    decision_record: dict[str, Any]  # versioned, JSON-safe, contains no raw values
    # Local-only. Excluded from repr/compare and from the record; never put these on the wire.
    source_graph: DisclosureGraph | None = field(default=None, repr=False, compare=False)
    # token -> first-seen original text, PSEUDONYMIZE only. A local rehydration table, never sent outward.
    rehydration_table: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False)

    @property
    def export_allowed(self) -> bool:
        return self.export_status == EXPORT_ALLOWED

    def record_json(self) -> str:
        return canonical_json(self.decision_record)


class _Pseudonymizer:
    """Per-document token allocator: stable per entity, counters per token class, order of first use."""

    def __init__(self) -> None:
        self._next: dict[str, int] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        self.table: dict[str, str] = {}

    def token(self, element: DisclosureElement) -> str:
        cls = PSEUDONYM_CLASS.get(element.element_type, element.element_type.replace("_", ""))
        key = (cls, element.entity_key or fold(element.text))
        tok = self._tokens.get(key)
        if tok is None:
            n = self._next.get(cls, 0) + 1
            self._next[cls] = n
            tok = f"[{cls}_{n:02d}]"
            self._tokens[key] = tok
            self.table[tok] = element.text
        return tok


def _render(element: DisclosureElement, action: Action, pseud: _Pseudonymizer) -> str:
    """The replacement text for one finding. DENY never renders: the whole export is blocked instead."""
    if action is Action.KEEP:
        return element.text
    if action is Action.OMIT:
        return ""
    if action is Action.GENERALIZE:
        return GENERALIZED_LABEL.get(element.element_type, f"[{element.element_type.lower().replace('_', ' ')}]")
    if action is Action.PSEUDONYMIZE:
        return pseud.token(element)
    if action is Action.REDACT:
        return f"[REDACTED:{element.element_type}]"
    raise ValueError(f"action {action.value} cannot be rendered")


def _check_replacement(element: DisclosureElement, action: Action, rep: str) -> None:
    """Self-check of every replacement before it is used or recorded: it must be exactly the placeholder
    shape its action promises and must not carry the original text. Raises, which blocks the export."""
    if action is Action.KEEP:
        ok = rep == element.text
    elif action is Action.OMIT:
        ok = rep == ""
    elif action is Action.GENERALIZE:
        ok = rep.startswith("[") and rep.endswith("]") and fold(element.text) not in fold(rep)
    else:  # PSEUDONYMIZE, REDACT
        ok = TOKEN_RE.fullmatch(rep) is not None
    if not ok:
        raise ValueError("renderer produced a replacement that does not match its action")


# ---------------------------------------------------------------------------- record + blocked artifacts
def _summary(rows: Sequence[Mapping[str, Any]], graph: DisclosureGraph | None) -> dict[str, Any]:
    by_action: dict[str, int] = {}
    for r in rows:
        by_action[r["action"]] = by_action.get(r["action"], 0) + 1
    counts = graph.counts() if graph is not None else {"by_type": {}, "by_sensitivity": {}}
    return {
        "elements_found": len(rows),
        "max_sensitivity": graph.max_sensitivity() if graph is not None else "PUBLIC",
        "by_action": dict(sorted(by_action.items())),
        **counts,
    }


def _record(*, policy: PrivacyPolicy, task: Any, role: Any, destination: Any, source_sha256: str,
            segments: Sequence[TextSegment], status: str, reasons: Sequence[str],
            blocking_ids: Sequence[str], inspected: bool, rows: Sequence[Mapping[str, Any]],
            graph: DisclosureGraph | None, artifact_text: str,
            extraction: Mapping[str, Any] | None) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "record_version": DECISION_RECORD_VERSION,
        "policy": policy.describe(),
        "request": {
            "task": task if isinstance(task, str) else None,
            "role": role if isinstance(role, str) else None,
            "destination": destination if isinstance(destination, str) else None,
            "destination_class": destination_class(destination),
        },
        "source": {
            "sha256": source_sha256,
            "chars": sum(len(s.text) for s in segments if isinstance(s.text, str)),
            "segments": [{"locator": s.locator, "kind": s.kind,
                          "chars": len(s.text) if isinstance(s.text, str) else 0,
                          "carried": s.kind == BODY_KIND} for s in segments],
        },
        "inspected": inspected,
        "export_status": status,
        "block_reasons": list(reasons),
        "blocking_element_ids": list(blocking_ids),
        "summary": _summary(rows, graph),
        "elements": list(rows),
        "artifact": {"sha256": sha256_text(artifact_text), "chars": len(artifact_text)},
    }
    if extraction is not None:
        rec["extraction"] = dict(extraction)
    return rec


def blocked_artifact(
    reasons: Sequence[str], *, task: Any = None, role: Any = None, destination: Any = None,
    policy: PrivacyPolicy = DEFAULT_POLICY, source_sha256: str = "", segments: Sequence[TextSegment] = (),
    extraction: Mapping[str, Any] | None = None, graph: DisclosureGraph | None = None,
    rows: Sequence[Mapping[str, Any]] = (), blocking_ids: Sequence[str] = (), inspected: bool = False,
) -> SafeArtifact:
    """An EXPORT_BLOCKED artifact: empty text, the reasons, and (if known) what was found."""
    rec = _record(policy=policy, task=task, role=role, destination=destination, source_sha256=source_sha256,
                  segments=segments, status=EXPORT_BLOCKED, reasons=reasons, blocking_ids=blocking_ids,
                  inspected=inspected, rows=rows, graph=graph, artifact_text="", extraction=extraction)
    return SafeArtifact(EXPORT_BLOCKED, "", EMPTY_SHA256, rec, source_graph=graph)


# ---------------------------------------------------------------------------- core
def _precheck(segments: Sequence[TextSegment], task: Any, role: Any, policy: PrivacyPolicy) -> list[str]:
    reasons: list[str] = []
    if not isinstance(role, str) or role not in policy.known_roles:
        reasons.append("UNKNOWN_ROLE")
    if not isinstance(task, str) or not task.strip() or len(task) > MAX_TASK_CHARS:
        reasons.append("TASK_INVALID")
    if any(not isinstance(s.text, str) or not _encodable(s.text) for s in segments):
        reasons.append("NOT_TEXT")
    elif sum(len(s.text) for s in segments) > policy.max_chars:
        reasons.append("TEXT_TOO_LARGE")
    if len({s.locator for s in segments}) != len(segments):
        reasons.append("DUPLICATE_LOCATOR")
    return reasons


def _sanitize(segments: Sequence[TextSegment], *, source_sha256: str, task: str, role: str, destination: str,
              policy: PrivacyPolicy, source_trust: str, extraction: Mapping[str, Any] | None) -> SafeArtifact:
    common = dict(task=task, role=role, destination=destination, policy=policy, source_sha256=source_sha256,
                  segments=segments, extraction=extraction)
    pre = _precheck(segments, task, role, policy)
    if pre:
        return blocked_artifact(pre, **common)

    dest_class = destination_class(destination)
    graph = DisclosureGraph(source_sha256)
    for seg in segments:
        graph.extend(detect(seg.text, locator=seg.locator, source_trust=source_trust,
                            vocabulary=policy.vocabulary, source_sha256=source_sha256))

    kind_of = {s.locator: s.kind for s in segments}
    decisions: dict[str, tuple[Action, str]] = {}
    for el in graph:
        action, rule = policy.action_for(el, destination_class=dest_class)
        if action is not Action.DENY and kind_of[el.locator] != BODY_KIND:
            action, rule = Action.OMIT, "R-SEGMENT-OMITTED"  # segment is not part of the artifact at all
        if el.sensitivity == "RESTRICTED" and action not in _RESTRICTED_OK_ACTIONS:
            raise ValueError("policy returned a non-redacting action for a RESTRICTED element")
        decisions[el.element_id] = (action, rule)

    reasons: list[str] = []
    blocking = [eid for eid, (a, _) in decisions.items() if a is Action.DENY]
    for eid in blocking:
        code = _RULE_TO_REASON.get(decisions[eid][1], "DENIED_ELEMENT")
        if code not in reasons:
            reasons.append(code)
    if policy.block_on_hidden_content and any(s.kind in HIDDEN_CONTENT_KINDS and s.text.strip() for s in segments):
        reasons.append("HIDDEN_CONTENT_PRESENT")

    def rows(replacements: Mapping[str, str] | None) -> list[dict[str, Any]]:
        out = []
        for el in graph.elements:
            action, rule = decisions[el.element_id]
            row = el.to_record()
            row.update({"action": action.value, "rule_id": rule})
            if replacements is not None and el.element_id in replacements and action is not Action.KEEP:
                row["replacement"] = replacements[el.element_id]
            out.append(row)
        return out

    if reasons:
        return blocked_artifact(reasons, graph=graph, rows=rows(None), blocking_ids=sorted(blocking),
                                inspected=True, **common)

    pseud = _Pseudonymizer()
    replacements: dict[str, str] = {}
    rendered: list[str] = []
    for seg in segments:
        if seg.kind != BODY_KIND:
            continue
        pieces: list[str] = []
        pos = 0
        for el in graph.at_locator(seg.locator):
            if el.start < pos:
                raise ValueError("overlapping elements reached the renderer")
            action, _ = decisions[el.element_id]
            rep = _render(el, action, pseud)
            _check_replacement(el, action, rep)
            replacements[el.element_id] = rep
            pieces.append(seg.text[pos:el.start])
            pieces.append(rep)
            pos = el.end
        pieces.append(seg.text[pos:])
        rendered.append("".join(pieces))
    text = "\n\n".join(rendered)
    text.encode("utf-8")  # raises on lone surrogates: such text cannot be exported or hashed

    rec = _record(policy=policy, task=task, role=role, destination=destination, source_sha256=source_sha256,
                  segments=segments, status=EXPORT_ALLOWED, reasons=[], blocking_ids=[], inspected=True,
                  rows=rows(replacements), graph=graph, artifact_text=text, extraction=extraction)
    return SafeArtifact(EXPORT_ALLOWED, text, sha256_text(text), rec, source_graph=graph,
                        rehydration_table=dict(pseud.table))


def sanitize_segments(
    segments: Sequence[TextSegment], *, task: str, role: str, destination: str,
    policy: PrivacyPolicy = DEFAULT_POLICY, source_sha256: str = "", source_trust: str = "untrusted_external",
    extraction: Mapping[str, Any] | None = None,
) -> SafeArtifact:
    """Sanitize extracted segments (see extract.py). Body segments form the artifact; the rest are omitted."""
    try:
        return _sanitize(segments, source_sha256=source_sha256, task=task, role=role, destination=destination,
                         policy=policy, source_trust=source_trust, extraction=extraction)
    except Exception as exc:  # fail closed: never let a bug turn into an export
        return blocked_artifact(["INTERNAL_ERROR"], task=task, role=role, destination=destination, policy=policy,
                                source_sha256=source_sha256, segments=segments,
                                extraction={**(extraction or {}), "error_type": type(exc).__name__})


def sanitize_text(
    text: str, *, task: str, role: str, destination: str, policy: PrivacyPolicy = DEFAULT_POLICY,
    locator: str = BODY_KIND, source_trust: str = "unknown",
) -> SafeArtifact:
    """Sanitize one string for `task` / `role` / `destination` under `policy`. Never raises."""
    seg = TextSegment(locator, BODY_KIND, text)
    sha = sha256_text(text) if isinstance(text, str) and _encodable(text) else ""
    return sanitize_segments([seg], task=task, role=role, destination=destination, policy=policy,
                             source_sha256=sha, source_trust=source_trust)


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


__all__ = ["SafeArtifact", "blocked_artifact", "sanitize_segments", "sanitize_text", "sha256_text", "EMPTY_SHA256"]
