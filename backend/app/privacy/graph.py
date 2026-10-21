"""Disclosure graph: the in-memory model of everything sensitive found in one document.

A DisclosureElement is one located finding (type, span, sensitivity, trust, owner, provenance). A
DisclosureGraph is a collection of them with lookup and a JSON decision-record view.

Two rules shape this module:
  * Element ids are derived from *position and type only*, never from the matched text, so a record can
    be stored or shown without becoming an oracle for the value it describes.
  * The raw matched text lives on the element (the verifier needs it) but is excluded from repr() and
    from every serialized record. It never leaves the process through this module.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping

GRAPH_RECORD_VERSION = "aman-disclosure-graph-v1"

SENSITIVITIES: tuple[str, ...] = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED")
SENSITIVITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SENSITIVITIES)}

# Same vocabulary as Document.trust_label in app.models, plus an explicit "unknown" (treated as untrusted).
SOURCE_TRUST_LEVELS: tuple[str, ...] = ("trusted_internal", "untrusted_external", "unknown")

_TYPE_RE = re.compile(r"^[A-Z][A-Z_]{1,30}$")


def sensitivity_rank(sensitivity: str) -> int:
    """Rank of a label; raises KeyError for anything unknown so callers fail closed."""
    return SENSITIVITY_RANK[sensitivity]


def max_sensitivity(values: Iterable[str]) -> str:
    return max(values, key=sensitivity_rank, default="PUBLIC")


def make_element_id(locator: str, start: int, end: int, element_type: str) -> str:
    """Stable, content-free id: the same position and type always give the same id."""
    raw = f"{locator}|{start}|{end}|{element_type}".encode("utf-8")
    return "E-" + hashlib.sha256(raw).hexdigest()[:12]


@dataclass(frozen=True)
class DisclosureElement:
    element_id: str
    element_type: str  # EMAIL, PHONE, NATIONAL_ID, ACCOUNT_NUMBER, ORG, PERSON, BUDGET_FIGURE, CANARY, ...
    locator: str  # which text segment the offsets refer to, e.g. "body" or "docx:comments"
    start: int
    end: int
    sensitivity: str
    source_trust: str = "unknown"
    owner: str | None = None  # e.g. "tenant:northbridge" or "role:finance_manager"; None if unassigned
    provenance: tuple[str, ...] = ()  # detector ids and source notes that produced this element
    # Raw matched text and its normalized identity. In-memory only: never repr'd, never serialized.
    text: str = field(default="", repr=False)
    entity_key: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if self.sensitivity not in SENSITIVITY_RANK:
            raise ValueError(f"unknown sensitivity label: {self.sensitivity!r}")
        if self.source_trust not in SOURCE_TRUST_LEVELS:
            raise ValueError(f"unknown source_trust: {self.source_trust!r}")
        if not _TYPE_RE.match(self.element_type):
            raise ValueError(f"invalid element_type: {self.element_type!r}")
        if not (0 <= self.start < self.end):
            raise ValueError("element span must satisfy 0 <= start < end")
        if self.text and len(self.text) != self.end - self.start:
            raise ValueError("element text length does not match its span")

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_record(self) -> dict[str, Any]:
        """Serializable view with no raw text and no entity key."""
        return {
            "element_id": self.element_id,
            "element_type": self.element_type,
            "locator": self.locator,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "sensitivity": self.sensitivity,
            "source_trust": self.source_trust,
            "owner": self.owner,
            "provenance": list(self.provenance),
        }


class DisclosureGraph:
    """Ordered collection of DisclosureElement with id lookup and a JSON decision-record view."""

    def __init__(self, source_sha256: str = "", elements: Iterable[DisclosureElement] = ()) -> None:
        self.source_sha256 = source_sha256
        self._by_id: dict[str, DisclosureElement] = {}
        for el in elements:
            self.add(el)

    # ------------------------------------------------------------------ collection
    def add(self, element: DisclosureElement) -> None:
        if element.element_id in self._by_id:
            raise ValueError(f"duplicate element id: {element.element_id}")
        self._by_id[element.element_id] = element

    def extend(self, elements: Iterable[DisclosureElement]) -> None:
        for el in elements:
            self.add(el)

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self) -> Iterator[DisclosureElement]:
        return iter(self.elements)

    def __contains__(self, element_id: object) -> bool:
        return element_id in self._by_id

    @property
    def elements(self) -> tuple[DisclosureElement, ...]:
        """Elements in a stable order: by locator, then start offset, then end offset."""
        return tuple(sorted(self._by_id.values(), key=lambda e: (e.locator, e.start, e.end, e.element_id)))

    # ------------------------------------------------------------------ lookup
    def get(self, element_id: str) -> DisclosureElement:
        return self._by_id[element_id]

    def by_type(self, element_type: str) -> tuple[DisclosureElement, ...]:
        return tuple(e for e in self.elements if e.element_type == element_type)

    def by_sensitivity(self, sensitivity: str) -> tuple[DisclosureElement, ...]:
        return tuple(e for e in self.elements if e.sensitivity == sensitivity)

    def at_locator(self, locator: str) -> tuple[DisclosureElement, ...]:
        return tuple(e for e in self.elements if e.locator == locator)

    def max_sensitivity(self) -> str:
        return max_sensitivity(e.sensitivity for e in self._by_id.values())

    # ------------------------------------------------------------------ serialization
    def counts(self) -> dict[str, dict[str, int]]:
        by_type: dict[str, int] = {}
        by_sens: dict[str, int] = {}
        for e in self._by_id.values():
            by_type[e.element_type] = by_type.get(e.element_type, 0) + 1
            by_sens[e.sensitivity] = by_sens.get(e.sensitivity, 0) + 1
        return {"by_type": dict(sorted(by_type.items())), "by_sensitivity": dict(sorted(by_sens.items()))}

    def to_record(self, annotations: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
        """JSON-safe decision record. `annotations` maps element_id -> extra keys (action, token, ...)."""
        extra = annotations or {}
        rows = []
        for e in self.elements:
            row = e.to_record()
            row.update(extra.get(e.element_id, {}))
            rows.append(row)
        return {
            "record_version": GRAPH_RECORD_VERSION,
            "source_sha256": self.source_sha256,
            "max_sensitivity": self.max_sensitivity(),
            "counts": self.counts(),
            "elements": rows,
        }

    def to_json(self, annotations: Mapping[str, Mapping[str, Any]] | None = None) -> str:
        return canonical_json(self.to_record(annotations))


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only. Same record -> same bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
