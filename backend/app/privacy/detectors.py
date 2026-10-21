"""Deterministic detectors. Plain regular expressions plus a configurable institution vocabulary: no
model, no network, no randomness. Every pattern is listed in PATTERN_DETECTORS with its type and
sensitivity so the whole detection surface can be read (and unit-tested) in one place.

Detection runs on a *normalized view* of the text (compatibility-folded, digits mapped to ASCII, dash
variants mapped to '-', zero-width and other format characters dropped). Each match is mapped back to
exact offsets in the original text, so a canary written as "LAB<ZWSP>-CANARY-７７３１" is still found
and the replacement covers the original characters.

When detectors overlap, the overlapping matches are merged into ONE element spanning their union, typed
and labelled by the strongest match (highest sensitivity, then detector priority, then length). Merging
rather than dropping the weaker match means no fragment of the weaker span is left behind in the output.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Callable

from .graph import DisclosureElement, DisclosureGraph, make_element_id, sensitivity_rank

DETECTOR_SET_VERSION = "aman-detectors-v1"
DEFAULT_LOCATOR = "body"

# Placeholder shapes the sanitizer emits. Source text that already looks like one is itself a finding
# (TOKEN_LOOKALIKE) so it cannot impersonate a real placeholder downstream.
TOKEN_RE = re.compile(r"\[(?:[A-Z]+_\d{2,}|REDACTED:[A-Z_]+)\]")


# ---------------------------------------------------------------------------- normalized view
_STRIPPED_CATEGORIES = {"Cf"}  # zero-width space/joiners, BOM, soft hyphen, bidi marks


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Return (normalized text, origin) where origin[i] is the index in `text` of normalized char i."""
    out: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(text):
        cat = unicodedata.category(ch)
        if cat in _STRIPPED_CATEGORIES:
            continue
        if cat == "Nd":
            rep = str(unicodedata.decimal(ch))
        elif cat == "Pd" or ch == "−":
            rep = "-"
        else:
            rep = unicodedata.normalize("NFKC", ch)
        for r in rep:
            out.append(r)
            origin.append(i)
    return "".join(out), origin


def fold(text: str) -> str:
    """Normalized, case-folded form of a string (used for identity comparison and survival checks)."""
    return normalize_with_map(text)[0].casefold()


def squash(text: str) -> str:
    """Folded form with everything except letters and digits removed: defeats separator tricks."""
    return "".join(c for c in fold(text) if c.isalnum())


# ---------------------------------------------------------------------------- entity-key normalizers
def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def _entity_phone(s: str) -> str:
    d = _digits(s)
    plus = s.lstrip().startswith("+")
    if d.startswith("0092"):
        return "0" + d[4:]
    if plus and d.startswith("92"):
        return "0" + d[2:]
    return d


def _entity_alnum(s: str) -> str:
    return squash(s).upper()


def _entity_fold(s: str) -> str:
    return fold(s).strip()


# ---------------------------------------------------------------------------- validators
def _digit_count_between(lo: int, hi: int) -> Callable[[str], bool]:
    return lambda s: lo <= len(_digits(s)) <= hi


def _budget_amount_plausible(s: str) -> bool:
    """An amount next to a ceiling-style label: 5+ digits, a magnitude word, or a currency marker and 3+ digits."""
    digits = len(_digits(s))
    has_currency = bool(re.match(r"(?i)\s*(?:pkr|rs\.?|usd|\$)", s))
    has_magnitude = bool(re.search(r"(?i)(?:million|mn|crore|lakh)\s*$", s))
    return digits >= 5 or has_magnitude or (has_currency and digits >= 3)


# ---------------------------------------------------------------------------- pattern detectors
@dataclass(frozen=True)
class PatternDetector:
    detector_id: str
    element_type: str
    sensitivity: str
    pattern: re.Pattern[str]
    description: str
    priority: int = 50  # tie-break on overlap after sensitivity: higher wins
    group: str | int = 0  # which group is the finding (the label before it is not redacted)
    validate: Callable[[str], bool] | None = None
    entity: Callable[[str], str] = _entity_fold


_CURRENCY = r"(?:PKR|Rs\.?|USD|\$)"

PATTERN_DETECTORS: tuple[PatternDetector, ...] = (
    PatternDetector(
        "EMAIL-v1", "EMAIL", "CONFIDENTIAL",
        re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+"),
        "Email address: local part, '@', dotted domain.", priority=60),
    PatternDetector(
        "PHONE-PK-v1", "PHONE", "CONFIDENTIAL",
        re.compile(r"(?<![\w+])(?:(?:\+|00)92[\s-]?|0)(?:3\d{2}|[1-9]\d{1,2})[\s-]?\d{6,8}(?!\d)"),
        "Pakistan-style number: +92/0092/0 prefix, mobile (3xx) or landline area code, 6-8 digit subscriber.",
        priority=40, validate=_digit_count_between(9, 14), entity=_entity_phone),
    PatternDetector(
        "PHONE-INTL-v1", "PHONE", "CONFIDENTIAL",
        re.compile(r"(?<![\w+])\+(?!92)\d{1,3}[\s-]?\(?\d{1,4}\)?(?:[\s-]?\d{2,4}){2,4}(?!\d)"),
        "International number written with a leading '+' (8-15 digits).",
        priority=40, validate=_digit_count_between(8, 15), entity=_entity_phone),
    PatternDetector(
        "NATIONAL-ID-SYNTH-v1", "NATIONAL_ID", "CONFIDENTIAL",
        re.compile(r"(?<!\d)\d{5}-\d{7}-\d(?!\d)"),
        "CNIC-like SYNTHETIC national id, format nnnnn-nnnnnnn-n (5-7-1 digits).",
        priority=80, entity=_digits),
    PatternDetector(
        "NATIONAL-ID-LABELED-v1", "NATIONAL_ID", "CONFIDENTIAL",
        re.compile(r"(?i)\b(?:cnic|nic|national\s*id(?:entity)?)(?:\s*(?:no\.?|number))?\s*[:#-]?\s*(?P<v>\d{13})(?!\d)"),
        "13 contiguous digits directly after a CNIC / NIC / national id label.",
        priority=80, group="v", entity=_digits),
    PatternDetector(
        "ACCOUNT-IBAN-PK-v1", "ACCOUNT_NUMBER", "CONFIDENTIAL",
        re.compile(r"(?i)(?<![A-Za-z0-9])PK\d{2}[A-Z]{4}\d{16}(?![A-Za-z0-9])"),
        "Pakistan IBAN: PK, 2 check digits, 4-letter bank code, 16 digits.",
        priority=75, entity=_entity_alnum),
    PatternDetector(
        "ACCOUNT-LABELED-v1", "ACCOUNT_NUMBER", "CONFIDENTIAL",
        re.compile(r"(?i)\b(?:a/c|acct?\.?|account)(?:\s*(?:no\.?|number|num|#))?\s*[:#-]?\s*"
                   r"(?P<v>\d(?:[ -]?\d){6,19})(?!\d)"),
        "7-20 digits directly after an account label (a/c, acct, account, account no).",
        priority=70, group="v", entity=_entity_alnum),
    PatternDetector(
        "BUDGET-CEILING-CONTEXT-v1", "BUDGET_FIGURE", "RESTRICTED",
        re.compile(r"(?i)\b(?:ceiling|budget\s+(?:cap|limit)|approved\s+budget)\b[^\n\d]{0,40}?"
                   rf"(?P<v>(?:{_CURRENCY}\s*)?\d(?:[\d,.]*\d)?(?:\s*(?:million|mn|crore|lakh))?)"),
        "An amount within 40 characters after 'ceiling', 'budget cap/limit' or 'approved budget'.",
        priority=90, group="v", validate=_budget_amount_plausible, entity=_digits),
    PatternDetector(
        "CANARY-v1", "CANARY", "RESTRICTED",
        re.compile(r"(?i)LAB[\s_-]*CANARY(?:[\s_-]*\d+)?"),
        "Lab canary token family: LAB-CANARY-<digits>, any separators, any case.",
        priority=100, entity=_entity_alnum),
    PatternDetector(
        "TOKEN-LOOKALIKE-v1", "TOKEN_LOOKALIKE", "INTERNAL",
        TOKEN_RE,
        "Source text shaped like a sanitizer placeholder ([ORG_01], [REDACTED:X]); neutralized so it "
        "cannot be mistaken for a real placeholder.",
        priority=10, entity=_entity_fold),
)


# ---------------------------------------------------------------------------- institution vocabulary
@dataclass(frozen=True)
class VocabEntry:
    """One named entity with every surface form that should be treated as the same thing."""

    entity_key: str
    element_type: str
    sensitivity: str
    terms: tuple[str, ...]

    def compiled(self) -> re.Pattern[str]:
        alts = sorted(self.terms, key=len, reverse=True)
        body = "|".join(re.escape(t).replace(r"\ ", r"\s+") for t in alts)
        return re.compile(rf"(?<!\w)(?:{body})(?!\w)", re.IGNORECASE)


@dataclass(frozen=True)
class InstitutionVocabulary:
    entries: tuple[VocabEntry, ...] = ()
    restricted_figures: tuple[int, ...] = ()  # known RESTRICTED amounts, e.g. a budget ceiling


def figure_patterns(value: int) -> tuple[re.Pattern[str], ...]:
    """Patterns for one known figure: digit groups with any separator, and 'x.yz million' shorthand."""
    s = str(value)
    groups = [s[max(i - 3, 0):i] for i in range(len(s), 0, -3)][::-1]
    sep = r"[,.\s_']?"
    core = sep.join(groups)
    pats = [re.compile(rf"(?<![\d,.])(?:{_CURRENCY}\s*)?{core}(?!\d|[,.]\d)", re.IGNORECASE)]
    if value % 10_000 == 0:
        mantissa = f"{value / 1_000_000:g}".replace(".", r"\.")
        pats.append(re.compile(rf"(?<![\d.])(?:{_CURRENCY}\s*)?{mantissa}\s*(?:million|mn|m)\b", re.IGNORECASE))
    return tuple(pats)


# Synthetic Northbridge University data only. The canary literal duplicates app.seed.CANARY on purpose;
# a test pins them together so they cannot drift.
DEFAULT_VOCABULARY = InstitutionVocabulary(
    entries=(
        VocabEntry("org:northbridge", "ORG", "INTERNAL", ("Northbridge University", "Northbridge")),
        VocabEntry("canary:lab-canary-7731", "CANARY", "RESTRICTED", ("LAB-CANARY-7731",)),
        VocabEntry("person:ayesha-khan", "PERSON", "CONFIDENTIAL", ("Ayesha Khan",)),
        VocabEntry("person:bilal-ahmed", "PERSON", "CONFIDENTIAL", ("Bilal Ahmed",)),
        VocabEntry("person:fatima-raza", "PERSON", "CONFIDENTIAL", ("Fatima Raza",)),
        VocabEntry("person:omar-siddiqui", "PERSON", "CONFIDENTIAL", ("Omar Siddiqui",)),
        VocabEntry("person:sana-malik", "PERSON", "CONFIDENTIAL", ("Sana Malik",)),
        VocabEntry("person:zara-lodhi", "PERSON", "CONFIDENTIAL", ("Zara Lodhi",)),
    ),
    restricted_figures=(6_950_000,),
)


# ---------------------------------------------------------------------------- detection engine
@dataclass
class _Candidate:
    start: int  # offsets in the ORIGINAL text
    end: int
    element_type: str
    sensitivity: str
    priority: int
    detector_id: str
    entity_key: str


def _strength(c: _Candidate) -> tuple[int, int, int]:
    return (sensitivity_rank(c.sensitivity), c.priority, c.end - c.start)


def _merge_overlaps(cands: list[_Candidate]) -> list[tuple[int, int, _Candidate, list[str]]]:
    """Cluster overlapping candidates; each cluster -> (union start, union end, winner, detector ids)."""
    cands = sorted(cands, key=lambda c: (c.start, c.end))
    clusters: list[list[_Candidate]] = []
    cur_end = -1
    for c in cands:
        if clusters and c.start < cur_end:
            clusters[-1].append(c)
            cur_end = max(cur_end, c.end)
        else:
            clusters.append([c])
            cur_end = c.end
    merged = []
    for cl in clusters:
        winner = max(cl, key=lambda c: (_strength(c), c.detector_id))
        merged.append((min(c.start for c in cl), max(c.end for c in cl), winner,
                       sorted({c.detector_id for c in cl})))
    return merged


def detect(
    text: str,
    *,
    locator: str = DEFAULT_LOCATOR,
    source_trust: str = "unknown",
    owner: str | None = None,
    vocabulary: InstitutionVocabulary = DEFAULT_VOCABULARY,
    source_sha256: str = "",
) -> DisclosureGraph:
    """Find every sensitive element in `text`. Pure and deterministic: same input, same graph."""
    norm, origin = normalize_with_map(text)

    def to_original(ns: int, ne: int) -> tuple[int, int]:
        return origin[ns], origin[ne - 1] + 1

    cands: list[_Candidate] = []

    def collect(pattern: re.Pattern[str], group: str | int, validate: Callable[[str], bool] | None,
                make: Callable[[str], _Candidate]) -> None:
        for m in pattern.finditer(norm):
            ns, ne = m.span(group)
            if ne <= ns:
                continue
            piece = norm[ns:ne]
            if validate is not None and not validate(piece):
                continue
            c = make(piece)
            c.start, c.end = to_original(ns, ne)
            cands.append(c)

    for det in PATTERN_DETECTORS:
        collect(det.pattern, det.group, det.validate,
                lambda piece, d=det: _Candidate(0, 0, d.element_type, d.sensitivity, d.priority,
                                                d.detector_id, d.entity(piece)))
    for entry in vocabulary.entries:
        collect(entry.compiled(), 0, None,
                lambda piece, e=entry: _Candidate(0, 0, e.element_type, e.sensitivity, 70,
                                                  f"VOCAB:{e.entity_key}", e.entity_key))
    for figure in vocabulary.restricted_figures:
        for pat in figure_patterns(figure):
            collect(pat, 0, None,
                    lambda piece: _Candidate(0, 0, "BUDGET_FIGURE", "RESTRICTED", 95,
                                             "VOCAB-FIGURE-v1", _digits(piece)))

    graph = DisclosureGraph(source_sha256)
    for start, end, winner, detector_ids in _merge_overlaps(cands):
        graph.add(DisclosureElement(
            element_id=make_element_id(locator, start, end, winner.element_type),
            element_type=winner.element_type,
            locator=locator,
            start=start,
            end=end,
            sensitivity=winner.sensitivity,
            source_trust=source_trust,
            owner=owner,
            provenance=tuple(f"detector:{d}" for d in detector_ids) + (f"locator:{locator}",),
            text=text[start:end],
            entity_key=winner.entity_key,
        ))
    return graph
