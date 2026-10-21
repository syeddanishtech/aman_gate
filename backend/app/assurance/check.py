"""Output assurance for a model reply (AMAN Gate 2.0, WP3): validate, scan, then restore only what is allowed.

The reply is untrusted text from a model that only ever saw pseudonyms such as [PERSON_01]. check_response
runs a fixed pipeline; the first three stages are deterministic enforcement, the last is advisory:

  1. LEAK SCAN     the WP1 detectors run over the raw reply. The canary or any RESTRICTED value BLOCKS the
                   reply (nothing is returned or restored). Other sensitive values found in clear are
                   reported as leaks but do not block: the requester typed or received that text already.
  2. INTEGRITY     every placeholder-shaped string is classified against the set issued for THIS vault
                   session: issued (valid), irreversible ([REDACTED:X], valid but nothing to restore), or
                   not issued (invented). Altered look-alikes ([PERSON_1], [person_01], (ORG_02), PERSON_01,
                   full-width or zero-width variants, ...) are reported as malformed. Restoration is by
                   EXACT string equality with an issued token; there is no normalization, nearest match or
                   guessing anywhere on that path, so an altered or invented placeholder can only stay as is.
  3. REHYDRATION   only exact, issued, reversible placeholders are restored, and only when the requesting
                   role and purpose hold a vault entry for them (ROLE_CLASS_GRANTS ceiling + an entry
                   encrypted for exactly that scope). Everything else stays pseudonymized. Placeholders inside
                   links (URLs, markdown targets, HTML attributes) are never restored: a restored original in
                   a URL is an exfiltration channel. Restoration is one pass over the original reply, so a
                   restored value is never itself re-expanded. Each restored value is screened first (a
                   poisoned vault entry holding the canary or a RESTRICTED value is refused), and the final
                   text is scanned again: the exact string that is returned has just passed the blocking scan,
                   which also catches values that only become restricted once adjacent restorations join.
  4. FLAGS         advisory review signals (figures or references absent from the source, unsupported
                   certainty, unverifiable citations, a small toxicity keyword list, links). They never block
                   and never change what is restored. They are heuristics, not an access boundary.

No stage consults a model or the network. Diagnostics never echo reply content except placeholder-shaped
strings, and only after a scan (a look-alike that contains the canary is withheld).
"""
from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from app.privacy.detectors import TOKEN_RE, detect, normalize_with_map
from app.privacy.policy import DEFAULT_POLICY, PSEUDONYM_CLASS, PrivacyPolicy
from app.privacy.vault import PSEUDONYM_RE, Reveal, VaultConfigError, VaultContext, VaultError, screen_original

ASSURANCE_VERSION = "aman-assurance-v1"
ASSURANCE_POLICY_ID = "POL-OUTPUT-ASSURANCE-v1"
MAX_REPLY_CHARS = 100_000
MAX_SOURCE_CHARS = 400_000
MAX_LISTED = 25  # cap on items listed per diagnostic list (totals are reported separately)
_ECHO_CHARS = 48


class AssuranceInputError(ValueError):
    """The request itself is unusable (not text, too large). Distinct from a failed check."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


# ---------------------------------------------------------------------------- results
@dataclass(frozen=True)
class Leak:
    type: str
    sensitivity: str
    stage: str  # model_reply | vault_entry | rehydrated
    blocking: bool  # True: the reply is withheld
    reason: str
    start: int | None = None
    end: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "sensitivity": self.sensitivity,
                "severity": "CRITICAL" if self.blocking or self.sensitivity == "RESTRICTED" else "HIGH",
                "blocking": self.blocking, "stage": self.stage, "start": self.start, "end": self.end,
                "reason": self.reason}


@dataclass
class AssuranceResult:
    placeholder_integrity: dict[str, Any]
    leaks: list[Leak]
    flags: list[dict[str, Any]]
    rehydrated: str | None
    blocked: bool
    rehydration: dict[str, Any]
    grounding: dict[str, Any]
    reason_codes: list[str] = field(default_factory=list)

    @property
    def audit_decision(self) -> str:
        return "DENY" if self.blocked else "ALLOW"

    def audit_details(self) -> dict[str, Any]:
        """Counts and codes only: never reply text, placeholders' originals or leaked values."""
        r = self.rehydration
        return {"blocked": self.blocked, "restored": r["restored"], "kept_pseudonymized": r["kept_pseudonymized"],
                "rehydration_reasons": dict(r["reasons"]), "aborted": r["aborted"],
                "leak_types": sorted({lk.type for lk in self.leaks}),
                "integrity_ok": self.placeholder_integrity["ok"],
                "flag_codes": sorted({f["code"] for f in self.flags}),
                "scope": dict(r["scope"])}

    def to_response(self) -> dict[str, Any]:
        return {
            "placeholder_integrity": self.placeholder_integrity,
            "leaks": [lk.to_dict() for lk in self.leaks],
            "flags": self.flags,
            "rehydrated": self.rehydrated,
            "blocked": self.blocked,
            "rehydration": self.rehydration,
            "grounding": self.grounding,
            "assurance": {
                "version": ASSURANCE_VERSION, "policy_id": ASSURANCE_POLICY_ID,
                "enforced": ["placeholder_integrity", "leaks", "rehydration"], "advisory": ["flags"],
                "note": "Flags are advisory review signals, not an access boundary. Pseudonymization is "
                        "reversible by design: it is a privacy control, not a guarantee against re-identification.",
            },
        }


# ---------------------------------------------------------------------------- leak scan
def _scan(text: str, policy: PrivacyPolicy, stage: str) -> list[Leak]:
    """Detector hits in `text` as content-free Leak records. TOKEN_LOOKALIKE is the placeholder check's job."""
    out: list[Leak] = []
    for el in detect(text, locator="reply", vocabulary=policy.vocabulary):
        if el.element_type == "TOKEN_LOOKALIKE":
            continue
        blocking = el.element_type == "CANARY" or el.sensitivity == "RESTRICTED"
        reason = ("Restricted value or canary in model output; reply withheld." if blocking
                  else "Sensitive value in clear in model output; the vault did not produce it.")
        out.append(Leak(el.element_type, el.sensitivity, stage, blocking, reason, el.start, el.end))
    return out


def _blocking(leaks: Iterable[Leak]) -> bool:
    return any(lk.blocking for lk in leaks)


def _safe_echo(raw: str, policy: PrivacyPolicy) -> str:
    """A reply fragment that is safe to show in diagnostics: ASCII-escaped, truncated, and withheld
    outright if it contains the canary or a RESTRICTED value (e.g. an invented "[LABCANARY_7731]")."""
    if _blocking(_scan(raw, policy, "echo")):
        return "[withheld]"
    shown = raw[:_ECHO_CHARS].encode("ascii", "backslashreplace").decode("ascii")
    return shown + ("..." if len(raw) > _ECHO_CHARS else "")


# ---------------------------------------------------------------------------- links
_LINK_RES = (
    re.compile(r"(?i)(?<![a-z0-9])(?:https?|ftps?|wss?|file)://[^\s<>\"']*"),
    re.compile(r"(?i)(?<![a-z0-9])(?:javascript|vbscript|data|mailto|tel|sms):[^\s<>\"']+"),
    re.compile(r"(?i)(?<![a-z0-9])www\.[^\s<>\"']*"),
    re.compile(r"(?i)(?<![\w@.\-])(?:[a-z0-9\-]{1,63}\.)+[a-z]{2,24}[/?][^\s<>\"']*"),  # bare domain + path/query
    re.compile(r"\]\((?>[^)\s]{0,500})\)"),  # markdown link / image target (atomic + bounded: no quadratic scans)
    re.compile(r"(?i)\b(?:href|src|action|formaction|srcset|poster|background|cite)\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]*)"),
)


class _Spans:
    """Disjoint, sorted [start, end) intervals with O(log n) overlap queries (a reply can hold thousands)."""

    def __init__(self, spans: Iterable[tuple[int, int]]) -> None:
        merged: list[list[int]] = []
        for s, e in sorted(spans):
            if merged and s < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        self._starts = [s for s, _ in merged]
        self._ends = [e for _, e in merged]

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect_left(self._starts, end) - 1  # the last interval that begins before `end`
        return i >= 0 and self._ends[i] > start

    def intervals(self) -> list[tuple[int, int]]:
        return list(zip(self._starts, self._ends))

    def __bool__(self) -> bool:
        return bool(self._starts)

    def __len__(self) -> int:
        return len(self._starts)


def _link_spans(norm: str, origin: list[int]) -> _Spans:
    """Spans (in original-text offsets) a renderer could treat as a link, found on the normalized view so
    full-width or zero-width disguises do not hide them."""
    return _Spans((origin[m.start()], origin[m.end() - 1] + 1) for pat in _LINK_RES for m in pat.finditer(norm))


# ---------------------------------------------------------------------------- placeholders
@dataclass(frozen=True)
class _Occurrence:
    start: int
    end: int
    token: str
    status: str  # issued | irreversible | not_issued | unverified


@lru_cache(maxsize=32)
def _loose_patterns(classes: frozenset[str]) -> tuple[re.Pattern[str], ...]:
    """Shapes that look like a mangled placeholder of a known class. Detection only: nothing found here is
    ever restored."""
    names = "|".join(sorted(classes, key=lambda c: (-len(c), c)))
    opener, closer = r"[\[\(\{<]", r"[\]\)\}>]"
    return (
        # [PERSON_1]  [Person 01]  (ORG-02)  [ PERSON_01 ]  [PERSON_01a]  {PERSON_01}
        re.compile(opener + r"\s*(?:" + names + r")(?![A-Za-z])[^\]\)\}>\n\d]{0,12}\d{1,6}[^\]\)\}>\n]{0,12}" + closer,
                   re.IGNORECASE),
        # [REDACTED]  [redacted: budget]  (REDACTED:X)
        re.compile(opener + r"\s*REDACTED(?![A-Za-z])[^\]\)\}>\n]{0,40}" + closer, re.IGNORECASE),
        # PERSON_01 without brackets (upper case only: "person 1" is ordinary prose)
        re.compile(r"(?<![A-Za-z0-9_])(?:" + names + r")_[0-9]{1,6}(?![A-Za-z0-9_])"),
    )


def _occurrences(response: str, ctx: VaultContext | None) -> list[_Occurrence]:
    out: list[_Occurrence] = []
    for m in TOKEN_RE.finditer(response):
        tok = m.group(0)
        if ctx is None:
            status = "unverified"
        elif tok in ctx.issued_tokens:  # exact string equality, nothing else
            status = "irreversible" if tok.startswith("[REDACTED:") else "issued"
        else:
            status = "not_issued"
        out.append(_Occurrence(m.start(), m.end(), tok, status))
    return out


def _malformed(response: str, norm: str, origin: list[int], ctx: VaultContext | None,
               exact: list[_Occurrence]) -> list[str]:
    classes = set(PSEUDONYM_CLASS.values())
    if ctx is not None:
        classes |= {m.group(1) for t in ctx.issued_tokens if (m := PSEUDONYM_RE.fullmatch(t))}
    exact_spans = _Spans((o.start, o.end) for o in exact)
    found: list[tuple[int, int]] = []
    for pat in _loose_patterns(frozenset(classes)):
        for m in pat.finditer(norm):
            s, e = origin[m.start()], origin[m.end() - 1] + 1
            if not exact_spans.overlaps(s, e):
                found.append((s, e))
    return [response[s:e] for s, e in _Spans(found).intervals()]


def _listed(values: Iterable[str], policy: PrivacyPolicy) -> tuple[list[str], int]:
    uniq = sorted(set(values))
    return [_safe_echo(v, policy) for v in uniq[:MAX_LISTED]], len(uniq)


def _integrity(ctx: VaultContext | None, exact: list[_Occurrence], malformed: list[str],
               policy: PrivacyPolicy) -> dict[str, Any]:
    valid = {o.token for o in exact if o.status in ("issued", "irreversible")}
    unexpected = {o.token for o in exact if o.status == "not_issued"}
    unverified = {o.token for o in exact if o.status == "unverified"}
    dropped = (set(ctx.issued_tokens) - valid) if ctx is not None else set()
    if ctx is not None:
        ok: bool | None = not unexpected and not malformed
        status = "OK" if ok and valid else "NO_PLACEHOLDERS" if ok else "VIOLATIONS"
    elif malformed:
        ok, status = False, "VIOLATIONS"
    elif unverified:
        ok, status = None, "NO_SESSION_CONTEXT"
    else:
        ok, status = True, "NO_PLACEHOLDERS"
    valid_l, _ = _listed(valid, policy)
    unexpected_l, unexpected_n = _listed(unexpected, policy)
    unverified_l, _ = _listed(unverified, policy)
    malformed_l, malformed_n = _listed(malformed, policy)
    dropped_l, _ = _listed(dropped, policy)
    return {
        "ok": ok, "status": status,
        "expected": len(ctx.issued_tokens) if ctx is not None else 0,
        "found": len(valid) + len(unexpected) + len(unverified),
        "valid": valid_l, "unexpected": unexpected_l, "malformed": malformed_l, "dropped": dropped_l,
        "unverified": unverified_l, "unexpected_total": unexpected_n, "malformed_total": malformed_n,
    }


# ---------------------------------------------------------------------------- advisory flags
@dataclass(frozen=True, eq=False)
class ToxicityLexicon:
    """A tiny, reviewable keyword list. Heuristic: expect false positives and misses; it is configurable
    by design (pass your own) and is never used to block or rewrite output."""

    version: str
    categories: Mapping[str, tuple[str, ...]]


DEFAULT_TOXICITY_LEXICON = ToxicityLexicon("aman-toxicity-lexicon-v1", MappingProxyType({
    "insult": ("idiot", "idiots", "stupid", "moron", "morons", "imbecile", "dumb", "pathetic", "worthless"),
    "threat": ("kill you", "hurt you", "destroy you", "you will regret", "you'll regret", "make you pay"),
    "abuse": ("shut up", "get lost", "go to hell", "loser"),
}))


@lru_cache(maxsize=8)
def _compile_lexicon(lex: ToxicityLexicon) -> tuple[tuple[str, re.Pattern[str]], ...]:
    out = []
    for cat, terms in lex.categories.items():
        body = "|".join(re.escape(t.casefold()).replace(r"\ ", r"\s+") for t in sorted(terms, key=len, reverse=True))
        out.append((cat, re.compile(r"(?<!\w)(?:" + body + r")(?!\w)")))
    return tuple(out)


_CERTAINTY_RE = re.compile(
    r"(?i)\b(?:guaranteed?|100\s*%\s*(?:certain|sure|safe|accurate|compliant)|without (?:any |a )?doubt|"
    r"risk[- ]free|absolutely (?:certain|no risk)|definitely (?:approved|compliant|safe)|"
    r"officially (?:confirmed|approved|verified))\b")
_CITATION_RE = re.compile(
    r"(?i)\b(?:according to (?:a|an|the|our)\s+[\w\- ]{3,40}?(?:study|report|audit|survey|review|investigation)|"
    r"studies (?:show|have shown)|research (?:shows|proves)|et al\.)|(?<![\w\[])\[\d{1,3}\](?![\w\]])")
_FIGURE_RE = re.compile(  # digit runs are bounded so a hostile reply cannot make Decimal/int conversions huge
    r"(?i)(?<![\w.,])((?:pkr|rs\.?|usd|\$)\s*)?(\d{1,3}(?:,\d{3}){1,8}(?:\.\d{1,6})?|\d{1,30}(?:\.\d{1,6})?)"
    r"(?:\s*(million|mn|crore|lakh|percent|%)(?![A-Za-z]))?")
_REF_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,15}(?:-[A-Z0-9]{1,15}){1,4}\b")
_MULTIPLIER = {"million": 10**6, "mn": 10**6, "crore": 10**7, "lakh": 10**5}


def _figure_key(num: str, unit: str | None) -> str | None:
    """Notation-independent key: '7,280,000', '7280000' and '7.28 million' are the same figure."""
    try:
        d = Decimal(num.replace(",", ""))
    except (InvalidOperation, ValueError):
        return None
    u = (unit or "").lower()
    if u in ("%", "percent"):
        return f"{d.normalize():f}%"
    v = d * _MULTIPLIER.get(u, 1)
    return str(int(v)) if v == v.to_integral_value() else f"{v.normalize():f}"


def _figures(text: str, *, significant_only: bool) -> set[str]:
    keys: set[str] = set()
    for m in _FIGURE_RE.finditer(text):
        currency, num, unit = m.group(1), m.group(2), m.group(3)
        if significant_only and not (currency or unit or len(re.sub(r"\D", "", num)) >= 3):
            continue
        key = _figure_key(num, unit)
        if key is not None:
            keys.add(key)
    return keys


def _grounding(norm_reply: str, source: str | None, ctx: VaultContext | None,
               policy: PrivacyPolicy) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Figures and document references in the reply that the safe copy does not contain."""
    if source is None:
        return {"evaluated": False, "reason": "NO_SOURCE_TEXT"}, []
    verified = None
    if ctx is not None:
        verified = hashlib.sha256(source.encode("utf-8")).hexdigest() == ctx.artifact_sha256
        if not verified:
            return {"evaluated": False, "reason": "SOURCE_DIGEST_MISMATCH"}, []
    src_norm = normalize_with_map(source)[0]
    missing_figs = sorted(_figures(norm_reply, significant_only=True) - _figures(src_norm, significant_only=False))
    src_refs = {r.upper() for r in _REF_RE.findall(src_norm)}
    missing_refs = sorted({r for r in _REF_RE.findall(norm_reply) if r.upper() not in src_refs})
    info = {"evaluated": True, "source_verified": bool(verified), "reason": None,
            "figures_not_in_source": len(missing_figs), "references_not_in_source": len(missing_refs)}
    flags = []
    if missing_figs or missing_refs:
        ex_figs, _ = _listed(missing_figs[:5], policy)
        ex_refs, _ = _listed(missing_refs[:5], policy)
        flags.append({
            "code": "UNGROUNDED_CLAIM", "basis": "not-in-source", "advisory": True,
            "message": f"{len(missing_figs)} figure(s) and {len(missing_refs)} reference(s) in the reply do not "
                       "appear in the safe copy. Check them against the source.",
            "examples": {"figures": ex_figs, "references": ex_refs}})
    return info, flags


def _advisory_flags(response: str, norm: str, link_spans: _Spans, lexicon: ToxicityLexicon) -> list[dict[str, Any]]:
    flags: list[dict[str, Any]] = []
    if not response.strip():
        flags.append({"code": "EMPTY_RESPONSE", "advisory": True, "message": "The reply is empty."})
    certainty = len(_CERTAINTY_RE.findall(norm))
    if certainty:
        flags.append({"code": "UNGROUNDED_CLAIM", "basis": "unsupported-certainty", "advisory": True,
                      "count": certainty,
                      "message": "Absolute or guaranteed wording with no cited source. Verify before relying on it."})
    citations = len(_CITATION_RE.findall(norm))
    if citations:
        flags.append({"code": "UNGROUNDED_CLAIM", "basis": "unverifiable-citation", "advisory": True,
                      "count": citations,
                      "message": "The reply cites studies, reports or numbered references that cannot be checked here."})
    folded = norm.casefold()
    hits = {cat: n for cat, pat in _compile_lexicon(lexicon) if (n := len(pat.findall(folded)))}
    if hits:
        flags.append({"code": "TOXICITY", "advisory": True, "categories": hits, "lexicon": lexicon.version,
                      "message": "Keyword heuristic matched abusive wording. Review the reply; it was not altered or blocked."})
    if link_spans:
        flags.append({"code": "LINK_IN_OUTPUT", "advisory": True, "count": len(link_spans),
                      "message": "The reply contains link-like text. The gateway never fetches links, and "
                                 "placeholders inside links are not restored."})
    return flags


# ---------------------------------------------------------------------------- pipeline
def _validate(response: Any, grounding_text: Any) -> None:
    for name, val, limit in (("RESPONSE", response, MAX_REPLY_CHARS), ("SOURCE", grounding_text, MAX_SOURCE_CHARS)):
        if val is None and name == "SOURCE":
            continue
        if not isinstance(val, str):
            raise AssuranceInputError(f"{name}_NOT_TEXT")
        try:
            val.encode("utf-8")
        except UnicodeEncodeError:
            raise AssuranceInputError(f"{name}_NOT_TEXT", "contains unpaired surrogates") from None
        if len(val) > limit:
            raise AssuranceInputError(f"{name}_TOO_LARGE", f"limit is {limit} characters")


def check_response(
    response: str, *, ctx: VaultContext | None, role: str, purpose: str, grounding_text: str | None = None,
    policy: PrivacyPolicy = DEFAULT_POLICY, lexicon: ToxicityLexicon = DEFAULT_TOXICITY_LEXICON,
) -> AssuranceResult:
    """Check one model reply for the identity (`role`, `purpose`) holding `ctx` (None: no vault session).

    Never raises for a bad reply: problems become leaks, integrity failures or an unrestored result. Raises
    AssuranceInputError only when the request itself is unusable."""
    _validate(response, grounding_text)
    norm, origin = normalize_with_map(response)

    # 1. leak scan of the raw reply -----------------------------------------------------------------
    leaks = _scan(response, policy, "model_reply")
    blocked = _blocking(leaks)

    # 2. placeholder integrity ----------------------------------------------------------------------
    exact = _occurrences(response, ctx)
    integrity = _integrity(ctx, exact, _malformed(response, norm, origin, ctx, exact), policy)
    link_spans = _link_spans(norm, origin)

    # 3. rehydration --------------------------------------------------------------------------------
    reasons: Counter[str] = Counter()
    rehydrated: str | None = None
    restored = 0
    aborted = False
    codes: list[str] = []
    if blocked:
        if exact:
            reasons["BLOCKED"] = len(exact)
    elif ctx is None:
        if exact:
            reasons["NO_SESSION_CONTEXT"] = len(exact)
    else:
        candidates = [o for o in exact if o.status == "issued"]
        for status, reason in (("not_issued", "NOT_ISSUED"), ("irreversible", "IRREVERSIBLE")):
            n = sum(1 for o in exact if o.status == status)
            if n:
                reasons[reason] += n
        in_link = {o for o in candidates if link_spans.overlaps(o.start, o.end)}
        if in_link:
            reasons["IN_LINK_CONTEXT"] += len(in_link)
        eligible = [o for o in candidates if o not in in_link]
        tokens = sorted({o.token for o in eligible})
        try:
            reveals: dict[str, Reveal] = ctx.reveal_many(tokens, role=role, purpose=purpose)
        except VaultConfigError:  # a deployment fault (bad master secret): restore nothing, say why
            reveals = {t: Reveal(t, "VAULT_NOT_CONFIGURED") for t in tokens}
        except VaultError:  # e.g. a corrupted session row: same, fail closed
            reveals = {t: Reveal(t, "AUTH_FAILED") for t in tokens}
        accepted: dict[str, str] = {}
        failure_codes: dict[str, str] = {}
        for tok in tokens:
            rv = reveals.get(tok) or Reveal(tok, "NO_ENTRY_FOR_SCOPE")
            if rv.code != "OK" or rv.value is None:
                failure_codes[tok] = {"AUTH_FAILED": "VAULT_INTEGRITY_FAILURE",
                                      "VAULT_NOT_CONFIGURED": "VAULT_NOT_CONFIGURED"}.get(rv.code, "NOT_AUTHORIZED")
                continue
            why = screen_original(rv.value, policy)  # a poisoned entry is refused, not trusted
            if why is not None:
                failure_codes[tok] = "ENTRY_REJECTED"
                if why == "RESTRICTED_VALUE":
                    leaks.append(Leak("VAULT_ENTRY", "RESTRICTED", "vault_entry", False,
                                      "A vault entry holds a restricted value; it was not restored."))
                continue
            accepted[tok] = rv.value
        for o in eligible:
            if o.token in failure_codes:
                reasons[failure_codes[o.token]] += 1
        if accepted:
            todo = sorted((o for o in eligible if o.token in accepted), key=lambda o: o.start)
            todo_set = set(todo)
            pieces: list[str] = []
            pos = 0
            for o in todo:  # single pass over the ORIGINAL reply: restored text is never scanned for tokens
                pieces.append(response[pos:o.start])
                pieces.append(accepted[o.token])
                pos = o.end
            pieces.append(response[pos:])
            candidate = "".join(pieces)
            kept = Counter(o.token for o in exact if o not in todo_set)
            if Counter(TOKEN_RE.findall(candidate)) != kept:
                aborted = True  # restoring would have formed or consumed a placeholder-shaped string
                reasons["TOKEN_FORMATION"] += 1
            else:
                post = _scan(candidate, policy, "rehydrated")  # the exact string that may be returned
                if _blocking(post):
                    aborted = True  # e.g. two innocent values that together form the canary
                    leaks.extend(lk for lk in post if lk.blocking)
                    reasons["RESCAN_BLOCKED"] += 1
                else:
                    rehydrated, restored = candidate, len(todo)
    kept_total = len(exact) - restored

    # 4. advisory flags + grounding -----------------------------------------------------------------
    grounding, grounding_flags = _grounding(norm, grounding_text, ctx, policy)
    flags = [*grounding_flags, *_advisory_flags(response, norm, link_spans, lexicon)]

    # reason codes for the audit trail (codes only) ---------------------------------------------------
    if blocked:
        codes.append("OUTPUT_BLOCKED")
    if leaks:
        codes.append("LEAK_DETECTED")
    if integrity["ok"] is False:
        codes.append("PLACEHOLDER_VIOLATION")
    if restored:
        codes.append("REHYDRATED" if not kept_total else "REHYDRATION_PARTIAL")
    elif reasons.get("NOT_AUTHORIZED"):
        codes.append("REHYDRATION_DENIED")
    for code in ("VAULT_INTEGRITY_FAILURE", "ENTRY_REJECTED", "NO_SESSION_CONTEXT"):
        if reasons.get(code):
            codes.append("VAULT_ENTRY_REJECTED" if code == "ENTRY_REJECTED" else code)
    if aborted:
        codes.append("REHYDRATION_ABORTED_RESCAN")

    rehydration = {
        "applied": rehydrated is not None, "restored": restored, "kept_pseudonymized": kept_total,
        "aborted": aborted, "reasons": dict(sorted(reasons.items())),
        "scope": {"role": role, "purpose": purpose},
    }
    return AssuranceResult(integrity, leaks, flags, rehydrated, blocked, rehydration, grounding,
                           list(dict.fromkeys(codes)))


__all__ = [
    "ASSURANCE_POLICY_ID", "ASSURANCE_VERSION", "AssuranceInputError", "AssuranceResult",
    "DEFAULT_TOXICITY_LEXICON", "Leak", "MAX_REPLY_CHARS", "MAX_SOURCE_CHARS", "ToxicityLexicon", "check_response",
]
