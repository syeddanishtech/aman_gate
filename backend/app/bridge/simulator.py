"""The local simulator behind LOCAL_SIMULATOR: a deterministic responder, not a language model.

It reads ONLY the sanitized text it is handed and describes it: size, headline, which placeholders appear,
what the Privacy Shield withheld, a few lines, and a next step. Nothing is generated from outside that text:
every placeholder in the answer is one that was in the input, lines are cut at placeholder boundaries so no
token is ever half-printed, and there is no clock, randomness, file or network access. The same input always
gives byte-identical output, which makes the demo replayable and the tests exact.

It does not follow instructions found in the text. Wording that looks like an instruction aimed at an AI
(a keyword rule, not a classifier) is only counted and reported, to show that document content is treated
as data.
"""
from __future__ import annotations

import re
from collections import Counter

from app.privacy.detectors import TOKEN_RE

SIMULATOR_ID = "aman-local-simulator-v1"
MARKER = "[SIMULATED RESPONSE - LOCAL_SIMULATOR - no model was called, nothing left this machine]"

HEADLINE_CHARS = 120
LINE_CHARS = 100
KEY_LINES = 3

_INSTRUCTION_RE = re.compile(
    r"(?i)\b(?:ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)|system\s+override"
    r"|disregard\s+(?:the\s+)?(?:previous|above|rules)|you\s+must\s+now|call\s+\w+\(|run_shell_command"
    r"|simulated_external_sink|export_all_records)")


def _clip(line: str, limit: int) -> str:
    """Shorten a line to `limit` characters without cutting a [PLACEHOLDER] in half."""
    if len(line) <= limit:
        return line
    cut = line[:limit]
    open_at = cut.rfind("[")
    if open_at != -1 and "]" not in cut[open_at:]:
        cut = cut[:open_at]
    return cut.rstrip() + "..."


def _tally(counts: Counter[str]) -> str:
    return ", ".join(f"{tok} x{n}" for tok, n in sorted(counts.items()))


def respond(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    counts = Counter(TOKEN_RE.findall(text))
    pseudonyms = Counter({t: n for t, n in counts.items() if not t.startswith("[REDACTED:")})
    withheld = Counter({t: n for t, n in counts.items() if t.startswith("[REDACTED:")})

    out = [MARKER]
    if lines:
        out.append(f"Summary: the safe copy has {len(lines)} non-empty line(s) and {len(text.split())} word(s).")
        out.append(f'Headline: "{_clip(lines[0], HEADLINE_CHARS)}"')
    else:
        out.append("Summary: the safe copy is empty.")
    out.append(f"Protected references (placeholders left as they are): {_tally(pseudonyms)}."
               if pseudonyms else "Protected references: none.")
    if withheld:
        out.append(f"Withheld by the Privacy Shield: {_tally(withheld)}.")
    if len(lines) > 1:
        out.append("Key lines:")
        out.extend(f"- {_clip(ln, LINE_CHARS)}" for ln in lines[1:1 + KEY_LINES])
    flagged = sum(1 for ln in lines if _INSTRUCTION_RE.search(ln))
    if flagged:
        out.append(f"Note: {flagged} line(s) contain instruction-like wording (keyword rule). "
                   "It was treated as document data and not followed.")
    contact = next((t for t in sorted(pseudonyms) if t.startswith("[PERSON_")), None) \
        or next((t for t in sorted(pseudonyms) if t.startswith("[EMAIL_")), None)
    out.append(f"Suggested next step: confirm details with {contact} through the approved channel." if contact
               else "Suggested next step: route to the document owner for review.")
    return "\n".join(out)
