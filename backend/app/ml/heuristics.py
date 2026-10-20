"""Interpretable heuristic signals (advisory only). Reported separately from the ML model's metrics."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import evasion_markers, normalize


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    pattern: re.Pattern
    explanation: str


def _rx(*parts: str) -> re.Pattern:
    return re.compile("|".join(parts), re.IGNORECASE)


SIGNALS = [
    Signal("override_phrase", 0.45, _rx(
        r"\bignore (all |any |your )?(previous|prior|earlier|above) (instructions|rules|guidance|directions)",
        r"\bdisregard (all |your |the )?(previous|prior|system|above)", r"\bforget (your|all|previous) (rules|instructions)",
        r"\bsystem override\b", r"\bnew (system )?instructions?\s*:", r"\boverride (your|the) (policy|rules|safety)",
        r"hidayat (ko )?nazarandaz", r"nazarandaz karo", r"purane rules khatam", r"security band kar",
        r"ہدایات\s*(کو\s*)?نظر\s*انداز", r"پابندیاں\s*بند", r"پرانے\s*اصول\s*ختم",
    ), "Attempts to override the assistant's instructions."),
    Signal("addressed_to_ai", 0.25, _rx(
        r"\b(attention|note (to|for)|dear) (the )?(ai|assistant|model|agent|llm)\b", r"\bai (procurement )?assistant\b",
        r"\b(ai|llm) agent\b", r"\bassistant bhai\b", r"\bmodel ko chahiye\b", r"اے\s*آئی", r"اسسٹنٹ", r"ماڈل\s*کو",
    ), "Text addresses the AI system rather than the human reader."),
    Signal("tool_invocation", 0.35, _rx(
        r"\b(call|invoke|run|execute|chalao|call karo)\b[^\n]{0,40}\b[a-z]+_[a-z_]+\b", r"\b[a-z]+_[a-z_]+\s*\(",
        r"\bsimulated_external_sink\b", r"\brun_shell_command\b",
    ), "Asks for a specific tool/function call."),
    Signal("restricted_resource", 0.3, _rx(
        r"\bbudget-secret-\d+\b", r"\b(internal|secret|restricted|confidential) (budget|ceiling|ledger|files?|records?)\b",
        r"\bpayroll\b", r"خفیہ", r"\bkhufiya\b",
    ), "References restricted internal resources."),
    Signal("external_destination", 0.3, _rx(
        r"[a-z0-9._-]+@(?!university\.test)[a-z0-9-]+(\.[a-z0-9-]+)+", r"\bexternal (archive|portal|server|endpoint)\b",
        r"\bverification portal\b",
    ), "Mentions a destination outside the allowlisted university.test recipients."),
    Signal("secrecy_request", 0.3, _rx(
        r"\bdo not (mention|tell|reveal|inform)\b", r"\bwithout telling\b", r"\bhide this\b", r"\bmat batana\b",
        r"\bchupao\b", r"نہ\s*بتائیں", r"چھپائ",
    ), "Asks the assistant to hide its behaviour from the user."),
]


def score(text: str) -> dict:
    norm = normalize(text)
    hits = []
    p_clean = 1.0
    for sig in SIGNALS:
        m = sig.pattern.search(norm)
        if m:
            hits.append({"signal": sig.name, "weight": sig.weight, "match": m.group(0)[:60], "why": sig.explanation})
            p_clean *= 1 - sig.weight
    markers = evasion_markers(text)
    if markers and hits:
        p_clean *= 0.85
        hits.append({"signal": "evasion_encoding", "weight": 0.15, "match": ",".join(markers),
                     "why": "Instruction-like text was hidden with encoding/Unicode tricks."})
    return {"score": round(1 - p_clean, 4), "signals": hits, "evasion_markers": markers}
