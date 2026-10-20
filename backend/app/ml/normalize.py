"""Text normalisation shared by the agent simulator, the heuristics and the ML classifier.

Undoes common evasion tricks so that both the (vulnerable) simulated agent and the advisory detectors
see the same text: Unicode compatibility forms, zero-width / bidi control characters, dash variants,
a small Cyrillic/Greek homoglyph table and embedded base64 segments (decoded text is appended).
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­‪‫‬‭‮⁦⁧⁨⁩"), None)
DASHES = {ord(c): "-" for c in "‐‑‒–—―−﹣－"}
HOMOGLYPHS = {ord(k): v for k, v in {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "І": "I", "Ѕ": "S", "ο": "o", "α": "a", "Ο": "O", "Α": "A",
}.items()}
B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")


def decode_base64_segments(text: str, max_segments: int = 8) -> list[str]:
    out: list[str] = []
    for m in B64_TOKEN.finditer(text):
        if len(out) >= max_segments:
            break
        tok = m.group(0)
        if len(tok) % 4:
            continue
        try:
            raw = base64.b64decode(tok, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
        if decoded and printable / len(decoded) > 0.95:
            out.append(decoded)
    return out


def normalize(text: str, decode_b64: bool = True) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(ZERO_WIDTH).translate(DASHES).translate(HOMOGLYPHS)
    if decode_b64:
        decoded = decode_base64_segments(t)
        if decoded:
            t = t + "\n" + "\n".join(normalize(d, decode_b64=False) for d in decoded)
    return t


def evasion_markers(text: str) -> list[str]:
    markers = []
    if any(ord(c) in ZERO_WIDTH for c in text):
        markers.append("invisible_characters")
    if any(ord(c) in HOMOGLYPHS for c in text):
        markers.append("homoglyphs")
    if any(ord(c) in DASHES for c in text):
        markers.append("dash_variants")
    if decode_base64_segments(unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)):
        markers.append("base64_segment")
    return markers
