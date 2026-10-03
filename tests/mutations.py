"""Deterministic, offline obfuscations; no randomness or detector dependencies.

Letter substitutions are for readable text, not case-sensitive credentials or
encoded tokens. Callers decide applicability before applying a transform.
"""
from __future__ import annotations

import base64
import re

_HOMOGLYPHS = dict(zip("aeopcxisj", "аеорсхіѕј"))
_POLISH = dict(zip("acelnosz", "ąćęłńóśż"))
_LEET = dict(zip("aeiost", "431057"))


def _table(mapping: dict[str, str]) -> dict[int, str]:
    return str.maketrans({**mapping, **{k.upper(): v.upper() for k, v in mapping.items()}})


def zero_width(text: str) -> str:
    return "\u200b".join(text)


def homoglyphs(text: str) -> str:
    return text.translate(_table(_HOMOGLYPHS))


def case_flips(text: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))


def polish_diacritics(text: str) -> str:
    return text.translate(_table(_POLISH))


def base64_wrap(text: str) -> str:
    return "payload: " + base64.b64encode(text.encode("utf-8")).decode("ascii")


def hex_wrap(text: str) -> str:
    return "payload: " + text.encode("utf-8").hex()


def unicode_tags(text: str) -> str:
    # Tags carry ASCII only. Non-ASCII text is losslessly carried as base64 tags.
    payload = text if text.isascii() and all(32 <= ord(c) <= 126 for c in text) else base64_wrap(text)
    return "Attached note. " + "".join(chr(0xE0000 + ord(c)) for c in payload)


def split_letters(text: str) -> str:
    # Dots preserve word boundaries, unlike spaces which merge adjacent split words.
    return re.sub(r"[A-Za-z]{3,}", lambda m: ".".join(m[0]), text)


def leetspeak(text: str) -> str:
    return text.translate(_table(_LEET))


TRANSFORMS = {
    "zero_width": zero_width,
    "homoglyphs": homoglyphs,
    "case_flips": case_flips,
    "polish_diacritics": polish_diacritics,
    "base64": base64_wrap,
    "hex": hex_wrap,
    "unicode_tags": unicode_tags,
    "split_letters": split_letters,
    "leetspeak": leetspeak,
}
