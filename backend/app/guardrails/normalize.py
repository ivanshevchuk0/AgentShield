"""Bounded, offline text views. Only the original view preserves offsets."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from app.models import View

_LOOKALIKES = str.maketrans({
    **dict(zip("аеорсухікмтнвјѕ", "aeopcyxikmthbjs")),
    **dict(zip("αβεζηικνορτυχω", "abezhikvoptuxw")),
    "ł": "l", "є": "e", "ґ": "g", "ї": "i",
})
_SPLIT = re.compile(r"(?<!\w)[a-z](?:[ .\-][a-z]){2,}(?!\w)")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_HEX = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{16,}(?![A-Za-z0-9])")


def strip_invisible(text: str) -> str:
    return "".join(c for c in text if unicodedata.category(c) != "Cf"
                   and not 0xE0000 <= ord(c) <= 0xE007F)


def fold(text: str) -> str:
    text = strip_invisible(unicodedata.normalize("NFKC", text)).lower().translate(_LOOKALIKES)
    return "".join(c for c in unicodedata.normalize("NFKD", text)
                   if unicodedata.category(c) != "Mn")


def digits_with_map(text: str) -> tuple[str, list[int]]:
    pairs = [(str(unicodedata.decimal(c)), i) for i, c in enumerate(text) if c.isdecimal()]
    return "".join(c for c, _ in pairs), [i for _, i in pairs]


def views(text: str, max_decode_bytes: int = 4096) -> list[View]:
    result = [View("original", text, True)]
    seen = {text}

    def add(name: str, value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            result.append(View(name, value, False))

    def variants(name: str, value: str) -> None:
        add(name, value)
        folded = fold(value)
        add(name, folded)
        add(name, _SPLIT.sub(lambda m: re.sub(r"[ .\-]", "", m[0]), folded))

    folded = fold(text)
    add("folded", folded)
    add("collapsed", _SPLIT.sub(lambda m: re.sub(r"[ .\-]", "", m[0]), folded))
    tags = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        variants("unicode_tags", tags)
    remaining = max(0, max_decode_bytes)
    sources = [text] + ([tags] if tags else [])
    # Two passes: the outer encoding plus at most one nested encoding.
    for _ in range(2):
        nested: list[str] = []
        for source in sources:
            for name, pattern in (("hex", _HEX), ("base64", _BASE64)):
                for match in pattern.finditer(source):
                    token = match[0]
                    if len(token) < 16 or remaining == 0:
                        continue
                    estimate = len(token) // 2 if name == "hex" else (len(token.rstrip("=")) * 3) // 4
                    if estimate > remaining:
                        continue
                    try:
                        raw = (bytes.fromhex(token) if name == "hex" else
                               base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True))
                        decoded = raw.decode("utf-8")
                    except (ValueError, UnicodeDecodeError, binascii.Error):
                        continue
                    if not decoded or sum(c.isprintable() or c in "\r\n\t" for c in decoded) / len(decoded) < 0.85:
                        continue
                    if decoded in seen:
                        continue
                    remaining -= len(raw)
                    variants(name, decoded)
                    nested.append(decoded)
        sources = nested
        if not sources or remaining == 0:
            break
    return result
