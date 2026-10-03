"""Bounded, offline text views. Only the original view preserves offsets."""
from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata

from app.models import View

_LOOKALIKES = str.maketrans({
    **dict(zip("аеорсухікмтнвјѕ", "aeopcyxikmthbjs")),
    **dict(zip("αβεζηικνορτυχω", "abezhikvoptuxw")),
    "ł": "l", "є": "e", "ґ": "g", "ї": "i",
})
_CASE_LOOKALIKES = str.maketrans({
    **{chr(k): v for k, v in _LOOKALIKES.items()},
    **{chr(k).upper(): v.upper() for k, v in _LOOKALIKES.items()},
})
_SPLIT = re.compile(r"(?<![A-Za-z])[A-Za-z](?:\.[A-Za-z]){2,}(?![A-Za-z])|(?<![A-Za-z])[A-Za-z](?:-[A-Za-z]){2,}(?![A-Za-z])|(?<!\w)[A-Za-z](?: [A-Za-z]){2,}(?!\w)")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{14,}={0,2}")
_HEX = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{16,}(?![A-Za-z0-9])")
_SPLIT_JWT = re.compile(r"(?<![\w.])e\.y\.J[A-Za-z0-9_.-]{10,4096}(?![\w.])")
_SPLIT_MEMBERS = [(re.compile(r"(?<!\w)" + r"\.".join(name) + r"(?!\w)", re.I), restored)
                  for name, restored in (("pickleloads", "pickle.loads"),
                                         ("torchload", "torch.load"))]


def _json_prefix(value: str, limit: int) -> tuple[str, dict] | None:
    # Bounded recovery of a base64 JSON segment. Require a complete object,
    # never guess a delimiter merely from the shape of a token.
    for size in range(4, min(len(value), limit) + 1):
        if size % 4 == 1:
            continue
        segment = value[:size]
        try:
            decoded = base64.b64decode(segment + "=" * (-size % 4), altchars=b"-_", validate=True)
            if not decoded.endswith(b"}"):
                continue
            obj = json.loads(decoded)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            continue
        if isinstance(obj, dict):
            return segment, obj
    return None


def _structured_splits(text: str, max_recovery_chars: int = 4096) -> str:
    for pattern, restored in _SPLIT_MEMBERS:
        text = pattern.sub(restored, text)

    remaining = max(0, max_recovery_chars)

    def jwt(match: re.Match[str]) -> str:
        nonlocal remaining
        if len(match[0]) > remaining:
            return match[0]
        remaining -= len(match[0])
        compact = match[0].replace(".", "")
        header = _json_prefix(compact, 256)
        if header is None or not isinstance(header[1].get("alg"), str):
            return match[0]
        remainder = compact[len(header[0]):]
        payload = _json_prefix(remainder, 2048)
        if payload is None:
            return match[0]
        signature = remainder[len(payload[0]):]
        if not re.fullmatch(r"[A-Za-z0-9_-]{2,2048}", signature):
            return match[0]
        return ".".join((header[0], payload[0], signature))

    return _SPLIT_JWT.sub(jwt, text)


def strip_invisible(text: str) -> str:
    if text.isascii():
        return text
    return "".join(c for c in text if unicodedata.category(c) != "Cf"
                   and not 0xE0000 <= ord(c) <= 0xE007F)


def _canonical(text: str) -> str:
    if text.isascii():
        return text
    text = strip_invisible(unicodedata.normalize("NFKC", text)).translate(_CASE_LOOKALIKES)
    return "".join(c for c in unicodedata.normalize("NFKD", text)
                   if unicodedata.category(c) != "Mn")


def fold(text: str) -> str:
    return _canonical(text).lower()


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

    def collapse(value: str) -> str:
        return _SPLIT.sub(lambda m: re.sub(r"[ .\-]", "", m[0]), value)

    def variants(name: str, value: str) -> None:
        add(name, value)
        canonical = _canonical(value)
        split = collapse(value)
        add(name, _canonical(split) if split != value else canonical)
        add(name, canonical)
        add(name, canonical.lower())
        add("structured_splits", _structured_splits(canonical, max_decode_bytes))
        collapsed = _SPLIT.sub(lambda m: re.sub(r"[ .\-]", "", m[0]), canonical)
        add(name, collapsed)
        add(name, collapsed.lower())

    canonical = _canonical(text)
    add("folded", canonical)
    add("folded", canonical.lower())
    add("structured_splits", _structured_splits(canonical, max_decode_bytes))
    collapsed = _SPLIT.sub(lambda m: re.sub(r"[ .\-]", "", m[0]), canonical)
    add("collapsed", collapsed)
    add("collapsed", collapsed.lower())
    # Split ASCII runs may border letters that only become ASCII after folding.
    split = collapse(text)
    recovered = _canonical(split) if split != text else canonical
    add("collapsed", recovered)
    add("collapsed", recovered.lower())
    tags = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        variants("unicode_tags", tags)
    remaining = max(0, max_decode_bytes)
    sources = list(dict.fromkeys([canonical, collapsed, recovered] + ([tags] if tags else [])))
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
                    nested.extend(dict.fromkeys((_canonical(decoded), _canonical(collapse(decoded)))))
        sources = nested
        if not sources or remaining == 0:
            break
    return result
