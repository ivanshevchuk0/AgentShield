"""Checksum-gated PII detection with exact original spans and safe evidence."""
from __future__ import annotations

import re
import unicodedata
from datetime import date
from typing import Iterator

from app.guardrails.normalize import digits_with_map, strip_invisible
from app.models import Action, Finding, View, mask
from app.policy import PiiCfg

# ISO 13616 national lengths: a checksum alone does not establish an IBAN.
_IBAN_LENGTHS = dict(zip(
    "AL AD AT AZ BH BE BA BR BG CR HR CY CZ DK DO EE FO FI FR GE DE GI GR GL GT HU IS IE IL IT JO KZ XK KW LV LB LI LT LU MT MR MU MD MC ME NL MK NO PK PS PL PT QA RO LC SM ST SA RS SC SK SI ES SE CH TL TN TR UA AE GB VA VG BY EG IQ SV LY RU SD BI DJ SO NI MN FK OM YE HN".split(),
    (28,24,20,28,22,16,20,29,22,22,21,28,24,18,28,20,18,18,27,22,22,23,27,18,28,28,26,22,23,27,30,20,20,30,21,28,21,20,20,31,27,30,24,27,22,18,19,15,24,29,28,25,29,24,32,27,25,24,22,31,24,19,24,24,21,23,24,26,29,23,22,18,22,24,28,29,23,28,25,33,18,27,27,21,28,20,23,23,28,24,28),
))
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,8}(?![\w-])")
_IBAN_START = re.compile(r"(?<!\w)([A-Za-z])[ \t.\-]*([A-Za-z])[ \t.\-]*[0-9][ \t.\-]*[0-9]")
_NUMBERS = re.compile(r"\d+")


def _ascii_digits(s: str, length: int | None = None) -> bool:
    return bool(s) and s.isascii() and s.isdigit() and (length is None or len(s) == length)


def valid_pesel(s: str) -> bool:
    if not _ascii_digits(s, 11):
        return False
    if (sum(int(c) * w for c, w in zip(s[:10], (1,3,7,9,1,3,7,9,1,3))) + int(s[-1])) % 10:
        return False
    month = int(s[2:4])
    century = {0: 1900, 1: 2000, 2: 2100, 3: 2200, 4: 1800}.get(month // 20)
    if century is None:
        return False
    try:
        date(century + int(s[:2]), month % 20, int(s[4:6]))
    except ValueError:
        return False
    return True


def valid_nip(s: str) -> bool:
    return (_ascii_digits(s, 10) and len(set(s)) > 1
            and sum(int(c) * w for c, w in zip(s[:9], (6,5,7,2,3,4,5,6,7))) % 11 == int(s[-1]))


def valid_iban(s: str) -> bool:
    s = "".join(strip_invisible(s).split()).upper()
    if not s.isascii() or len(s) != _IBAN_LENGTHS.get(s[:2]) or not s[2:4].isdigit() or not s.isalnum():
        return False
    remainder = 0
    for c in s[4:] + s[:4]:
        for digit in (c if c.isdigit() else str(ord(c) - 55)):
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def luhn(s: str) -> bool:
    if not _ascii_digits(s) or len(s) < 2 or len(set(s)) == 1 and s[0] == "0":
        return False
    total = 0
    for i, c in enumerate(reversed(s)):
        n = int(c) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def _separator(s: str) -> bool:
    return all(c in " \t.-()" or unicodedata.category(c) == "Cf" for c in s)


def _numeric_candidates(text: str) -> Iterator[tuple[str, int, int, bool]]:
    digits, offsets = digits_with_map(text)
    # Contiguous numbers remain candidates even beside another number separated by spaces.
    emitted: set[tuple[int, int]] = set()
    for match in _NUMBERS.finditer(text):
        if len(match[0]) <= 19:
            emitted.add(match.span())
            yield "".join(str(unicodedata.decimal(c)) for c in match[0]), match.start(), match.end(), False
    start = 0
    for i in range(1, len(offsets) + 1):
        if i == len(offsets) or not _separator(text[offsets[i - 1] + 1:offsets[i]]):
            a, b = offsets[start], offsets[i - 1] + 1
            if (a, b) not in emitted and i - start <= 19:
                yield digits[start:i], a, b, False
            # Only whole digit groups may form subwindows, never substrings of
            # contiguous numbers. Nineteen digits bound the work per group.
            boundaries = [start] + [j for j in range(start + 1, i)
                                    if any(c in " \t.-()" for c in text[offsets[j - 1] + 1:offsets[j]])] + [i]
            lengths = {10, 11, *range(13, 20)}
            if len(set(digits[start:i])) == 1:
                lengths = {n for n in lengths if valid_pesel(digits[start] * n)
                           or valid_nip(digits[start] * n)
                           or n >= 13 and luhn(digits[start] * n)}
            for left, lo in enumerate(boundaries[:-1]) if lengths else ():
                for right in range(left + 1, len(boundaries)):
                    hi = boundaries[right]
                    if hi - lo > 19:
                        break
                    if hi - lo not in lengths or (lo == start and hi == i):
                        continue
                    value = digits[lo:hi]
                    a, b = offsets[lo], offsets[hi - 1] + 1
                    if (a, b) not in emitted:
                        yield value, a, b, True
            start = i


def _matches(text: str, entities: set[str]) -> Iterator[tuple[str, str, int, int]]:
    if "EMAIL" in entities:
        for match in _EMAIL.finditer(text):
            yield "EMAIL", match[0], match.start(), match.end()
    if "IBAN" in entities:
        for match in _IBAN_START.finditer(text):
            expected = _IBAN_LENGTHS.get((match[1] + match[2]).upper())
            if not expected:
                continue
            value: list[str] = []
            end = match.start()
            while end < len(text) and len(value) < expected:
                c = text[end]
                if c.isascii() and c.isalnum():
                    value.append(c)
                elif not (c.isspace() or c in ".-" or unicodedata.category(c) == "Cf"):
                    break
                end += 1
            canonical = "".join(value).upper()
            if (len(value) == expected and (end == len(text) or not text[end].isalnum())
                    and valid_iban(canonical)):
                yield "IBAN", canonical, match.start(), end
    if not entities.intersection({"PESEL", "NIP", "CREDIT_CARD", "PHONE"}):
        return
    for value, start, end, partial in _numeric_candidates(text):
        if (start and text[start - 1].isalnum()) or (end < len(text) and text[end].isalnum()):
            continue
        for entity, length, validator in (("PESEL", 11, valid_pesel), ("NIP", 10, valid_nip)):
            if entity in entities and len(value) == length and validator(value):
                yield entity, value, start, end
        if "CREDIT_CARD" in entities and 13 <= len(value) <= 19 and luhn(value):
            yield "CREDIT_CARD", value, start, end
        if "PHONE" in entities and not partial:
            plus = start > 0 and text[start - 1] == "+"
            parentheses = "(" in text[max(0, start - 1):end]
            if (len(value) == 9 or plus and 10 <= len(value) <= 15 or parentheses and len(value) == 10):
                a = start - 1 if plus or start > 0 and text[start - 1] == "(" else start
                yield "PHONE", value, a, end


def scan(text: str, views: list[View], cfg: PiiCfg) -> list[Finding]:
    if not cfg.enabled:
        return []
    findings: list[Finding] = []
    seen_values: set[tuple[str, str]] = set()
    seen_spans: set[tuple[str, int, int]] = set()
    entities = set(cfg.entities)
    sources = [View("original", text, True)] + [v for v in views if v.text != text]
    for view in sources:
        for entity, value, start, end in _matches(view.text, entities):
            key = entity, value.casefold()
            if view.maps_to_original:
                span = entity, start, end
                if span in seen_spans:
                    continue
                seen_spans.add(span)
            elif key in seen_values:
                continue
            seen_values.add(key)
            findings.append(Finding(f"pii.{entity.lower()}", Action(cfg.action),
                                    start=start if view.maps_to_original else None,
                                    end=end if view.maps_to_original else None, via=view.name,
                                    evidence=mask(value), detail=f"Detected {entity}", owasp="LLM02"))
    return findings


def redact(text: str, findings: list[Finding]) -> str:
    spans = sorted((f.start, f.end, f.control_id.rsplit(".", 1)[-1].upper())
                   for f in findings if f.control_id.startswith("pii.")
                   and f.start is not None and f.end is not None and 0 <= f.start < f.end <= len(text))
    merged: list[tuple[int, int, str]] = []
    for start, end, label in spans:
        if merged and start < merged[-1][1]:
            a, b, previous = merged[-1]
            merged[-1] = a, max(b, end), previous
        else:
            merged.append((start, end, label))
    for start, end, label in reversed(merged):
        text = text[:start] + f"[{label}]" + text[end:]
    return text
