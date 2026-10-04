"""Offline credential signatures; findings never contain an unmasked credential."""
from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from typing import Iterator

from app.models import Action, Finding, View, mask
from app.policy import ControlCfg

_PATTERNS = [(name, re.compile(pattern)) for name, pattern in (
    ("aws", r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
    ("github", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"),
    ("openai", r"\bsk-(?!ant-|or-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    ("anthropic", r"\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    ("openrouter", r"\bsk-or-(?:v1-)?[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    ("slack", r"\b(?:xox[baprs]-|xapp-)[A-Za-z0-9-]{10,255}(?![A-Za-z0-9-])"),
    ("google", r"\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"),
    ("stripe", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,255}(?![A-Za-z0-9])"),
    ("pem", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{2,2048}\.[A-Za-z0-9_-]{2,2048}\.[A-Za-z0-9_-]{2,2048}(?![A-Za-z0-9_-])"),
    ("connstr", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver)://[^\s@/:'\"]{1,128}:[^\s@/'\"]{1,256}@[^\s'\"<>]{1,512}"),
)]
_DSN = re.compile(r"\b(?:server|host|data source)\s*=[^\r\n]{1,512}", re.I)
_DSN_USER = re.compile(r"(?:^|;)\s*(?:user id|uid|user|username)\s*=\s*[^;\s]{1,128}", re.I)
_DSN_PASSWORD = re.compile(r"(?:^|;)\s*(?:password|pwd)\s*=\s*[^;\s]{1,256}", re.I)
_GENERIC = re.compile(r"\b(?:[a-z0-9]{1,24}[_-])?(?:api[_-]?key|password|passwd|pwd|secret|token|access[_-]?token|client[_-]?secret)\b[\"']?[ \t]{0,16}[:=][ \t]{0,16}[\"']?([a-z0-9_+/=.!\-:@$%#&*^~?]{8,256})", re.I)
_PLACEHOLDERS = {"password", "password123", "changeme", "12345678", "abcdefgh", "your_api_key", "your_token_here", "placeholder", "example", "redacted", "notasecret"}


def _entropy(value: str) -> bool:
    if value.lower() in _PLACEHOLDERS or len(value) < 8 or len(set(value)) < 5:
        return False
    frequencies = Counter(value)
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in frequencies.values())
    return entropy >= 2.5


def _jwt(value: str) -> bool:
    try:
        header, payload, _ = value.split(".")
        decoded = [json.loads(base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True))
                   for s in (header, payload)]
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(decoded[0], dict) and isinstance(decoded[1], dict) and isinstance(decoded[0].get("alg"), str)


def _matches(text: str) -> Iterator[tuple[str, str, int, int]]:
    for name, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            if name != "jwt" or _jwt(match[0]):
                yield name, match[0], match.start(), match.end()
    for match in _DSN.finditer(text):
        if _DSN_USER.search(match[0]) and _DSN_PASSWORD.search(match[0]):
            yield "connstr", match[0], match.start(), match.end()
    for match in _GENERIC.finditer(text):
        value = match[1].rstrip()
        if _entropy(value):
            yield "generic", value, match.start(1), match.start(1) + len(value)


def scan(text: str, views: list[View], cfg: ControlCfg) -> list[Finding]:
    if not cfg.enabled:
        return []
    findings: list[Finding] = []
    seen_values: set[tuple[str, str]] = set()
    seen_spans: set[tuple[str, int, int]] = set()
    for view in [View("original", text, True)] + [v for v in views if v.text != text]:
        for name, value, start, end in _matches(view.text):
            key = name, value.casefold()
            if view.maps_to_original:
                span = name, start, end
                if span in seen_spans:
                    continue
                seen_spans.add(span)
            elif key in seen_values:
                continue
            seen_values.add(key)
            findings.append(Finding(f"secrets.{name}", Action(cfg.action),
                                    start=start if view.maps_to_original else None,
                                    end=end if view.maps_to_original else None, via=view.name,
                                    evidence=mask(value), detail=f"Detected {name} credential", owasp="LLM02"))
    return findings


def redact(text: str, findings: list[Finding]) -> str:
    """Replace only original credential spans, retaining surrounding request intent."""
    spans = sorted((f.start, f.end) for f in findings
                   if f.control_id.startswith("secrets.")
                   and f.start is not None and f.end is not None
                   and 0 <= f.start < f.end <= len(text))
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        text = text[:start] + "[SECRET]" + text[end:]
    return text
