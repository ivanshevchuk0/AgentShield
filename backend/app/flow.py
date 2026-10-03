"""Offline provenance and hash-only flow checks, optionally persisted in signed audit."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import threading
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Callable, Iterator
from urllib.parse import unquote_plus

from app.guardrails.normalize import fold, views
from app.models import Action, Finding
from app.policy import FlowCfg, ToolCfg


def _key(key: bytes | str) -> bytes:
    return key.encode() if isinstance(key, str) else key


def sign_call_id(raw: str, tool: str, session: str, key: bytes | str, *,
                 agent_id: str | None = None, content: str | None = None) -> str:
    """Authenticate the original id, tool name and session as one payload."""
    if not all(isinstance(v, str) for v in (raw, tool, session)) or not tool:
        raise ValueError("call provenance must contain strings and a tool name")
    payload = base64.urlsafe_b64encode(
        json.dumps([raw, tool, session] + ([agent_id,
                    hmac.new(_key(key), content.encode(), hashlib.sha256).hexdigest() if content is not None else None]
                    if agent_id is not None or content is not None else []),
                   separators=(",", ":"), ensure_ascii=True).encode()
    ).decode().rstrip("=")
    signature = hmac.new(_key(key), payload.encode(), hashlib.sha256).hexdigest()
    return f"call_w.{payload}.{signature}"


def verify_call_id(call_id: str, key: bytes | str, *, agent_id: str | None = None,
                   session: str | None = None, tool: str | None = None,
                   content: str | None = None) -> str | None:
    """Return authenticated tool provenance; malformed or forged ids are untrusted."""
    if not isinstance(call_id, str) or len(call_id) > 16384:
        return None
    try:
        prefix, payload, signature = call_id.split(".")
        if prefix != "call_w" or not re.fullmatch(r"[A-Za-z0-9_-]+", payload):
            return None
        expected = hmac.new(_key(key), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None
        data = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True))
        if not isinstance(data, list) or len(data) not in (3, 5) or not all(isinstance(v, str) for v in data[:3]) or not data[1]:
            return None
        if len(data) == 3:
            if agent_id is not None or content is not None:
                return None
            data += [None, None]
        if agent_id is not None and data[3] != agent_id:
            return None
        if session is not None and data[2] != session:
            return None
        if tool is not None and data[1] != tool:
            return None
        if content is not None and data[4] != hmac.new(_key(key), content.encode(), hashlib.sha256).hexdigest():
            return None
        return data[1]
    except (ValueError, TypeError, UnicodeError, binascii.Error):
        pass
    return None


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _strings(child)
    elif value is not None and not isinstance(value, bool):
        yield str(value)


def _decoded(text: str) -> set[str]:
    """Reuse detector views; also cover URL escapes and short encoded values."""
    found = {text}
    frontier = {text}
    for _ in range(2):
        fresh: set[str] = set()
        for item in frontier:
            fresh.update(view.text for view in views(item))
            fresh.add(unquote_plus(item))
            for token in re.findall(r"[A-Za-z0-9_+/=-]{8,}", item):
                if len(token) > 8192:
                    continue
                candidates: list[bytes] = []
                try:
                    candidates.append(base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True))
                except (ValueError, binascii.Error):
                    pass
                if len(token) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", token):
                    candidates.append(bytes.fromhex(token))
                for data in candidates:
                    if not data or len(data) > 4096:
                        continue
                    try:
                        decoded = data.decode("utf-8")
                    except UnicodeError:
                        continue
                    if sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) >= 0.85:
                        fresh.add(decoded)
        frontier = fresh - found
        found.update(fresh)
    return found


def _alnum(text: str) -> str:
    return "".join(c for c in fold(text) if c.isalnum())


def _digest(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


def _shingles(text: str, width: int) -> tuple[bytes, ...]:
    return tuple(_digest(text[i:i + width]) for i in range(len(text) - width + 1))


@dataclass
class _Source:
    labels: frozenset[str]
    # Entity lengths and hashes; never retain the tool result or raw values.
    entities: set[tuple[int, bytes]]
    shingles: dict[int, tuple[bytes, ...]]


@dataclass
class _Session:
    labels: set[str] = field(default_factory=set)
    sources: list[_Source] = field(default_factory=list)


class TaintStore:
    """Only gateway-mediated tool results are added; user input is never tainted."""

    def __init__(self, records: list[dict] | None = None,
                 persist: Callable[[dict], Any] | None = None, key: bytes | None = None) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.RLock()
        self._persist = persist
        self._hash_key = key
        for record in records or []:
            if record.get("kind") != "flow_state":
                continue
            principal = record["principal"]
            if record.get("clear"):
                self._sessions.pop(principal, None)
                continue
            session = self._sessions.setdefault(principal, _Session())
            session.labels.update(record["labels"])
            for source in record["sources"]:
                session.sources.append(_Source(
                    frozenset(source["labels"]),
                    {(size, bytes.fromhex(digest)) for size, digest in source["entities"]},
                    {int(width): tuple(bytes.fromhex(digest) for digest in hashes)
                     for width, hashes in source["shingles"].items()},
                ))

    def _hash(self, text: str) -> bytes:
        # Keyed fingerprints resist offline guessing of short identifiers.
        if self._hash_key is not None:
            return hmac.new(self._hash_key, text.encode(), hashlib.sha256).digest()
        return _digest(text)

    def _hash_shingles(self, text: str, width: int) -> tuple[bytes, ...]:
        return tuple(self._hash(text[i:i + width]) for i in range(len(text) - width + 1))

    def add(self, session_id: str, tool_name: str, labels: list[str], content: str) -> None:
        labels_set = frozenset(labels)
        sources: list[_Source] = []
        if labels_set & {"secret", "untrusted"}:
            for text in _decoded(content):
                folded = fold(text)
                entities = set()
                patterns = (
                    r"[0-9](?:[ \t.-]*[0-9]){7,}",
                    r"[\w.+-]+@[\w.-]+\.[a-z]{2,}",
                    r"\b[a-z]{2}[ -]*[0-9]{2}(?:[ -]*[a-z0-9]){11,30}\b",
                )
                for pattern in patterns:
                    for match in re.finditer(pattern, folded):
                        value = _alnum(match.group())
                        entities.add((len(value), self._hash(value)))
                        if "secret" in labels_set and value.isdigit():
                            # Six digits catch meaningful identifier fragments, not short tokens.
                            entities.update((6, self._hash(value[i:i + 6])) for i in range(len(value) - 5))
                normal = _alnum(text)
                digits = "".join(c for c in folded if c in "0123456789")
                for form in {normal, digits}:
                    sources.append(_Source(labels_set, entities, {w: self._hash_shingles(form, w) for w in (6, 12)}))
        with self._lock:
            if self._persist and labels_set & {"secret", "untrusted"}:
                self._persist({"kind": "flow_state", "principal": session_id,
                               "labels": sorted(labels_set), "sources": [
                    {"labels": sorted(source.labels),
                     "entities": sorted((size, digest.hex()) for size, digest in source.entities),
                     "shingles": {str(width): [digest.hex() for digest in hashes]
                                  for width, hashes in source.shingles.items()}}
                    for source in sources]})
            session = self._sessions.setdefault(session_id, _Session())
            session.labels.update(labels_set)
            session.sources.extend(sources)

    def labels(self, session_id: str) -> set[str]:
        with self._lock:
            session = self._sessions.get(session_id)
            return set(session.labels) if session else set()

    def clear(self, session_id: str) -> None:
        with self._lock:
            if self._persist:
                self._persist({"kind": "flow_state", "principal": session_id, "clear": True})
            self._sessions.pop(session_id, None)

    def _matches(self, source: _Source, forms: set[str], minimum: int) -> bool:
        # Entity-specific minima (e.g. 8 digits) are independent of general shingles.
        for size, digest in source.entities:
            if any(self._hash(text[i:i + size]) == digest for text in forms for i in range(len(text) - size + 1)):
                return True
        width = 6 if minimum < 12 else 12
        required = minimum - width + 1
        stored = source.shingles[width]
        # ponytail: quadratic on repetitive text; use a rolling-hash index if sessions get large.
        return any(
            SequenceMatcher(None, stored, self._hash_shingles(text, width), autojunk=False).find_longest_match().size >= required
            for text in forms if len(text) >= minimum
        )

    def check_egress(
        self, session_id: str, tool_name: str, tool: ToolCfg, args: dict[str, Any], flow: FlowCfg,
    ) -> list[Finding]:
        if not flow.enabled:
            return []
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return []
            labels, sources = set(session.labels), tuple(session.sources)

        def forms(value: Any) -> set[str]:
            result: set[str] = set()
            strings = list(_strings(value))
            for string in [*strings, "".join(strings)]:
                for text in _decoded(string):
                    result.add(_alnum(text))
                    result.add("".join(c for c in fold(text) if c in "0123456789"))
            return result

        findings: list[Finding] = []
        checks = (
            ("secret", tool.egress, args, "flow.secret_egress", flow.rules.secret_to_egress),
            ("untrusted", bool(tool.target_args), {k: args[k] for k in tool.target_args if k in args},
             "flow.untrusted_target", flow.rules.untrusted_value_as_target),
        )
        for label, enabled, values, control, action in checks:
            if enabled and label in labels:
                candidates = forms(values)
                if any(label in source.labels and self._matches(source, candidates, flow.min_chars) for source in sources):
                    findings.append(Finding(control, Action(action), evidence="[protected tool-result value]",
                                            detail=f"Protected {label} value reused by {tool_name}", owasp="LLM06"))
        if "untrusted" in labels and tool.irreversible:
            rule = flow.rules.untrusted_before_irreversible
            action = Action.REQUIRE_APPROVAL if rule == "approval" else Action(rule)
            findings.append(Finding("flow.untrusted_before_irreversible", action,
                                    detail=f"Untrusted context precedes irreversible tool {tool_name}", owasp="LLM06"))
        return findings
