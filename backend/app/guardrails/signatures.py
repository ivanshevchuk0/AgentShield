"""Validated, last-good threat feed and literal canary detection."""

from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from re import _constants, _parser
from typing import Any

import yaml

from app.models import Action, Finding, View, mask
from app.policy import _UniqueKeyLoader, short_error


@dataclass(frozen=True)
class _Signature:
    id: str
    name: str
    category: str
    pattern: re.Pattern[str]
    direction: str
    severity: str
    owasp: str
    reference: str


def _safe_regex(pattern: str) -> re.Pattern[str]:
    """Reject nested repetition, repeated alternation and backreferences.

    Python's regex parser handles escaped punctuation and character classes correctly;
    a regex that tries to validate another regex would not.
    """
    repeats = {_constants.MAX_REPEAT, _constants.MIN_REPEAT, _constants.POSSESSIVE_REPEAT}

    def walk(nodes: Any, repeated: bool = False) -> None:
        for op, arg in nodes:
            if op in repeats:
                if repeated:
                    raise ValueError("nested regex quantifiers are forbidden")
                walk(arg[2], True)
            elif op == _constants.SUBPATTERN:
                walk(arg[3], repeated)
            elif op == _constants.BRANCH:
                if repeated:
                    raise ValueError("repeated regex alternation is forbidden")
                for branch in arg[1]:
                    walk(branch, repeated)
            elif op in {_constants.ASSERT, _constants.ASSERT_NOT, _constants.ATOMIC_GROUP}:
                raise ValueError("regex lookarounds and atomic groups are forbidden")
            elif op in {_constants.GROUPREF, _constants.GROUPREF_EXISTS}:
                raise ValueError("regex backreferences are forbidden")

    if not pattern or len(pattern) > 2000:
        raise ValueError("regex must contain 1..2000 characters")
    walk(_parser.parse(pattern, re.IGNORECASE))
    compiled = re.compile(pattern, re.IGNORECASE)
    if compiled.search(""):
        raise ValueError("regex must not match empty text")
    return compiled


class SignatureFeed:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._entries: tuple[_Signature, ...] = ()
        self._seen: tuple[int, int, int] | str | None = None
        self._version = 0
        self._hash = ""
        self._loaded_at = 0.0
        self._last_error: str | None = None
        self.reload_if_changed()
        if not self._entries:
            raise ValueError(f"invalid initial signature feed: {self._last_error}")

    def reload_if_changed(self) -> dict[str, Any] | None:
        """Atomically replace the feed only after every entry validates."""
        with self._lock:
            try:
                stat = self.path.stat()
                stamp = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
                if stamp == self._seen:
                    return None
                self._seen = stamp
                if stat.st_size > 1_000_000:
                    raise ValueError("signature feed exceeds 1 MB")
                raw = self.path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                if digest == self._hash:
                    self._last_error = None
                    return None
                rows = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeyLoader)
                if not isinstance(rows, list) or not rows:
                    raise ValueError("signature feed must be a nonempty list")
                entries: list[_Signature] = []
                ids: set[str] = set()
                fields = {"id", "name", "category", "pattern", "direction", "severity", "owasp", "reference"}
                for row in rows:
                    if not isinstance(row, dict) or set(row) != fields:
                        raise ValueError("signature entry requires exactly: " + ", ".join(sorted(fields)))
                    if any(not isinstance(v, str) or not v.strip() for v in row.values()):
                        raise ValueError("signature fields must be nonempty strings")
                    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", row["id"]) or row["id"] in ids:
                        raise ValueError("invalid or duplicate signature id")
                    if row["direction"] not in {"input", "output", "both"}:
                        raise ValueError("invalid signature direction")
                    if row["severity"] not in {"low", "medium", "high", "critical"}:
                        raise ValueError("invalid signature severity")
                    if not re.fullmatch(r"LLM(?:0[1-9]|10)", row["owasp"]):
                        raise ValueError("invalid signature OWASP tag")
                    ids.add(row["id"])
                    entries.append(_Signature(**{**row, "pattern": _safe_regex(row["pattern"])}))
            except (OSError, ValueError, TypeError, re.error, yaml.YAMLError) as exc:
                error = short_error(exc)
                # Report a missing/unreadable file once, not on every polling tick.
                if isinstance(exc, OSError):
                    if self._seen == error:
                        return None
                    self._seen = error
                self._last_error = error
                return {"status": "rejected", "error": error, "active_version": self._version,
                        "active_hash": self._hash}
            self._entries = tuple(entries)
            self._version += 1
            self._hash = digest
            self._loaded_at = time.time()
            self._last_error = None
            return {"status": "applied", **self.info()}

    def info(self) -> dict[str, Any]:
        with self._lock:
            return {"count": len(self._entries), "version": self._version, "hash": self._hash,
                    "loaded_at": self._loaded_at, "last_error": self._last_error}

    def scan(self, views: list[View], direction: str, action: Action | str) -> list[Finding]:
        if direction not in {"input", "output", "both"}:
            raise ValueError("direction must be input, output or both")
        action = Action(action)
        with self._lock:
            entries = self._entries
        findings: list[Finding] = []
        # Prefer offset-preserving views, regardless of the caller's ordering.
        ordered = sorted(views, key=lambda v: not v.maps_to_original)
        for entry in entries:
            if direction != "both" and entry.direction not in {direction, "both"}:
                continue
            for view in ordered:
                match = entry.pattern.search(view.text)
                if match:
                    findings.append(Finding(
                        control_id=f"signatures.{entry.id}", action=action,
                        start=match.start() if view.maps_to_original else None,
                        end=match.end() if view.maps_to_original else None,
                        via=view.name, evidence=mask(match.group()[:200]), owasp=entry.owasp,
                        detail=f"{entry.name}; {entry.category}; severity={entry.severity}; {entry.reference}",
                    ))
                    break
        return findings


def scan_canary(views: list[View], tokens: list[str], action: Action | str) -> list[Finding]:
    """One masked finding per distinct token. Exact match on views that keep offsets;
    decoded and folded views are lowercased, so they are matched case-insensitively."""
    findings: list[Finding] = []
    for token in dict.fromkeys(tokens):
        if not token:
            continue
        for view in sorted(views, key=lambda v: not v.maps_to_original):
            start = (view.text.find(token) if view.maps_to_original
                     else view.text.lower().find(token.lower()))
            if start >= 0:
                findings.append(Finding(
                    "canary", Action(action), start=start if view.maps_to_original else None,
                    end=start + len(token) if view.maps_to_original else None,
                    via=view.name, evidence=mask(token), detail="Canary token disclosed", owasp="LLM07",
                ))
                break
    return findings
