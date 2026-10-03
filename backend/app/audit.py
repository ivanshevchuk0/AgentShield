"""Durable single-writer HMAC audit chain with a tail-truncation checkpoint."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(text: str) -> dict[str, Any]:
    result = json.loads(text, object_pairs_hook=_unique)
    if not isinstance(result, dict):
        raise ValueError("audit entry must be an object")
    return result


def _md(value: Any) -> str:
    return html.escape(str(value)).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


class AuditLog:
    """One writer instance per directory; restart refuses corrupt or incomplete chains.

    Keep audit.head separately trusted: removing/replacing both log and checkpoint cannot
    be detected without an external checkpoint. External fixtures may omit a head file.
    """

    def __init__(self, directory: str | Path, key: bytes):
        if not isinstance(key, bytes) or not key:
            raise ValueError("a nonempty bytes HMAC key is required")
        self.directory = Path(directory)
        self.path = self.directory / "audit.jsonl"
        self.head_path = self.directory / "audit.head"
        self._key = key
        self._lock = threading.RLock()
        self._failed = False
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() and not self.head_path.exists():
            with self.path.open("x", encoding="utf-8") as stream:
                stream.flush()
                os.fsync(stream.fileno())
            self._write_head(_GENESIS, 0)
        verified = self.verify()
        if not verified["ok"]:
            raise ValueError(f"invalid audit chain: {verified['reason']} at {verified['broken_at']}")
        head = _load(self.head_path.read_text(encoding="utf-8"))
        self._hash, self._count = head["hash"], head["count"]

    def _digest(self, record: dict[str, Any]) -> str:
        body = {key: value for key, value in record.items() if key != "hash"}
        return hmac.new(
            self._key, (body["prev"] + _canonical(body)).encode("utf-8"), hashlib.sha256,
        ).hexdigest()

    def _write_head(self, digest: str, count: int) -> None:
        fd, name = tempfile.mkstemp(prefix=".audit-head-", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(_canonical({"hash": digest, "count": count}) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.head_path)
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._failed:
                raise RuntimeError("audit write failed; verify and reopen before appending")
            # JSON round trip both validates and detaches nested mutable caller data.
            entry = _load(_canonical(record))
            entry.update(seq=self._count + 1, ts=time.time(), prev=self._hash)
            entry.pop("hash", None)
            entry["hash"] = self._digest(entry)
            line = _canonical(entry) + "\n"
            try:
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(line)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._write_head(entry["hash"], entry["seq"])
            except OSError:
                self._failed = True
                raise
            self._hash, self._count = entry["hash"], entry["seq"]
            return entry

    def verify(self, path: str | Path | None = None) -> dict[str, Any]:
        """Return valid-prefix count and first broken 1-based sequence; never repair evidence."""
        target = self.path if path is None else Path(path)
        head_path = target.with_suffix(".head")
        require_head = target.resolve() == self.path.resolve()
        with self._lock:
            count, previous = 0, _GENESIS

            def failure(reason: str) -> dict[str, Any]:
                return {"ok": False, "count": count, "broken_at": count + 1, "reason": reason}

            try:
                with target.open("r", encoding="utf-8") as stream:
                    for line in stream:
                        if not line.endswith("\n"):
                            return failure("incomplete audit line")
                        record = _load(line)
                        if type(record.get("seq")) is not int or record["seq"] != count + 1:
                            return failure("sequence mismatch")
                        if record.get("prev") != previous:
                            return failure("previous hash mismatch")
                        digest = record.get("hash")
                        if not isinstance(digest, str) or not hmac.compare_digest(digest, self._digest(record)):
                            return failure("HMAC mismatch")
                        if line != _canonical(record) + "\n":
                            return failure("noncanonical audit line (bytes changed)")
                        previous, count = digest, count + 1
                if head_path.exists():
                    head = _load(head_path.read_text(encoding="utf-8"))
                    if type(head.get("count")) is not int or head["count"] != count:
                        return failure("head count mismatch (possible tail truncation)")
                    if head.get("hash") != previous:
                        return failure("head hash mismatch")
                elif require_head:
                    return failure("missing audit head")
            except (OSError, ValueError, TypeError, KeyError) as exc:
                return failure(f"unreadable audit: {exc}")
            return {"ok": True, "count": count, "broken_at": None, "reason": "ok"}

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            with self.path.open("r", encoding="utf-8") as stream:
                return [_load(line) for line in stream]

    def tail(self, n: int = 50, **filters: Any) -> list[dict[str, Any]]:
        if n < 0:
            raise ValueError("tail size must be nonnegative")
        records = [record for record in self.all()
                   if all(record.get(key) == value for key, value in filters.items())]
        return records[-n:] if n else []

    def page(self, limit: int, after_seq: int | None = None, **filters: Any) -> list[dict[str, Any]]:
        """Filtered records in ascending seq order, each guaranteed an integer ``seq``.

        Without ``after_seq``: the newest ``limit`` matches (a tail). With it: the oldest
        ``limit`` matches whose seq > after_seq, so a client can page forward without gaps.
        """
        if limit < 1:
            raise ValueError("page size must be positive")
        records = []
        for line_no, record in enumerate(self.all(), start=1):
            if type(record.get("seq")) is not int:
                record["seq"] = line_no
            if after_seq is not None and record["seq"] <= after_seq:
                continue
            if all(record.get(key) == value for key, value in filters.items()):
                records.append(record)
        return records[:limit] if after_seq is not None else records[-limit:]

    def tamper_drill(self, scratch_dir: str | Path, seq: int | None = None) -> dict[str, Any]:
        """Edit one record in a scratch copy of the live chain and verify the copy.

        The live log and head are copied under the writer lock (so they agree), the copy is
        edited and verified, then deleted; ``audit.jsonl`` itself is never written. Raises
        LookupError for an empty log and IndexError for a seq outside 1..count.
        """
        with self._lock:
            original_ok = bool(self.verify()["ok"])
            lines = self.path.read_text(encoding="utf-8").splitlines(keepends=True)
            head = self.head_path.read_bytes() if self.head_path.exists() else None
        if not lines:
            raise LookupError("audit log is empty: nothing to tamper with")
        target = len(lines) if seq is None else seq
        if not 1 <= target <= len(lines):
            raise IndexError(f"no audit record with seq {target} (log has {len(lines)})")
        record = _load(lines[target - 1])
        if isinstance(record.get("action"), str):
            field = "action"
            before, after = record["action"], "block" if record["action"] == "allow" else "allow"
        else:
            field = "summary"
            before = record.get("summary")
            after = f"{before or ''} (edited)"
        record[field] = after   # attacker rewrites the field and keeps the old hash
        lines[target - 1] = _canonical(record) + "\n"
        scratch = Path(scratch_dir)
        scratch.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="drill-", dir=scratch))
        try:
            drill_log = work / "audit.jsonl"
            drill_log.write_text("".join(lines), encoding="utf-8")
            if head is not None:
                drill_log.with_suffix(".head").write_bytes(head)
            result = self.verify(drill_log)
        finally:
            for leftover in work.iterdir():
                leftover.unlink()
            work.rmdir()
        return {"ok": result["ok"], "broken_at": result["broken_at"], "reason": result["reason"],
                "seq": target, "field": field, "before": before, "after": after,
                "original_ok": original_ok, "records": len(lines)}

    def report_md(self, snapshot: dict[str, Any]) -> str:
        with self._lock:
            chain = self.verify()
            try:
                records = self.all()
            except (OSError, ValueError):
                records = []
        counts = Counter(record.get("action", "unknown") for record in records
                         if record.get("kind") not in {"policy", "approval", "kill", "flow_state"})
        policy, posture = snapshot.get("policy", {}), snapshot.get("posture", {})
        lines = [
            "# AgentShield security report", "", "## Summary",
            f"- Audit records: {len(records)}",
            f"- Requests: {sum(counts.values())}",
            f"- Policy: {_md(policy.get('version', 'unknown'))} / {_md(policy.get('hash', 'unknown'))}",
            f"- Profile: {_md(policy.get('profile', 'unknown'))}; mode: {_md(policy.get('mode', 'unknown'))}",
            "", "## Posture", f"- Score: {_md(posture.get('score', 'unknown'))}",
        ]
        gaps = posture.get("gaps", [])
        lines.extend(f"- Gap: {_md(gap)}" for gap in gaps)
        if not gaps:
            lines.append("- No reported gaps.")
        lines += ["", "## Counts", "| Action | Count |", "|---|---:|"]
        lines.extend(f"| {_md(action)} | {count} |" for action, count in sorted(counts.items()))
        lines += ["", "## Top blocks (with why)", "| Seq | Agent | Control | Why |", "|---:|---|---|---|"]
        blocks = [record for record in records if record.get("action") == "block"]
        for record in blocks[-20:]:
            primary = record.get("primary") or {}
            why = primary.get("detail") or record.get("summary", "")
            lines.append(f"| {record['seq']} | {_md(record.get('agent_id', ''))} | "
                         f"{_md(primary.get('control_id', 'unknown'))} | {_md(why)} |")
        if not blocks:
            lines.append("No blocks recorded.")
        lines += ["", "## Policy changes"]
        changes = [record for record in records if record.get("kind") == "policy"]
        for record in changes[-20:]:
            description = record.get("summary") or record.get("changed") or record.get("status", "policy event")
            lines.append(f"- #{record['seq']}: {_md(description)}")
        if not changes:
            lines.append("No policy changes recorded.")
        lines += ["", "## Chain status", f"- {'OK' if chain['ok'] else 'BROKEN'}: {chain['count']} verified records."]
        if not chain["ok"]:
            lines.append(f"- Broken at #{chain['broken_at']}: {_md(chain['reason'])}")
        return "\n".join(lines) + "\n"
