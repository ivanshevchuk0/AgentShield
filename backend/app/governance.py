"""Offline tool authorization, durable single-use approvals and session loop limits."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable

from app.models import Action, Finding
from app.policy import AgentCfg, LoopCfg, Policy


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _json_value(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_json_value(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _json_value(v) for k, v in value.items())
    return False


def _canonical(args: dict[str, Any]) -> str:
    if not isinstance(args, dict) or not _json_value(args):
        raise ValueError("arguments must be a JSON object")
    return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _args_hash(args: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(args).encode()).hexdigest()


class ApprovalStore:
    """Append-only snapshots; args are stored as hashes, not as customer data.

    A single gateway owns each file. Writes precede in-memory state changes so
    a persistence failure cannot turn an undurable decision into authorization.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            with self.path.open(encoding="utf-8") as stream:
                for line in stream:
                    record = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_bad_constant)
                    required = {"id", "agent_id", "tool", "args_hash", "policy_hash", "status", "created_at", "expires_at"}
                    if not isinstance(record, dict) or not required <= record.keys():
                        raise ValueError("invalid approval journal record")
                    if record["status"] not in {"pending", "approved", "denied", "consumed", "expired"}:
                        raise ValueError("invalid approval status")
                    if not all(isinstance(record[k], str) for k in required - {"created_at", "expires_at"}):
                        raise ValueError("invalid approval journal fields")
                    for key in ("created_at", "expires_at"):
                        if isinstance(record[key], bool) or not isinstance(record[key], (int, float)) or not math.isfinite(record[key]):
                            raise ValueError("invalid approval timestamp")
                    self._records[record["id"]] = record

    def _save(self, record: dict[str, Any]) -> dict[str, Any]:
        encoded = (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self._records[record["id"]] = record
        return copy.deepcopy(record)

    def _expire(self, record: dict[str, Any]) -> dict[str, Any]:
        if record["status"] in {"pending", "approved"} and time.time() >= record["expires_at"]:
            self._save({**record, "status": "expired"})
            return self._records[record["id"]]
        return record

    def create(
        self, agent_id: str, tool: str, args: dict[str, Any], policy_hash: str, ttl_s: float,
    ) -> dict[str, Any]:
        digest = _args_hash(args)
        if isinstance(ttl_s, bool) or not math.isfinite(ttl_s) or ttl_s <= 0:
            raise ValueError("approval TTL must be positive and finite")
        now = time.time()
        with self._lock:
            return self._save({
                "id": uuid.uuid4().hex, "status": "pending", "agent_id": agent_id,
                "tool": tool, "args_hash": digest, "policy_hash": policy_hash,
                "created_at": now, "expires_at": now + ttl_s,
            })

    def decide(self, id: str, approve: bool, who: str = "dashboard") -> dict[str, Any]:
        if not isinstance(approve, bool):
            raise ValueError("approve must be boolean")
        with self._lock:
            record = self._expire(self._records[id])
            if record["status"] != "pending":
                raise ValueError("only pending, unexpired approvals can be decided")
            return self._save({**record, "status": "approved" if approve else "denied",
                               "who": who, "decided_at": time.time()})

    def consume(self, id: str, agent_id: str, tool: str, args: dict[str, Any]) -> bool:
        try:
            digest = _args_hash(args)
        except (ValueError, TypeError, RecursionError):
            return False
        with self._lock:
            record = self._records.get(id)
            if record is None:
                return False
            record = self._expire(record)
            if (record["status"] != "approved" or record["agent_id"] != agent_id
                    or record["tool"] != tool or record["args_hash"] != digest):
                return False
            self._save({**record, "status": "consumed", "consumed_at": time.time()})
            return True

    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            records = [self._expire(r) for r in tuple(self._records.values())]
            return copy.deepcopy([r for r in records if status is None or r["status"] == status])


def _finding(control: str, detail: str, action: Action = Action.BLOCK) -> Finding:
    return Finding(control, action, detail=detail, owasp="LLM06")


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_leaves(v)]
    if isinstance(value, list):
        return [s for v in value for s in _string_leaves(v)]
    return []


def check_tool_call(
    policy: Policy, agent: AgentCfg | None, tool_name: str, raw_args: str | dict[str, Any],
    approval: ApprovalStore, approval_id: str | None, policy_hash: str, *, check_approval: bool = True,
) -> tuple[dict[str, Any] | None, list[Finding]]:
    """Authorization cannot be bypassed by an approval; policy binding is checked here."""
    if agent and agent.id in policy.kill_switch:
        return None, [_finding("tools.kill_switch", "Agent is stopped by the kill switch")]
    if tool_name not in policy.tools:
        return None, [_finding("tools.unknown", "Tool is not in the policy catalog")]
    if agent is None or tool_name not in agent.allowed_tools:
        return None, [_finding("tools.allowlist", "Tool is not allowed for this agent")]
    try:
        args = json.loads(raw_args, object_pairs_hook=_unique_object, parse_constant=_bad_constant) if isinstance(raw_args, str) else raw_args
        # Roundtrip isolates caller-owned dictionaries and validates every nested value.
        args = json.loads(_canonical(args))
    except (ValueError, TypeError, RecursionError):
        return None, [_finding("tools.args", "Arguments must be a valid JSON object with unique keys and finite values")]

    tool = policy.tools[tool_name]
    findings: list[Finding] = []
    for name, pattern in tool.arg_patterns.items():
        if not isinstance(args.get(name), str) or re.fullmatch(pattern, args[name]) is None:
            findings.append(_finding("tools.arg_pattern", f"Argument {name} does not match its allowed pattern"))
    for name, pattern in tool.deny_arg_patterns.items():
        if any(re.search(pattern, value) for value in _string_leaves(args.get(name))):
            findings.append(_finding("tools.arg_pattern", f"Argument {name} matches a denied pattern"))
    for name, maximum in tool.max_values.items():
        value = args.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value > maximum:
            findings.append(_finding("tools.max_value", f"Argument {name} must be numeric and at most {maximum:g}"))
    if findings:
        return args, findings
    if tool.irreversible and check_approval:
        # consume()'s contracted signature has no policy hash; verify the immutable
        # binding first. No other decision can change a record's policy or arguments.
        matching_policy = approval_id is not None and any(
            r["id"] == approval_id and r["policy_hash"] == policy_hash for r in approval.list("approved")
        )
        if not matching_policy or not approval.consume(approval_id, agent.id, tool_name, args):
            pending = approval.create(agent.id, tool_name, args, policy_hash, policy.approval_ttl_s)
            findings.append(_finding("tools.approval", f"approval_id={pending['id']}; human approval required",
                                     Action.REQUIRE_APPROVAL))
    return args, findings


class LoopGuard:
    """Repeat counts use a sliding window; the session limit lasts for the session."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str], deque[tuple[float, str]]] = {}
        self._counts: dict[tuple[str, str], int] = {}

    def check(self, agent_id: str, session_id: str, fingerprint: str, cfg: LoopCfg) -> Finding | None:
        if not cfg.enabled:
            return None
        key = (agent_id, session_id)
        now = self.clock()
        with self._lock:
            count = self._counts.get(key, 0)
            if count >= cfg.max_requests_per_session:
                return Finding("loop.session_limit", Action(cfg.action), detail="Session request limit reached", owasp="LLM10")
            self._counts[key] = count + 1
            requests = self._requests.setdefault(key, deque())
            while requests and requests[0][0] <= now - cfg.window_seconds:
                requests.popleft()
            requests.append((now, fingerprint))
            if sum(previous == fingerprint for _, previous in requests) > cfg.max_identical:
                return Finding("loop.repeat", Action(cfg.action), detail="Identical request limit exceeded in sliding window", owasp="LLM10")
        return None
