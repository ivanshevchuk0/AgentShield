"""Transport-independent MCP filtering with persistent, first-seen tool pins.

Callbacks are synchronous and supplied by the policy engine. ``None`` from
allowed_tools means unrestricted; an empty set means no tools. Input messages
are never mutated. Decisions are available in ``events`` for the audit adapter.
The lock is a JSON object mapping tool names to SHA-256 hashes of canonical
JSON [name, description, inputSchema]. Do not share a lock between servers.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Callable


class McpGuard:
    def __init__(
        self,
        check_call: Callable[[str, dict], tuple[bool, dict]],
        scan_result: Callable[[str, str], tuple[str | None, dict]],
        allowed_tools: Callable[[], set[str] | None],
        lock_path: str | Path,
    ):
        self.check_call = check_call
        self.scan_result = scan_result
        self.allowed_tools = allowed_tools
        self.lock_path = Path(lock_path)
        self.pending: dict[str | int | float | None, str] = {}
        self.events: list[dict] = []
        self.blocked_tools: set[str] = set()
        # A corrupt lock must not silently reset the trusted baseline.
        self.pins = json.loads(self.lock_path.read_text(encoding="utf-8")) if self.lock_path.exists() else {}
        if not isinstance(self.pins, dict) or any(
            not isinstance(name, str) or not isinstance(pin, str)
            or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin)
            for name, pin in self.pins.items()
        ):
            raise ValueError("invalid MCP tools lock")

    @staticmethod
    def _record(summary: str, control_id: str = "tools.args", **extra) -> dict:
        return {"kind": "tool", "action": "block", "summary": summary,
                "primary": {"control_id": control_id, "owasp": "LLM06"}, **extra}

    @staticmethod
    def _error(request_id, record: dict, code: int = -32001) -> dict:
        return {"jsonrpc": "2.0", "id": request_id, "error": {
            "code": code, "message": record.get("summary") or record.get("message") or "MCP operation blocked",
            "data": record,
        }}

    @staticmethod
    def _valid_id(value) -> bool:
        return value is None or type(value) in (str, int) or (type(value) is float and math.isfinite(value))

    def _save_pins(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replacement: an interrupted write must not lose the baseline.
        fd, tmp = tempfile.mkstemp(dir=self.lock_path.parent, prefix=self.lock_path.name + ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.pins, stream, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.lock_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def handle_client_message(self, msg: dict) -> tuple[dict | None, dict | None]:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not self._valid_id(msg.get("id")):
            return None, self._error(None, self._record("Invalid JSON-RPC message"), -32600)
        if "method" not in msg:  # Client response to a server-initiated request.
            if "id" in msg and (("result" in msg) != ("error" in msg)):
                return copy.deepcopy(msg), None
            return None, self._error(msg.get("id"), self._record("Invalid JSON-RPC response"), -32600)
        if not isinstance(msg["method"], str) or "result" in msg or "error" in msg:
            return None, self._error(msg.get("id"), self._record("Invalid JSON-RPC request"), -32600)
        if "id" in msg and msg["id"] in self.pending:
            return None, self._error(msg["id"], self._record("Request id already pending"), -32600)
        if msg["method"] == "tools/call":
            params = msg.get("params", {})
            if not isinstance(params, dict) or not isinstance(params.get("name"), str) or not params["name"] or not isinstance(params.get("arguments", {}), dict):
                record = self._record("Tool name and object arguments are required")
                allowed = False
            else:
                name = params["name"]
                allowed, record = self.check_call(name, copy.deepcopy(params.get("arguments", {})))
                allowlist = self.allowed_tools()
                if allowed and (name in self.blocked_tools or (allowlist is not None and name not in allowlist)):
                    allowed = False
                    record = self._record("Tool is not available to this agent", "tools.allowlist", tool=name)
            self.events.append(copy.deepcopy(record))
            if not allowed:
                # JSON-RPC notifications never receive responses, even on denial.
                return None, self._error(msg["id"], record) if "id" in msg else None
        if "id" in msg:
            self.pending[msg["id"]] = msg["method"]
        return copy.deepcopy(msg), None

    def handle_server_message(self, msg: dict) -> dict:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not self._valid_id(msg.get("id")):
            raise ValueError("invalid server JSON-RPC message")
        if "method" in msg:  # Notifications / server requests must not consume client ids.
            if not isinstance(msg["method"], str) or "result" in msg or "error" in msg:
                raise ValueError("invalid server JSON-RPC request")
            return copy.deepcopy(msg)
        if "id" not in msg or (("result" in msg) == ("error" in msg)):
            raise ValueError("invalid server JSON-RPC response")
        method = self.pending.pop(msg["id"], None)
        out = copy.deepcopy(msg)
        if "error" in msg:
            return out
        if method == "tools/list":
            result = out["result"]
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                return self._error(msg["id"], self._record("Invalid tools/list result"))
            allowlist = self.allowed_tools()
            kept = []
            changed = False
            for tool in result["tools"]:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"] or not isinstance(tool.get("description", ""), str) or not isinstance(tool.get("inputSchema"), dict):
                    self.events.append(self._record("Invalid tool definition"))
                    continue
                name = tool["name"]
                if allowlist is not None and name not in allowlist:
                    continue
                canonical = json.dumps([name, tool.get("description", ""), tool["inputSchema"]],
                                       sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
                pin = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if name in self.pins and self.pins[name] != pin:
                    self.blocked_tools.add(name)
                    self.events.append(self._record("MCP tool description or schema changed", "tools.unknown",
                                                    event="rug_pull", tool=name, expected=self.pins[name], observed=pin))
                    continue
                if name not in self.pins:
                    self.pins[name] = pin
                    changed = True
                description, record = self.scan_result(tool.get("description", ""), "tool_description")
                self.events.append(copy.deepcopy(record))
                if description is None:
                    self.blocked_tools.add(name)
                    continue
                if name in self.blocked_tools:
                    continue
                if "description" in tool or description:
                    tool["description"] = description
                kept.append(tool)
            if changed:
                self._save_pins()
            # A later conflicting duplicate can invalidate an earlier entry in this page.
            result["tools"] = [tool for tool in kept if tool["name"] not in self.blocked_tools]
        elif method == "tools/call":
            result = out["result"]
            if not isinstance(result, dict) or not isinstance(result.get("content"), list):
                return self._error(msg["id"], self._record("Invalid tools/call result"))
            for item in result["content"]:
                if not isinstance(item, dict):
                    return self._error(msg["id"], self._record("Invalid tool content"))
                if item.get("type") == "text":
                    if not isinstance(item.get("text"), str):
                        return self._error(msg["id"], self._record("Invalid tool text"))
                    text, record = self.scan_result(item["text"], "tool_result")
                    self.events.append(copy.deepcopy(record))
                    if text is None:
                        return self._error(msg["id"], record)
                    item["text"] = text
        return out
