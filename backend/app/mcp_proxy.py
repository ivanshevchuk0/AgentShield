"""Transport-independent MCP filtering with persistent, first-seen tool pins.

Callbacks are synchronous and supplied by the policy engine. ``None`` from
allowed_tools means unrestricted; an empty set means no tools. Input messages
are never mutated. Decisions are available in ``events`` for the audit adapter.
The lock is a JSON object mapping tool names to SHA-256 hashes of canonical
JSON [name, description, inputSchema]. Do not share a lock between servers.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Callable

from fastapi import Request


def _json_texts(value):
    """Decoded text surfaces, including JSON keys and numeric structured data."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _json_texts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _json_texts(child)
    elif isinstance(value, str):
        yield value
    elif type(value) in (int, float):
        yield str(value)


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

    def _scan_json(self, value, kind: str):
        """Scan decoded leaves so JSON escaping cannot conceal attack text."""
        if isinstance(value, dict):
            clean = {}
            for key, child in value.items():
                clean_key, record = self._scan_json(key, kind)
                if clean_key != key:
                    if clean_key is not None:
                        record = self._record("Cannot safely redact MCP object keys")
                        self.events.append(record)
                    return None, record
                clean_child, record = self._scan_json(child, kind)
                if clean_child is None and child is not None:
                    return None, record
                clean[key] = clean_child
            return clean, {}
        if isinstance(value, list):
            clean = []
            for child in value:
                clean_child, record = self._scan_json(child, kind)
                if clean_child is None and child is not None:
                    return None, record
                clean.append(clean_child)
            return clean, {}
        if isinstance(value, str) or type(value) in (int, float):
            text = value if isinstance(value, str) else str(value)
            clean, record = self.scan_result(text, kind)
            self.events.append(copy.deepcopy(record))
            if clean is None:
                return None, record
            if isinstance(value, str):
                return clean, record
            if clean != text:
                record = self._record("Cannot safely redact numeric MCP data")
                self.events.append(record)
                return None, record
        return value, {}

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

    def _server_error(self, request_id, record: dict) -> dict:
        self.server_denied = True
        return self._error(request_id, record)

    def handle_server_message(self, msg: dict) -> dict:
        self.server_denied = False
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
            error, record = self._scan_json(out["error"], "tool_result")
            if error is None:
                return self._server_error(msg["id"], record)
            out["error"] = error
            return out
        if method == "tools/list":
            result = out["result"]
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                return self._server_error(msg["id"], self._record("Invalid tools/list result"))
            allowlist = self.allowed_tools()
            kept = []
            changed = False
            for tool in result["tools"]:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"] or not isinstance(tool.get("description", ""), str) or not isinstance(tool.get("inputSchema"), dict):
                    self.events.append(self._record("Invalid tool definition"))
                    continue
                name = tool["name"]
                if allowlist is not None and name not in allowlist:
                    self.events.append(self._record("Tool filtered by agent allow-list", "tools.allowlist", tool=name))
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
                clean_tool, record = self._scan_json(tool, "tool_description")
                if (not isinstance(clean_tool, dict) or clean_tool.get("name") != name
                        or not isinstance(clean_tool.get("inputSchema"), dict)):
                    self.blocked_tools.add(name)
                    continue
                if name in self.blocked_tools:
                    continue
                kept.append(clean_tool)
            if changed:
                self._save_pins()
            # A later conflicting duplicate can invalidate an earlier entry in this page.
            result["tools"] = [tool for tool in kept if tool["name"] not in self.blocked_tools]
        elif method == "tools/call":
            result = out["result"]
            if not isinstance(result, dict) or not isinstance(result.get("content"), list):
                return self._server_error(msg["id"], self._record("Invalid tools/call result"))
            for item in result["content"]:
                if not isinstance(item, dict):
                    return self._server_error(msg["id"], self._record("Invalid tool content"))
                if item.get("type") == "text":
                    if not isinstance(item.get("text"), str):
                        return self._server_error(msg["id"], self._record("Invalid tool text"))
                elif item.get("type") == "resource":
                    resource = item.get("resource")
                    if (not isinstance(resource, dict) or not isinstance(resource.get("text"), str)
                            or "blob" in resource):
                        return self._server_error(msg["id"], self._record("Opaque MCP resources are unsupported"))
                else:
                    return self._server_error(msg["id"], self._record("Unsupported MCP content type"))
            clean_result, record = self._scan_json(result, "tool_result")
            if not isinstance(clean_result, dict):
                return self._server_error(msg["id"], record)
            out["result"] = clean_result
        return out


class EngineMcpGuard(McpGuard):
    """One MCP session using the gateway's identity, governance, scans and ledger."""

    def __init__(self, gateway, headers: dict, lock_path: str | Path, server: str):
        self.gateway = gateway
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.server = server
        self.calls = {}
        self.reservations = {}
        self.scans = {}
        self.contexts = {}
        self.session_lock = asyncio.Lock()
        super().__init__(self._check, lambda text, kind: self.scans[(text, kind)],
                         self._allowed, lock_path)

    def _snapshot(self):
        self.gateway.store.poll()
        self.policy, self.phash, self.pver, self.disabled = self.gateway.effective()
        self.agent, self.auth = self.gateway.authenticate(
            self.policy, self.headers.get("authorization"), self.headers.get("x-agent-id"))
        self.agent_id = self.agent.id if self.agent else None
        self.session_id = self.headers.get("x-session") or f"default:{self.agent_id}"

    def _allowed(self):
        return set(self.agent.allowed_tools) if self.agent else set()

    def _decision(self, findings, **extra):
        import uuid

        return self.gateway.build_record(
            kind="tool", request_id=uuid.uuid4().hex[:16], agent_id=self.agent_id,
            session_id=self.session_id, direction="input", findings=findings,
            policy_hash=self.phash, policy_version=self.pver, detectors_disabled=self.disabled,
            extra={"transport": "mcp", "server": self.server, **extra})

    def _check(self, name, arguments):
        from app.models import Action

        if name in self.blocked_tools or (name in self._allowed() and name not in self.pins):
            from app.models import Finding

            return False, self._decision([Finding("tools.unknown", Action.BLOCK,
                detail="MCP tool requires discovery and an unchanged trusted pin", owasp="LLM06")], tool=name)
        args, findings, approval = self.gateway.govern_tool(
            self.policy, self.phash, self.agent, name, arguments, self.session_id,
            self.headers.get("x-approval"))
        record = self._decision(findings, tool=name)
        if approval:
            record["approval_id"] = approval
        return args is not None and not any(
            f.action in (Action.BLOCK, Action.REQUIRE_APPROVAL) for f in findings), record

    def _flush(self):
        from app.models import Action, Finding

        committed = []
        for event in self.events:
            if "policy_hash" not in event:
                primary = event.get("primary") or {}
                findings = [Finding(primary.get("control_id", "tools.args"),
                                    Action(event.get("action", "block")),
                                    detail=event.get("summary", "MCP operation blocked"), owasp="LLM06")]
                event = self._decision(findings, **{k: v for k, v in event.items()
                                                  if k in ("event", "tool", "expected", "observed")})
            committed.append(self.gateway.commit(event))
        self.events.clear()
        return committed

    async def handle_client_message(self, msg):
        async with self.session_lock:
            forward, reply = await self._client_message(msg)
            if forward is not None and "id" in forward:
                self.contexts[forward["id"]] = (self.policy, self.phash, self.pver, self.disabled, self.agent,
                                                 self.agent_id, self.session_id)
            return forward, reply

    async def _client_message(self, msg):
        import time
        from app.budget import estimate_tokens
        from app.models import Action, Finding
        from app.policy import ModelCfg

        self._snapshot()
        finding = self.auth
        if finding is None and self.agent_id in self.policy.kill_switch:
            finding = Finding("tools.kill_switch", Action.BLOCK, detail="Agent is kill-switched", owasp="LLM06")
        if finding:
            record = self.gateway.commit(self._decision([finding]))
            return None, self._error(msg.get("id") if isinstance(msg, dict) else None, record)
        if isinstance(msg, dict) and msg.get("method") not in (
            "initialize", "ping", "tools/list", "tools/call", "notifications/initialized"
        ):
            record = self.gateway.commit(self._decision([
                Finding("tools.unknown", Action.BLOCK, detail="Unsupported MCP method", owasp="LLM06")]))
            return None, self._error(msg.get("id"), record)
        # Admission precedes governance: a budget denial must not consume an approval.
        if (not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not self._valid_id(msg.get("id"))
                or "result" in msg or "error" in msg or ("id" in msg and msg["id"] in self.pending)):
            record = self.gateway.commit(self._decision([Finding(
                "tools.args", Action.BLOCK, detail="Invalid JSON-RPC request", owasp="LLM06")]))
            return None, self._error(None, record, -32600)
        if "id" not in msg:
            if msg["method"] in ("tools/call", "tools/list"):
                self.gateway.commit(self._decision([Finding(
                    "tools.args", Action.BLOCK, detail="MCP tool operations require an id", owasp="LLM06")]))
                return None, None
            return super().handle_client_message(msg)
        request_id = msg["id"]
        size = len(json.dumps(msg, ensure_ascii=False))
        if size > self.policy.max_input_chars:
            findings = [Finding("limits.input_size", Action.BLOCK, detail="MCP request exceeds input limit", owasp="LLM10")]
            reservation = None
        else:
            # MCP has no model-token price. Charge RPM/TPM and actual compute, not invented USD.
            model = ModelCfg(upstream="mock")
            reservation, findings = self.gateway.ledger.reserve(
                self.agent_id or "anonymous", self.policy.budget_for(self.agent), model,
                estimate_tokens(json.dumps(msg)), 0)
        if reservation is None:
            self.pending.pop(request_id, None)
            record = self.gateway.commit(self._decision(findings))
            return None, self._error(request_id, record)
        if findings:
            self.gateway.commit(self._decision(findings))
        forward, reply = super().handle_client_message(msg)
        records = self._flush()
        if forward is None:
            self.gateway.ledger.release(reservation)
            if reply is not None:
                if not records:
                    self.events.append(reply["error"]["data"])
                    records = self._flush()
                reply["error"]["data"] = records[-1]
            return forward, reply
        self.reservations[request_id] = (reservation, time.perf_counter())
        if forward["method"] == "tools/call":
            self.calls[request_id] = forward["params"]["name"]
        return forward, reply

    async def handle_server_message(self, msg):
        async with self.session_lock:
            request_id = msg.get("id") if isinstance(msg, dict) else None
            if (not isinstance(msg, dict) or "method" in msg or not self._valid_id(request_id)
                    or request_id not in self.contexts):
                raise ValueError("unsolicited MCP server message")
            (self.policy, self.phash, self.pver, self.disabled, self.agent,
             self.agent_id, self.session_id) = self.contexts.pop(request_id)
            return await self._server_message(msg)

    async def _server_message(self, msg):
        import time
        from app.budget import estimate_tokens
        from app.flow import sign_call_id
        from app.models import Action, Context
        from app.policy import ModelCfg

        request_id = msg.get("id") if isinstance(msg, dict) else None
        method = self.pending.get(request_id) if "method" not in msg else None
        name = self.calls.get(request_id)
        self.scans.clear()
        result = msg.get("result", {})
        texts = []
        if method == "tools/list" and isinstance(result, dict) and isinstance(result.get("tools"), list):
            # Scan only entries that the base guard will inspect (valid, allowed, unchanged).
            for tool in result["tools"]:
                if not isinstance(tool, dict) or tool.get("name") not in self._allowed():
                    continue
                description = tool.get("description", "")
                schema = tool.get("inputSchema")
                if not isinstance(description, str) or not isinstance(schema, dict):
                    continue
                pin = hashlib.sha256(json.dumps([tool["name"], description, schema], sort_keys=True,
                    separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
                if tool["name"] in self.pins and self.pins[tool["name"]] != pin:
                    continue
                texts.extend((text, "tool_description", tool["name"]) for text in _json_texts(tool))
        elif method == "tools/call" and isinstance(result, dict) and isinstance(result.get("content"), list):
            texts = [(text, "tool_result", name) for text in _json_texts(result)]
        if "error" in msg:
            texts.extend((text, "tool_result", name) for text in _json_texts(msg["error"]))
        for text, kind, tool_name in texts:
            if (text, kind) in self.scans:
                continue
            if kind == "tool_result":
                cfg = self.policy.tools.get(tool_name)
                self.gateway.taint.add(self.gateway.flow_key(self.agent_id), tool_name, list(cfg.labels) if cfg else ["untrusted"], text)
            ctx = Context(request_id=str(request_id), agent_id=self.agent_id, session_id=self.session_id,
                          policy_hash=self.phash, policy_version=self.pver, source="tool", tool_name=tool_name)
            decision = await self.gateway.inspect(text, ctx, self.policy)
            record = self._decision(decision.findings, tool=tool_name, event=kind)
            record["judge"] = decision.judge
            record["timings_ms"] = decision.timings_ms
            # No raw text is copied into the audit record.
            self.scans[(text, kind)] = (None if decision.action == Action.BLOCK else decision.text, record)
        out = super().handle_server_message(msg)
        records = self._flush()
        if self.server_denied and "error" in out and "data" in out["error"]:
            if "policy_hash" not in out["error"]["data"]:
                self.events.append(out["error"]["data"])
                records.extend(self._flush())
            out["error"]["data"] = records[-1]
        entry = self.reservations.pop(request_id, None) if method else None
        if entry:
            reservation, started = entry
            compute = time.perf_counter() - started
            self.gateway.ledger.settle(reservation, reservation.tokens,
                                       estimate_tokens(json.dumps(msg)), compute, ModelCfg(upstream="mock"))
            self.gateway.commit(self._decision([], event="settled", compute_s=compute))
        if name and method == "tools/call":
            self.calls.pop(request_id, None)
            if "result" in out:
                out["result"]["call_id"] = sign_call_id(str(request_id), name, self.session_id, self.gateway.call_key)
        return out

    def close(self):
        """Refund incomplete operations, retaining admitted RPM charges."""
        for reservation, _ in self.reservations.values():
            self.gateway.ledger.release(reservation)
        self.reservations.clear()
        self.contexts.clear()
        self.pending.clear()


def register(app, gateway):
    """Mount buffered JSON-over-HTTP MCP servers selected only from policy."""
    import asyncio
    import httpx
    from fastapi.responses import JSONResponse
    from app.models import Action, Finding

    locks = {}

    @app.post("/mcp/{server}")
    async def mcp(server: str, request: Request):
        from app.mcp_stdio import _decode

        policy, _, _, _ = gateway.effective()
        config = policy.mcp_servers.get(server)
        if config is None or not config.url or not config.url.startswith(("http://", "https://")):
            return JSONResponse({"error": "Unknown HTTP MCP server"}, status_code=404)
        try:
            body = await request.body()
            if len(body) > 1024 * 1024:
                raise ValueError("oversized MCP request")
            msg = _decode(body)
            if not isinstance(msg, dict):
                raise ValueError("JSON-RPC object required")
        except (ValueError, UnicodeError):
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)
        # One pin writer per server; guards/approvals remain bound to the calling identity.
        async with locks.setdefault(server, asyncio.Lock()):
            pin_name = hashlib.sha256(server.encode()).hexdigest() + ".lock"
            guard = None
            try:
                guard = EngineMcpGuard(gateway, dict(request.headers), gateway.data_dir / "mcp" / pin_name, server)
                async with httpx.AsyncClient(transport=gateway.transport, timeout=10, follow_redirects=False) as client:
                    async def exchange(message):
                        forward, reply = await guard.handle_client_message(message)
                        if forward is None:
                            return reply
                        upstream = await client.post(config.url, json=forward)
                        upstream.raise_for_status()
                        return await guard.handle_server_message(_decode(upstream.content))

                    # Re-list before every call: a changed description cannot bypass pinning
                    # by calling directly without asking for the catalog first.
                    if msg.get("method") == "tools/call":
                        listing = await exchange({"jsonrpc": "2.0", "id": "agentshield-preflight", "method": "tools/list"})
                        if listing and "error" in listing:
                            listing["id"] = msg.get("id")
                            return JSONResponse(listing)
                        params = msg.get("params", {})
                        name = params.get("name") if isinstance(params, dict) else None
                        # A policy entry is not proof that this server actually advertised the tool.
                        if name in guard._allowed() and name not in {t["name"] for t in listing["result"]["tools"]}:
                            record = gateway.commit(guard._decision([Finding(
                                "tools.unknown", Action.BLOCK, detail="MCP tool absent or withheld from listing", owasp="LLM06")], tool=name))
                            return JSONResponse(guard._error(msg.get("id"), record))
                    out = await exchange(msg)
                    return JSONResponse(out) if out is not None else JSONResponse(None, status_code=202)
            except (OSError, httpx.HTTPError, ValueError, KeyError, TypeError):
                if guard is None:
                    # Keep a corrupt pin file intact; never silently trust a new baseline.
                    agent, _ = gateway.authenticate(policy, request.headers.get("authorization"), request.headers.get("x-agent-id"))
                    _, phash, pver, disabled = gateway.effective()
                    record = gateway.commit(gateway.build_record(
                        kind="tool", request_id=server, agent_id=agent.id if agent else None,
                        session_id=request.headers.get("x-session"), direction="input",
                        findings=[Finding("tools.unknown", Action.BLOCK, detail="MCP pin validation failed", owasp="LLM06")],
                        policy_hash=phash, policy_version=pver, detectors_disabled=disabled,
                        extra={"transport": "mcp", "server": server}))
                    return JSONResponse(McpGuard._error(msg.get("id"), record), status_code=502)
                guard._snapshot()
                record = gateway.commit(guard._decision([Finding(
                    "tools.args", Action.BLOCK, detail="Invalid or unavailable MCP server response", owasp="LLM06")]))
                return JSONResponse(guard._error(msg.get("id") if isinstance(msg, dict) else None, record), status_code=502)
            finally:
                if guard is not None:
                    guard.close()
