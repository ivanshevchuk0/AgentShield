"""FastAPI app: OpenAI-compatible gateway + dashboard API. All decisions live in engine.Gateway."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.engine import BACKEND_DIR, Gateway, GatewayResult
from app.policy import PolicyStore

REPO_DIR = BACKEND_DIR.parent
APP_DIR = REPO_DIR / "frontend" / "app"   # the new UI, served at /app/
POLL_INTERVAL_S = 0.5
EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT = 200, 1000
POLICY_HISTORY_LIMIT = 50

APP_SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
    "X-Content-Type-Options": "nosniff",
}


class SecurityHeaders:
    """ASGI wrapper that sets fixed security headers on every response of the wrapped app."""

    def __init__(self, app: ASGIApp, headers: dict[str, str]):
        self.app = app
        self.headers = headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                for name, value in self.headers.items():
                    response_headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


class UIStaticFiles(StaticFiles):
    """StaticFiles that answers errors itself (so SecurityHeaders covers them too) and serves 404
    rather than crashing while the UI directory does not exist yet."""

    async def check_config(self) -> None:
        if self.directory is not None and not os.path.isdir(self.directory):
            raise StarletteHTTPException(404)   # re-checked on every request until the UI appears
        await super().check_config()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        except StarletteHTTPException as exc:   # raised before any response was started
            await PlainTextResponse(exc.detail, status_code=exc.status_code, headers=exc.headers)(
                scope, receive, send)


def _policy_result(store: PolicyStore, entry: dict | None, changed: list[str] | None = None) -> tuple[int, dict]:
    entry = entry or {"status": "unchanged"}
    status = entry.get("status", "unchanged")
    body = {
        "status": status,
        "error": entry.get("error"),
        "version": store.version,
        "hash": store.hash,
        "changed": changed if changed is not None else entry.get("changed", []),
    }
    if status == "rejected":
        body["rejected_hash"] = entry.get("hash")
    return (400 if status == "rejected" else 200), body


def _sse(response: dict) -> StreamingResponse:
    """stream:true is buffered + inspected in full, then re-emitted as SSE chunks."""
    try:
        from app.sse import completion_to_sse_chunks  # shared helper (parallel module)

        chunks = list(completion_to_sse_chunks(response))

        def gen_mod():
            for c in chunks:
                if isinstance(c, (bytes, str)):
                    yield c
                else:
                    yield "data: " + json.dumps(c) + "\n\n"
            if not any(isinstance(c, str) and "[DONE]" in c for c in chunks):
                yield "data: [DONE]\n\n"

        return StreamingResponse(gen_mod(), media_type="text/event-stream")
    except Exception:  # noqa: BLE001 - fall back to the inline encoder
        pass

    def gen():
        base = {"id": response.get("id", "chatcmpl"), "object": "chat.completion.chunk",
                "created": response.get("created", int(time.time())), "model": response.get("model")}
        for ch in response.get("choices") or []:
            msg = ch.get("message") or {}
            delta: dict[str, Any] = {"role": "assistant"}
            if msg.get("content") is not None:
                delta["content"] = msg["content"]
            if msg.get("tool_calls"):
                delta["tool_calls"] = [{"index": i, **tc} for i, tc in enumerate(msg["tool_calls"])]
            yield "data: " + json.dumps({**base, "choices": [{"index": ch.get("index", 0), "delta": delta,
                                                              "finish_reason": None}]}) + "\n\n"
            yield "data: " + json.dumps({**base, "choices": [{"index": ch.get("index", 0), "delta": {},
                                                              "finish_reason": ch.get("finish_reason", "stop")}],
                                         "agentshield": response.get("agentshield")}) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


def _to_response(res: GatewayResult):
    if res.stream and res.status == 200:
        r = _sse(res.body)
        r.headers.update(res.headers)
        return r
    return JSONResponse(res.body, status_code=res.status, headers=res.headers)


EXTENSIONS = ("app.mcp_proxy", "app.anthropic_adapter")


def mount_extensions(app: FastAPI, gw: Gateway) -> list[str]:
    """Extension point: /mcp/{server} (mcp_proxy) and /v1/messages (anthropic_adapter).
    A module that defines `register(app, gateway)` is mounted automatically; missing modules are skipped."""
    mounted = []
    for name in EXTENSIONS:
        try:
            mod = __import__(name, fromlist=["register"])
        except Exception:  # noqa: BLE001
            continue
        reg = getattr(mod, "register", None)
        if callable(reg):
            try:
                reg(app, gw)
                mounted.append(name)
            except Exception:  # noqa: BLE001
                continue
    app.state.extensions = mounted
    return mounted


def create_app(policy_path=None, data_dir=None, transport=None, judge_transport=None) -> FastAPI:
    policy_path = Path(policy_path or os.environ.get("AGENTSHIELD_POLICY") or BACKEND_DIR / "policy.yaml")
    data_dir = Path(data_dir or os.environ.get("AGENTSHIELD_DATA_DIR") or "data")
    store = PolicyStore(policy_path)
    gw = Gateway(store, data_dir, transport=transport, judge_transport=judge_transport)
    admin_token = os.environ.get("AGENTSHIELD_ADMIN_TOKEN")  # optional; dashboard demo runs without it

    async def poller():
        while True:
            await asyncio.sleep(POLL_INTERVAL_S)
            try:
                store.poll()
                if store._pending_since is not None:  # change seen: apply after the debounce, not next tick
                    await asyncio.sleep(0.2)
                    store.poll()
            except Exception:  # noqa: BLE001 - the watcher must never die
                pass
            try:
                gw.poll_feed()
            except Exception:  # noqa: BLE001
                pass

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(poller())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    app = FastAPI(title="AgentShield", version="1.0", lifespan=lifespan)
    app.state.gateway = gw
    app.state.store = store

    def admin(request: Request) -> None:
        if admin_token and not hmac.compare_digest(request.headers.get("x-admin-token", ""), admin_token):
            raise HTTPException(401, "admin token required")

    async def json_body(request: Request) -> dict:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "body must be JSON") from None
        if not isinstance(body, dict):
            raise HTTPException(400, "body must be a JSON object")
        return body

    # ---------------------------------------------------------------- agent-facing API
    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        body = await json_body(request)
        return _to_response(await gw.chat(body, dict(request.headers)))

    @app.get("/v1/models")
    async def models(request: Request):
        policy, _, _, _ = gw.effective()
        agent, _ = gw.authenticate(policy, request.headers.get("authorization"), None)
        names = [m for m in policy.models if policy.model_allowed(agent, m)]
        return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "agentshield",
                                            "upstream": policy.models[m].upstream} for m in names]}

    @app.post("/v1/tools/call")
    async def tools_call(request: Request):
        body = await json_body(request)
        return _to_response(await gw.tool_call(body, dict(request.headers)))

    # ---------------------------------------------------------------- dashboard API
    @app.post("/api/try")
    async def try_it(request: Request):
        body = await json_body(request)
        return await gw.try_text(body.get("agent_key"), str(body.get("text") or ""),
                                 str(body.get("direction") or "input"))

    @app.get("/api/snapshot")
    async def snapshot():
        """Dashboard state (CONTRACTS.md "GET /api/snapshot") plus, for the /app UI:

        - coverage: [{framework: "OWASP LLM 2025", id: "LLM01".."LLM10", title: str,
          controls: [posture control id], status: "covered" | "partial" | "gap"}], ordered LLM01..LLM10,
          computed on the effective policy (dashboard overrides included); [] if posture is unavailable.
        - upstream_calls: int, model calls actually attempted since start (blocked requests never count).
        - server_time: float, epoch seconds when the snapshot was built (client clock-skew correction).
        - judge gains breaker_open: bool (true only while calls are refused), open_until: float | null
          (epoch seconds when the breaker turns half-open), calls: int, failures: int (consecutive).
        """
        return gw.snapshot()

    @app.get("/api/events")
    async def events(limit: int = EVENTS_DEFAULT_LIMIT, after_seq: int | None = None,
                     action: str | None = None, kind: str | None = None, agent_id: str | None = None):
        """Decision records, ascending by integer seq; limit is clamped to 1..1000 (default 200).

        Without after_seq: the newest `limit` matching records. With after_seq=N: the oldest `limit`
        matching records with seq > N (lossless cursor: pass the last seq you received).
        """
        filters = {k: v for k, v in {"action": action, "kind": kind, "agent_id": agent_id}.items() if v}
        return gw.audit.page(max(1, min(limit, EVENTS_MAX_LIMIT)), after_seq, **filters)

    @app.get("/api/policy/history")
    async def policy_history():
        """Last 50 PolicyStore events, oldest first: [{status: "applied" | "rejected", version: int,
        hash: str, changed: [str], error: str | null, ts: float}]. version is the policy version in
        force after the event (for a rejected edit: the version still enforced); hash is the hash of
        the text that was applied or rejected."""
        out = []
        for entry in list(store.history)[-POLICY_HISTORY_LIMIT:]:
            version = entry.get("version", entry.get("active_version"))
            out.append({"status": entry.get("status"), "version": version, "hash": entry.get("hash"),
                        "changed": list(entry.get("changed") or []), "error": entry.get("error"),
                        "ts": entry.get("ts")})
        return out

    @app.get("/api/policy/raw")
    async def policy_raw():
        return PlainTextResponse(store.text(), headers={"X-Policy-Hash": store.hash,
                                                        "X-Policy-Version": str(store.version)})

    @app.post("/api/policy")
    async def policy_update(request: Request):
        admin(request)
        body = await json_body(request)
        text = body.get("yaml")
        if not isinstance(text, str):
            raise HTTPException(400, "body must be {\"yaml\": \"...\"}")
        code, out = _policy_result(store, store.apply_text(text))
        return JSONResponse(out, status_code=code)

    @app.post("/api/policy/profile/{name}")
    async def policy_profile(name: str, request: Request):
        admin(request)
        code, out = _policy_result(store, store.set_profile(name))
        return JSONResponse(out, status_code=code)

    def _override_result(changed: list[str]) -> dict:
        view = gw.overrides_view()
        return {"status": "applied", "error": None, "version": store.version, "hash": store.hash,
                "changed": changed, **view}

    @app.post("/api/policy/toggle")
    async def policy_toggle(request: Request):
        admin(request)
        body = await json_body(request)
        control = str(body.get("control") or "")
        try:
            gw.set_override(control, bool(body.get("enabled")))
        except ValueError as exc:
            return JSONResponse({"status": "rejected", "error": str(exc), "version": store.version,
                                 "hash": store.hash, "changed": []}, status_code=400)
        return _override_result([control])

    @app.post("/api/policy/detectors-off")
    async def detectors_off(request: Request):
        admin(request)
        gw.detectors_off()
        return _override_result(list(gw.overrides))

    @app.post("/api/policy/detectors-on")
    async def detectors_on(request: Request):
        admin(request)
        gw.detectors_on()
        return _override_result([])

    @app.get("/api/approvals")
    async def approvals(status: str | None = None):
        return gw.approvals_view(status)

    @app.post("/api/approvals/{approval_id}")
    async def approval_decide(approval_id: str, request: Request):
        admin(request)
        body = await json_body(request)
        try:
            return gw.decide_approval(approval_id, bool(body.get("approve")))
        except (KeyError, LookupError) as exc:
            raise HTTPException(404, f"unknown approval {approval_id}") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/kill/{agent_id}")
    async def kill(agent_id: str, request: Request):
        admin(request)
        try:
            return gw.kill(agent_id)
        except KeyError as exc:
            raise HTTPException(404, f"unknown agent {agent_id}") from exc

    @app.delete("/api/kill/{agent_id}")
    async def unkill(agent_id: str, request: Request):
        admin(request)
        return gw.unkill(agent_id)

    @app.get("/api/audit/verify")
    async def audit_verify():
        return gw.audit.verify()

    @app.post("/api/audit/tamper-drill")
    async def audit_tamper_drill(request: Request):
        """Body optional: {"seq": int} (default: the latest record). Edits that record in a scratch copy
        of the live chain under data/drills/ and verifies the copy; audit.jsonl is never modified.
        200 -> {ok: bool (false), broken_at: int, reason: str, seq: int, field: "action" | "summary",
        before, after, original_ok: bool (live log verifies), records: int}. 409 on an empty log,
        404 for an unknown seq, 400 for a malformed body."""
        admin(request)
        seq = None
        if (await request.body()).strip():
            seq = (await json_body(request)).get("seq")
            if seq is not None and type(seq) is not int:
                raise HTTPException(400, "seq must be an integer")
        try:
            return gw.audit.tamper_drill(gw.data_dir / "drills", seq)
        except IndexError as exc:  # before LookupError, its base class
            raise HTTPException(404, str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, f"target audit record is unreadable: {exc}") from exc

    @app.get("/api/audit/verify-fixture")
    async def audit_verify_fixture():
        """Verifies data/fixtures/tampered.jsonl (record #2 edited after signing): must report ok=false."""
        return gw.verify_fixture()

    @app.get("/api/audit.jsonl")
    async def audit_export():
        path = data_dir / "audit.jsonl"
        if not path.exists():
            return PlainTextResponse("", media_type="application/x-ndjson")
        return FileResponse(path, media_type="application/x-ndjson", filename="audit.jsonl")

    @app.get("/api/report.md")
    async def report_md():
        return PlainTextResponse(gw.audit.report_md(gw.snapshot()), media_type="text/markdown")

    @app.get("/api/tests")
    async def tests_report():
        return gw.tests_report()

    @app.get("/metrics")
    async def metrics():
        snap = gw.snapshot()
        lines = ["# TYPE agentshield_decisions_total counter"]
        for action, n in snap["counts"].items():
            lines.append(f'agentshield_decisions_total{{action="{action}"}} {n}')
        lat = snap["latency"]
        lines += [
            "# TYPE agentshield_overhead_ms gauge",
            f'agentshield_overhead_ms{{quantile="0.5",judge="no"}} {lat["p50_ms"]}',
            f'agentshield_overhead_ms{{quantile="0.99",judge="no"}} {lat["p99_ms"]}',
            f'agentshield_overhead_ms{{quantile="0.5",judge="yes"}} {lat["p50_judge_ms"]}',
            f'agentshield_overhead_ms{{quantile="0.99",judge="yes"}} {lat["p99_judge_ms"]}',
            f'agentshield_judge_rate {lat["judge_rate"]}',
            f'agentshield_judge_breaker_open {1 if snap["judge"]["breaker"] != "closed" else 0}',
            f'agentshield_posture_score {snap["posture"]["score"]}',
            f'agentshield_policy_version {snap["policy"]["version"]}',
            f'agentshield_approvals_pending {snap["approvals_pending"]}',
        ]
        for b in snap["budgets"]:
            lines.append(f'agentshield_budget_usd_used{{agent="{b["agent_id"]}"}} {b["usd_used"]}')
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    @app.get("/health")
    async def health():
        policy, h, v, disabled = gw.effective()
        return {"status": "ok", "policy_version": v, "policy_hash": h, "mode": policy.mode,
                "uptime_s": round(time.time() - gw.started, 1), "detectors_disabled": disabled}

    mount_extensions(app, gw)

    app.mount("/app", SecurityHeaders(UIStaticFiles(directory=APP_DIR, html=True, check_dir=False),
                                      APP_SECURITY_HEADERS), name="app")

    @app.get("/", include_in_schema=False)
    async def index():
        return RedirectResponse("/app/", status_code=307)

    @app.get("/classic", include_in_schema=False)
    async def classic():
        """The original single-file dashboard, kept as a fallback."""
        page = REPO_DIR / "frontend" / "index.html"
        if page.exists():
            return FileResponse(page, media_type="text/html")
        return HTMLResponse("<h1>AgentShield</h1><p>Dashboard not built yet. See <a href='/api/snapshot'>"
                            "/api/snapshot</a>.</p>")

    return app


def _default_app() -> FastAPI:
    return create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(create_app(), host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8080")))
