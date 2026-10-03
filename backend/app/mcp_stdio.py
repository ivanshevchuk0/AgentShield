"""Newline-delimited MCP stdio relay (stdlib only).

Run from backend, or set PYTHONPATH=backend::
    python -m app.mcp_stdio --agent-key KEY --lock tools.lock -- SERVER_CMD ARGS...

The supplied identity is authenticated by the same Gateway as the HTTP API.
Policy and audit paths use AGENTSHIELD_POLICY and AGENTSHIELD_DATA_DIR.
Use a separate audit directory from any running HTTP gateway (one writer per log).
Prefer AGENTSHIELD_AGENT_KEY to a key in the process command line.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import inspect
import os
import sys
from collections.abc import Awaitable, Callable

from .mcp_proxy import EngineMcpGuard, McpGuard


LINE_LIMIT = 1024 * 1024


def build_guard(agent_key: str, lock_path: str = "tools.lock") -> McpGuard:
    from .engine import BACKEND_DIR, Gateway
    from .policy import PolicyStore

    gateway = Gateway(PolicyStore(os.environ.get("AGENTSHIELD_POLICY") or BACKEND_DIR / "policy.yaml"),
                      os.environ.get("AGENTSHIELD_DATA_DIR") or "data/mcp-stdio")
    return EngineMcpGuard(gateway, {"authorization": "Bearer " + agent_key}, lock_path, "stdio")


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def _reject_constant(value):
    raise ValueError("non-finite JSON number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _decode(line: bytes) -> dict:
    return json.loads(line, object_pairs_hook=_unique_object, parse_constant=_reject_constant, parse_float=_finite_float)


def _encode(msg: dict) -> bytes:
    return (json.dumps(msg, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


async def relay(
    guard: McpGuard,
    client_reader: asyncio.StreamReader,
    send_client: Callable[[dict], Awaitable[None]],
    server_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
) -> None:
    """Relay a single session. Neither stream may contain JSON-RPC batches."""
    async def client_to_server():
        while line := await client_reader.readline():
            try:
                msg = _decode(line)
            except (ValueError, UnicodeError):
                await send_client({"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700, "message": "Invalid JSON"}})
                continue
            handled = guard.handle_client_message(msg)
            forward, reply = await handled if inspect.isawaitable(handled) else handled
            if reply is not None:
                await send_client(reply)
            if forward is not None:
                server_writer.write(_encode(forward))
                await server_writer.drain()
        server_writer.close()

    async def server_to_client():
        while line := await server_reader.readline():
            # Malformed server output aborts the session rather than bypassing inspection.
            handled = guard.handle_server_message(_decode(line))
            await send_client(await handled if inspect.isawaitable(handled) else handled)

    upstream = asyncio.create_task(client_to_server())
    downstream = asyncio.create_task(server_to_client())
    try:
        done, _ = await asyncio.wait((upstream, downstream), return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if downstream not in done:
            # Drain final replies on client EOF, but do not leave a hung child alive.
            await asyncio.wait_for(downstream, timeout=5)
    finally:
        for task in (upstream, downstream):
            if not task.done():
                task.cancel()
        await asyncio.gather(upstream, downstream, return_exceptions=True)
        server_writer.close()
        if isinstance(guard, EngineMcpGuard):
            guard.close()


async def run_stdio(command: list[str], guard: McpGuard) -> int:
    process = await asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        # Inherit stderr: server diagnostics never contaminate JSON-RPC stdout.
        limit=LINE_LIMIT,
    )
    transport = None
    try:
        reader = asyncio.StreamReader(limit=LINE_LIMIT)
        transport, _ = await asyncio.get_running_loop().connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer,
        )

        def write_stdout(msg):
            sys.stdout.buffer.write(_encode(msg))
            sys.stdout.buffer.flush()

        async def send_client(msg):
            await asyncio.to_thread(write_stdout, msg)

        await relay(guard, reader, send_client, process.stdout, process.stdin)
    finally:
        if transport is not None:
            transport.close()
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=1)
            except asyncio.TimeoutError:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=1)
                except asyncio.TimeoutError:
                    process.kill()
        await process.wait()
    return process.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP stdio proxy with tool pinning")
    parser.add_argument("--agent-key", default=os.environ.get("AGENTSHIELD_AGENT_KEY"))
    parser.add_argument("--lock", default="tools.lock")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a server command is required after --")
    if not args.agent_key:
        parser.error("set AGENTSHIELD_AGENT_KEY or supply --agent-key")
    try:
        return asyncio.run(run_stdio(command, build_guard(args.agent_key, args.lock)))
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        print(f"AgentShield MCP session failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
