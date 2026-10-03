"""Newline-delimited MCP stdio relay (stdlib only).

Run from backend, or set PYTHONPATH=backend::
    python -m app.mcp_stdio --agent-key KEY --lock tools.lock -- SERVER_CMD ARGS...

``build_guard`` is the engine integration hook. Its default callbacks are
explicitly permissive: the key is passed to the hook, NOT authenticated here.
Pinning is active, but policy inspection requires replacing this hook. This
module does not mount an HTTP MCP endpoint or select a policy-configured server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
from collections.abc import Awaitable, Callable

from .mcp_proxy import McpGuard


LINE_LIMIT = 1024 * 1024


def build_guard(agent_key: str, lock_path: str = "tools.lock") -> McpGuard:
    """Replace with engine-bound synchronous callbacks for the supplied identity."""
    return McpGuard(
        check_call=lambda name, arguments: (True, {"action": "allow", "summary": "Policy callback not installed"}),
        scan_result=lambda text, kind: (text, {"action": "allow", "summary": "Scan callback not installed"}),
        allowed_tools=lambda: None,
        lock_path=lock_path,
    )


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
            forward, reply = guard.handle_client_message(msg)
            if reply is not None:
                await send_client(reply)
            if forward is not None:
                server_writer.write(_encode(forward))
                await server_writer.drain()
        server_writer.close()

    async def server_to_client():
        while line := await server_reader.readline():
            # Malformed server output aborts the session rather than bypassing inspection.
            await send_client(guard.handle_server_message(_decode(line)))

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
    parser.add_argument("--agent-key", required=True)
    parser.add_argument("--lock", default="tools.lock")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a server command is required after --")
    print("AgentShield MCP: default callbacks are permissive; install build_guard policy callbacks before production use.", file=sys.stderr)
    try:
        return asyncio.run(run_stdio(command, build_guard(args.agent_key, args.lock)))
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        print(f"AgentShield MCP session failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
