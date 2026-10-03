"""Buffered OpenAI chat SSE serialization and upstream delta reassembly.

Each emitted string is a complete SSE event (including its blank delimiter).
The parser accepts those events, a text stream, or an iterable of decoded lines.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Iterable


_METADATA = ("id", "created", "model", "system_fingerprint", "service_tier")


def completion_to_sse_chunks(completion: dict) -> list[str]:
    """Re-emit an already inspected completion; never stream uninspected tokens."""
    base = {key: copy.deepcopy(completion[key]) for key in _METADATA if key in completion}
    base.update(object="chat.completion.chunk")
    base.setdefault("id", "")
    base.setdefault("created", 0)
    base.setdefault("model", "")
    events = []

    def emit(choices: list, **extra) -> None:
        events.append("data: " + json.dumps({**base, "choices": choices, **extra},
                                           ensure_ascii=False, separators=(",", ":")) + "\n\n")

    for position, choice in enumerate(completion["choices"]):
        index = choice.get("index", position)
        message = choice["message"]
        emit([{"index": index, "delta": {"role": message.get("role", "assistant")},
               "finish_reason": None}])
        delta = {key: copy.deepcopy(message[key]) for key in ("content", "refusal")
                 if message.get(key) is not None}
        if message.get("tool_calls"):
            delta["tool_calls"] = [{**copy.deepcopy(call), "index": i}
                                   for i, call in enumerate(message["tool_calls"])]
        if delta:
            emit([{"index": index, "delta": delta, "finish_reason": None}])
        final = {"index": index, "delta": {}, "finish_reason": choice.get("finish_reason")}
        if "logprobs" in choice:
            final["logprobs"] = copy.deepcopy(choice["logprobs"])
        emit([final])
    if completion.get("usage") is not None:
        emit([], usage=copy.deepcopy(completion["usage"]))
    events.append("data: [DONE]\n\n")
    return events


def parse_sse_stream(lines: Iterable[str | bytes] | str | bytes) -> dict:
    """Collect content and indexed tool deltas, preserving usage and choice indices.

    Invalid JSON and provider error events raise ValueError, not an empty success.
    A missing [DONE] is accepted (some providers close after the finish event).
    """
    if isinstance(lines, (str, bytes)):
        lines = [lines]
    result = {"object": "chat.completion"}
    choices: dict[int, dict] = {}
    calls: dict[int, dict[int, dict]] = {}

    def merge(chunk: dict) -> None:
        if not isinstance(chunk, dict) or "error" in chunk:
            raise ValueError("invalid or error upstream SSE event")
        if not isinstance(chunk.get("choices"), list):
            raise ValueError("upstream SSE event must contain choices")
        for key in _METADATA:
            if key in chunk:
                result[key] = chunk[key]
        if chunk.get("usage") is not None:
            result["usage"] = chunk["usage"]
        for part in chunk["choices"]:
            index = part["index"]
            choice = choices.setdefault(index, {"index": index, "message": {
                "role": "assistant", "content": None}, "finish_reason": None})
            message = choice["message"]
            delta = part.get("delta") or {}
            if delta.get("role"):
                message["role"] = delta["role"]
            for key in ("content", "refusal"):
                if delta.get(key) is not None:
                    message[key] = (message.get(key) or "") + delta[key]
            for tool in delta.get("tool_calls") or []:
                call = calls.setdefault(index, {}).setdefault(tool["index"], {
                    "id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                if tool.get("id") is not None:
                    call["id"] += tool["id"]
                if tool.get("type") is not None:
                    call["type"] = tool["type"]
                for key in ("name", "arguments"):
                    value = (tool.get("function") or {}).get(key)
                    if value is not None:
                        call["function"][key] += value
            if part.get("finish_reason") is not None:
                choice["finish_reason"] = part["finish_reason"]
            if "logprobs" in part and part["logprobs"] is not None:
                existing = choice.get("logprobs")
                if existing is None:
                    choice["logprobs"] = copy.deepcopy(part["logprobs"])
                else:
                    for key, value in part["logprobs"].items():
                        if isinstance(value, list):
                            existing.setdefault(key, []).extend(value)

    pending: list[str] = []
    done = False
    for item in lines:
        if done:
            break
        if isinstance(item, bytes):
            item = item.decode("utf-8")
        for line in item.splitlines() or [""]:
            if not line:
                if pending:
                    raise ValueError("invalid JSON in upstream SSE event")
                continue
            if not line.startswith("data:"):
                continue  # SSE comments, event names, ids, and retry fields.
            data = line[5:]
            if data.startswith(" "):
                data = data[1:]
            if data.strip() == "[DONE]" and not pending:
                done = True
                break
            pending.append(data)
            try:
                chunk = json.loads("\n".join(pending))
            except json.JSONDecodeError:
                continue  # SSE permits JSON split over multiple data fields.
            pending.clear()
            merge(chunk)
    if pending:
        raise ValueError("incomplete JSON in upstream SSE event")
    if not choices:
        raise ValueError("upstream SSE stream contains no completion choices")
    for index, tools in calls.items():
        choices[index]["message"]["tool_calls"] = [tools[i] for i in sorted(tools)]
    result["choices"] = [choices[i] for i in sorted(choices)]
    return result
