"""Pure adapters for the text/tool subset of Anthropic's Messages protocol.

No HTTP, authentication, model aliasing, or Anthropic streaming lives here.
Unsupported content blocks are rejected rather than silently removed. OpenAI
cannot preserve interleaving of assistant text and tool blocks: text comes first
on the return path. Tool IDs (including gateway signatures) are kept unchanged.
"""

from __future__ import annotations

import copy
import json


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        raise ValueError("content must be text or a list of text blocks")
    parts = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
            raise ValueError("only text blocks are supported here")
        parts.append(block["text"])
    return "".join(parts)


def _required_text(obj: dict, key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a nonempty string")
    return value


def anthropic_to_openai(body: dict) -> dict:
    """Convert a Messages request to a gateway chat request without mutating it."""
    model = _required_text(body, "model")
    max_tokens = body.get("max_tokens")
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens <= 0:
        raise ValueError("max_tokens must be a positive integer")
    source = body.get("messages")
    if not isinstance(source, list) or not source:
        raise ValueError("messages must be a nonempty list")
    messages = []
    if "system" in body:
        messages.append({"role": "system", "content": _text(body["system"])})
    for message in source:
        if not isinstance(message, dict) or message.get("role") not in {"user", "assistant"}:
            raise ValueError("Anthropic messages must have user or assistant role")
        role = message["role"]
        content = message.get("content")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            raise ValueError("message content must be text or blocks")
        text = []
        calls = []
        for block in content:
            if not isinstance(block, dict):
                raise ValueError("content block must be an object")
            kind = block.get("type")
            if kind == "text":
                text.append(_text([block]))
            elif kind == "tool_use" and role == "assistant":
                args = block.get("input")
                if not isinstance(args, dict):
                    raise ValueError("tool_use input must be an object")
                calls.append({"id": _required_text(block, "id"), "type": "function",
                              "function": {"name": _required_text(block, "name"),
                                           "arguments": json.dumps(args, ensure_ascii=False, allow_nan=False)}})
            elif kind == "tool_result" and role == "user":
                # Keep user text on either side of tool results in its original order.
                if text:
                    messages.append({"role": "user", "content": "".join(text)})
                    text.clear()
                result = _text(block.get("content", ""))
                if block.get("is_error"):
                    result = "[Tool error]\n" + result
                messages.append({"role": "tool", "tool_call_id": _required_text(block, "tool_use_id"),
                                 "content": result})
            else:
                raise ValueError(f"unsupported {role} content block: {kind}")
        if role == "assistant":
            converted = {"role": role, "content": "".join(text) if text or not calls else None}
            if calls:
                converted["tool_calls"] = calls
            messages.append(converted)
        elif text or not content:
            messages.append({"role": role, "content": "".join(text)})
    result = {"model": model, "messages": messages, "max_tokens": max_tokens}
    for key in ("temperature", "top_p", "stream"):
        if key in body:
            result[key] = copy.deepcopy(body[key])
    if "stop_sequences" in body:
        result["stop"] = copy.deepcopy(body["stop_sequences"])
    if "tools" in body:
        if not isinstance(body["tools"], list):
            raise ValueError("tools must be a list")
        tools = []
        for tool in body["tools"]:
            if not isinstance(tool, dict) or not isinstance(tool.get("input_schema"), dict):
                raise ValueError("tools must contain input_schema objects")
            function = {"name": _required_text(tool, "name"), "parameters": copy.deepcopy(tool["input_schema"])}
            if "description" in tool:
                function["description"] = tool["description"]
            tools.append({"type": "function", "function": function})
        result["tools"] = tools
    if "tool_choice" in body:
        choice = body["tool_choice"]
        if not isinstance(choice, dict):
            raise ValueError("tool_choice must be an object")
        kind = choice.get("type")
        if kind == "tool":
            result["tool_choice"] = {"type": "function", "function": {"name": _required_text(choice, "name")}}
        elif kind in {"auto", "any", "none"}:
            result["tool_choice"] = "required" if kind == "any" else kind
        else:
            raise ValueError(f"unsupported tool_choice: {kind}")
        if "disable_parallel_tool_use" in choice:
            result["parallel_tool_calls"] = not choice["disable_parallel_tool_use"]
    return result


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate tool argument key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str):
    raise ValueError(f"non-finite tool argument: {value}")


def openai_to_anthropic(completion: dict, model: str) -> dict:
    """Convert one inspected choice to a non-streaming Anthropic Message.

    Reject malformed tool JSON: replacing it with {} would hide a security error.
    A generic OpenAI 'stop' cannot distinguish an end turn from a stop sequence.
    """
    choices = completion.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("Anthropic responses require exactly one completion choice")
    choice = choices[0]
    message = choice["message"]
    if message.get("role") != "assistant":
        raise ValueError("completion message must be an assistant")
    content = []
    text = message.get("content")
    if text is not None:
        if not isinstance(text, str):
            raise ValueError("completion content must be text or null")
        if text or not message.get("tool_calls"):
            content.append({"type": "text", "text": text})
    if message.get("refusal"):
        content.append({"type": "text", "text": message["refusal"]})
    for call in message.get("tool_calls") or []:
        if call.get("type") != "function":
            raise ValueError("only function tool calls are supported")
        function = call["function"]
        args = json.loads(function["arguments"], object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
        if not isinstance(args, dict):
            raise ValueError("tool arguments must be a JSON object")
        content.append({"type": "tool_use", "id": _required_text(call, "id"),
                        "name": _required_text(function, "name"), "input": args})
    reasons = {"stop": "end_turn", "length": "max_tokens", "tool_calls": "tool_use",
               "content_filter": "refusal"}
    finish = choice.get("finish_reason")
    if finish not in reasons:
        raise ValueError(f"unsupported or incomplete finish_reason: {finish}")
    usage = completion.get("usage") or {}
    return {"id": _required_text(completion, "id"), "type": "message", "role": "assistant",
            "model": model, "content": content, "stop_reason": reasons[finish], "stop_sequence": None,
            "usage": {"input_tokens": usage.get("prompt_tokens", 0),
                      "output_tokens": usage.get("completion_tokens", 0)}}
