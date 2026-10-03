"""Offline protocol contract and security regression checks."""

import copy
import json

import pytest

from app.anthropic_adapter import anthropic_to_openai, openai_to_anthropic
from app.sse import completion_to_sse_chunks, parse_sse_stream


def completion(content="Cześć 👋\nSecond line", calls=None, finish="stop"):
    message = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = calls
    return {"id": "chatcmpl-123", "object": "chat.completion", "created": 123,
            "model": "mock/vulnerable-llm", "system_fingerprint": "fp_test",
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}}


def tool(call_id="call_w.signed.id", name="lookup_customer", args='{"customer_id":"ąć"}'):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": args}}


def event(choices, **extra):
    return "data: " + json.dumps({"id": "chatcmpl-123", "model": "mock/vulnerable-llm",
                                 "created": 123, "choices": choices, **extra}) + "\n\n"


@pytest.mark.parametrize("content,calls,finish", [
    ("Cześć 👋\nSecond line", None, "stop"), ("", None, "length"),
    (None, [tool()], "tool_calls"), ("Checking", [tool(), tool("call_2", "read_document", '{}')], "tool_calls"),
])
def test_sse_completion_round_trip(content, calls, finish):
    original = completion(content, calls, finish)
    saved = copy.deepcopy(original)
    chunks = completion_to_sse_chunks(original)
    assert chunks[-1] == "data: [DONE]\n\n"
    assert all(chunk.startswith("data: ") and chunk.endswith("\n\n") for chunk in chunks)
    payloads = [json.loads(c[6:]) for c in chunks[:-1]]
    assert all(p["object"] == "chat.completion.chunk" for p in payloads)
    assert payloads[0]["choices"][0]["delta"] == {"role": "assistant"}
    assert payloads[-2]["choices"][0]["finish_reason"] == finish
    assert payloads[-1]["choices"] == []
    assert parse_sse_stream(chunks) == original
    assert parse_sse_stream("".join(chunks).encode()) == original
    assert parse_sse_stream("".join(chunks).splitlines()) == original
    assert original == saved


def test_sse_interleaved_choices_tools_and_usage():
    lines = [": heartbeat\n\nevent: message\n", event([
        {"index": 2, "delta": {"role": "assistant", "content": "Hel"}},
        {"index": 0, "delta": {"role": "assistant", "tool_calls": [
            {"index": 1, "id": "call_2", "type": "function", "function": {"name": "read_", "arguments": '{"doc'}}]}}]),
        event([{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": '{}'}},
            {"index": 1, "function": {"name": "document", "arguments": '_id":"7"}'}}]}},
            {"index": 2, "delta": {"content": "lo 👋"}, "finish_reason": "stop"}]),
        event([{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]),
        event([], usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}),
        "data: [DONE]\n\n", "data: invalid trailing bytes\n\n"]
    parsed = parse_sse_stream(iter(lines))
    assert [c["index"] for c in parsed["choices"]] == [0, 2]
    assert parsed["choices"][1]["message"]["content"] == "Hello 👋"
    assert parsed["choices"][0]["message"] == {"role": "assistant", "content": None,
        "tool_calls": [tool("call_1", "lookup", '{}'), tool("call_2", "read_document", '{"doc_id":"7"}') ]}
    assert parsed["usage"]["total_tokens"] == 3
    assert parse_sse_stream(completion_to_sse_chunks(parsed)) == parsed


def test_sse_multiline_and_no_blank_delimiters():
    assert parse_sse_stream(['event: message', 'data: {"choices": [',
        'data: {"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}',
        'data: ]}', '', 'data: [DONE]'])["choices"][0]["message"]["content"] == "ok"
    assert parse_sse_stream([event([{"index": 0, "delta": {"content": "a"}}]).strip(),
        event([{"index": 0, "delta": {"content": "b"}, "finish_reason": "stop"}]).strip()]
        )["choices"][0]["message"]["content"] == "ab"


def test_sse_refusal_and_logprobs_deltas():
    result = parse_sse_stream([event([{"index": 0, "delta": {"refusal": "I "},
        "logprobs": {"content": [{"token": "I"}]}}]),
        event([{"index": 0, "delta": {"refusal": "cannot"}, "finish_reason": "content_filter",
                "logprobs": {"content": [{"token": "cannot"}]}}])])
    assert result["choices"][0]["message"]["refusal"] == "I cannot"
    assert len(result["choices"][0]["logprobs"]["content"]) == 2
    assert parse_sse_stream(completion_to_sse_chunks(result)) == result


@pytest.mark.parametrize("lines", [[], ["data: [DONE]"], ["data: nope\n\n"],
    ['data: {"choices":'], ['data: {"error":{"message":"provider failed"}}'],
    ['data: []'], ['data: {"choices":null}']])
def test_sse_invalid_or_empty_stream_is_not_success(lines):
    with pytest.raises(ValueError):
        parse_sse_stream(lines)


def request(messages=None, **extra):
    return {"model": "mock/vulnerable-llm", "max_tokens": 256,
            "messages": messages if messages is not None else [{"role": "user", "content": "Hi"}], **extra}


def test_anthropic_system_tools_options_and_no_mutation():
    body = request(system=[{"type": "text", "text": "Be "}, {"type": "text", "text": "helpful"}],
        tools=[{"name": "lookup_customer", "description": "Look up a customer",
                "input_schema": {"type": "object", "properties": {"id": {"type": "string"}}}}],
        tool_choice={"type": "tool", "name": "lookup_customer", "disable_parallel_tool_use": True},
        temperature=0, top_p=0.9, stop_sequences=["END"], stream=False)
    saved = copy.deepcopy(body)
    result = anthropic_to_openai(body)
    assert result["messages"] == [{"role": "system", "content": "Be helpful"},
                                  {"role": "user", "content": "Hi"}]
    assert result["tools"] == [{"type": "function", "function": {"name": "lookup_customer",
        "description": "Look up a customer", "parameters": body["tools"][0]["input_schema"]}}]
    assert result["tool_choice"] == {"type": "function", "function": {"name": "lookup_customer"}}
    assert result["parallel_tool_calls"] is False
    assert (result["max_tokens"], result["temperature"], result["top_p"], result["stop"], result["stream"]) == (256, 0, 0.9, ["END"], False)
    result["tools"][0]["function"]["parameters"]["type"] = "changed"
    assert body == saved
    assert anthropic_to_openai(request(system="Rules"))["messages"][0]["content"] == "Rules"


@pytest.mark.parametrize("anthropic,openai", [("auto", "auto"), ("any", "required"), ("none", "none")])
def test_tool_choice_mapping(anthropic, openai):
    assert anthropic_to_openai(request(tool_choice={"type": anthropic}))["tool_choice"] == openai


def test_anthropic_mixed_tool_results_preserve_order_and_error():
    result = anthropic_to_openai(request([
        {"role": "assistant", "content": [
            {"type": "text", "text": "Checking"},
            {"type": "tool_use", "id": "call_1", "name": "lookup_customer", "input": {"id": "ąć"}},
            {"type": "tool_use", "id": "call_2", "name": "read_document", "input": {}}]},
        {"role": "user", "content": [
            {"type": "text", "text": "Before"},
            {"type": "tool_result", "tool_use_id": "call_1", "content": [{"type": "text", "text": "OK"}]},
            {"type": "tool_result", "tool_use_id": "call_2", "content": "Failed", "is_error": True},
            {"type": "text", "text": "After"}]}]))
    assert result["messages"][0]["content"] == "Checking"
    assert json.loads(result["messages"][0]["tool_calls"][0]["function"]["arguments"]) == {"id": "ąć"}
    assert result["messages"][1:] == [
        {"role": "user", "content": "Before"},
        {"role": "tool", "tool_call_id": "call_1", "content": "OK"},
        {"role": "tool", "tool_call_id": "call_2", "content": "[Tool error]\nFailed"},
        {"role": "user", "content": "After"}]


@pytest.mark.parametrize("text", [None, "Checking"])
def test_anthropic_tool_completion_round_trip_through_sse(text):
    original = completion(text, [tool(), tool("call_2", "read_document", '{}')], "tool_calls")
    saved = copy.deepcopy(original)
    message = openai_to_anthropic(parse_sse_stream(completion_to_sse_chunks(original)), "claude-client-model")
    assert message["model"] == "claude-client-model"
    assert message["type"] == "message"
    assert message["stop_reason"] == "tool_use"
    assert message["usage"] == {"input_tokens": 12, "output_tokens": 7}
    converted = anthropic_to_openai(request([{"role": "assistant", "content": message["content"]}]))
    returned = converted["messages"][0]
    assert returned["content"] == text
    assert [c["id"] for c in returned["tool_calls"]] == [c["id"] for c in original["choices"][0]["message"]["tool_calls"]]
    assert [json.loads(c["function"]["arguments"]) for c in returned["tool_calls"]] == [{"customer_id": "ąć"}, {}]
    assert original == saved


@pytest.mark.parametrize("finish,reason", [("stop", "end_turn"), ("length", "max_tokens"), ("content_filter", "refusal")])
def test_anthropic_text_response_shape_and_finish(finish, reason):
    result = openai_to_anthropic(completion("Hello", finish=finish), "claude")
    assert result == {"id": "chatcmpl-123", "type": "message", "role": "assistant", "model": "claude",
        "content": [{"type": "text", "text": "Hello"}], "stop_reason": reason, "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 7}}
    assert anthropic_to_openai(request([{"role": "assistant", "content": result["content"]}]))["messages"] == [{"role": "assistant", "content": "Hello"}]


@pytest.mark.parametrize("args", ['{"id":', '[]', 'null', '{"id":1,"id":2}',
    '{"nested":{"id":1,"id":2}}', '{"amount":NaN}', '{"amount":Infinity}'])
def test_anthropic_never_hides_invalid_tool_arguments(args):
    with pytest.raises(ValueError):
        openai_to_anthropic(completion(None, [tool(args=args)], "tool_calls"), "claude")


@pytest.mark.parametrize("body", [
    request(max_tokens=0), request(max_tokens=True), request(model=""), request(messages=[]),
    request(system=[{"type": "image"}]), request(tool_choice={"type": "unknown"}),
    request(tools=[{"name": "x"}]), request([{"role": "system", "content": "x"}]),
    request([{"role": "user", "content": [{"type": "image", "source": {}}]}]),
    request([{"role": "assistant", "content": [{"type": "thinking", "thinking": "x"}]}]),
    request([{"role": "user", "content": [{"type": "tool_use", "id": "x", "name": "x", "input": {}}]}]),
    request([{"role": "assistant", "content": [{"type": "tool_use", "id": "x", "name": "x", "input": []}]}]),
    request([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x", "content": [{"type": "image"}]}]}]),
])
def test_anthropic_rejects_invalid_or_unsupported_requests(body):
    with pytest.raises(ValueError):
        anthropic_to_openai(body)


def test_anthropic_rejects_multi_choice_and_incomplete_responses():
    original = completion()
    original["choices"] *= 2
    with pytest.raises(ValueError):
        openai_to_anthropic(original, "claude")
    with pytest.raises(ValueError):
        openai_to_anthropic(completion(finish=None), "claude")


def test_anthropic_empty_text_missing_usage_and_refusal():
    original = completion("")
    del original["usage"]
    assert openai_to_anthropic(original, "claude")["usage"] == {"input_tokens": 0, "output_tokens": 0}
    assert openai_to_anthropic(original, "claude")["content"] == [{"type": "text", "text": ""}]
    original["choices"][0]["message"].update(content=None, refusal="Cannot help")
    original["choices"][0]["finish_reason"] = "content_filter"
    assert openai_to_anthropic(original, "claude")["content"] == [{"type": "text", "text": "Cannot help"}]
