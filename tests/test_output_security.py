"""Provider text must not escape output guardrails through alternate fields."""

import asyncio
import json

import httpx
import pytest

from app.sse import completion_to_sse_chunks
from app.anthropic_adapter import openai_to_anthropic


def provider_message(message, **extra):
    return {"id": "chatcmpl-test", "object": "chat.completion", "created": 123,
            "model": "offline", "choices": [{"index": 0, "finish_reason": "stop",
            "message": message}], "usage": {"prompt_tokens": 4, "completion_tokens": 4,
            "total_tokens": 8}, **extra}


def configure_provider(gateway, response):
    text = gateway.store.text().replace("    upstream: mock", "    upstream: ollama", 1)
    assert gateway.store.apply_text(text)["status"] == "applied"
    gateway.transport = httpx.MockTransport(lambda request: httpx.Response(200, json=response))


async def chat(gateway):
    return await gateway.chat({"model": "mock/vulnerable-llm", "messages": [
        {"role": "user", "content": "Hello"}]}, {"authorization": "Bearer wk_judge"})


@pytest.mark.parametrize("secret", ["AWS key: AKIAIOSFODNN7EXAMPLE", "WRDN-CANARY-7F3A"])
def test_secret_in_refusal_is_blocked(gateway, secret):
    configure_provider(gateway, provider_message({"role": "assistant", "content": None,
                                                   "refusal": secret}))
    result = asyncio.run(chat(gateway))
    assert result.status == 403
    assert result.record["direction"] == "output"


def test_pii_in_refusal_redacted_in_every_protocol(gateway):
    configure_provider(gateway, provider_message({"role": "assistant", "content": "Safe",
                                                   "refusal": "jan.kowalski@bank.example"}))
    result = asyncio.run(chat(gateway))
    assert result.status == 200
    assert result.body["choices"][0]["message"]["content"] == "Safe"
    for output in (result.body, completion_to_sse_chunks(result.body),
                   openai_to_anthropic(result.body, "offline")):
        assert "jan.kowalski@bank.example" not in json.dumps(output)
    assert result.record["action"] == "redact"


def test_uninspected_provider_extensions_removed(gateway):
    secret = "WRDN-CANARY-7F3A"
    response = provider_message({"role": "assistant", "content": "Safe",
        "reasoning": secret, "reasoning_content": secret, "annotations": [secret],
        "audio": {"transcript": secret}, "function_call": {"arguments": secret}},
        provider_extension=secret)
    response["choices"][0]["logprobs"] = {"content": [{"token": secret}]}
    response["choices"][0]["extension"] = secret
    response["usage"]["extension"] = secret
    configure_provider(gateway, response)
    result = asyncio.run(chat(gateway))
    assert result.status == 200
    assert result.body["choices"][0]["message"] == {"role": "assistant", "content": "Safe"}
    assert secret not in json.dumps(result.body)
    assert secret not in json.dumps(completion_to_sse_chunks(result.body))


@pytest.mark.parametrize("refusal", [123, {}, []])
def test_malformed_provider_refusal_rejected(gateway, refusal):
    configure_provider(gateway, provider_message({"role": "assistant", "content": "Safe",
                                                   "refusal": refusal}))
    assert asyncio.run(chat(gateway)).status == 502
