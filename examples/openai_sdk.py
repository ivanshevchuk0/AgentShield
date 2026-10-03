"""OpenAI SDK if installed; otherwise the identical request with httpx."""
from __future__ import annotations

import uuid

import httpx

BASE_URL = "http://localhost:8080/v1"
API_KEY = "wk_bank_ops_demo"
MODEL = "mock/vulnerable-llm"


def complete(prompt: str = "Summarise the purpose of a banking operations assistant.", *, transport=None) -> dict:
    payload = {"model": MODEL, "messages": [{"role": "user", "content": prompt}],
               "max_tokens": 128, "stream": False}
    session = uuid.uuid4().hex
    try:
        from openai import OpenAI
    except ImportError:
        with httpx.Client(transport=transport, timeout=30, trust_env=False) as client:
            response = client.post(BASE_URL + "/chat/completions", json=payload, headers={
                "Authorization": f"Bearer {API_KEY}", "X-Session": session,
            })
            if response.is_error:
                print(response.text)
            response.raise_for_status()
            print("Gateway decision:", response.headers.get("X-AgentShield-Decision", "unknown"))
            return response.json()
    # No automatic retries of paid requests. Errors propagate; never bypass the gateway.
    with httpx.Client(transport=transport, timeout=30, trust_env=False) as http_client:
        with OpenAI(base_url=BASE_URL, api_key=API_KEY, max_retries=0, http_client=http_client,
                    default_headers={"X-Session": session}) as client:
            raw = client.chat.completions.with_raw_response.create(**payload)
            print("Gateway decision:", raw.headers.get("X-AgentShield-Decision", "unknown"))
            return raw.parse().model_dump()


def test_httpx_fallback(monkeypatch) -> None:
    import json
    import sys
    import pytest

    monkeypatch.setitem(sys.modules, "openai", None)
    requests = []

    def handle(request):
        requests.append(request)
        assert str(request.url) == BASE_URL + "/chat/completions"
        assert request.headers["authorization"] == f"Bearer {API_KEY}"
        assert request.headers["x-session"]
        assert json.loads(request.content)["model"] == MODEL
        return httpx.Response(200, json={"choices": [{"message": {"content": "Hello"}}]},
                              headers={"X-AgentShield-Decision": "allow"})

    assert complete("Hello", transport=httpx.MockTransport(handle))["choices"][0]["message"]["content"] == "Hello"
    assert len(requests) == 1
    with pytest.raises(httpx.HTTPStatusError):
        complete(transport=httpx.MockTransport(lambda _: httpx.Response(403, json={"error": {"code": "tools.allowlist"}})))


def test_optional_sdk(monkeypatch) -> None:
    import sys
    from types import SimpleNamespace

    calls = []

    class FakeOpenAI:
        def __init__(self, **kwargs):
            assert kwargs["base_url"] == BASE_URL
            assert kwargs["api_key"] == API_KEY
            assert kwargs["max_retries"] == 0
            assert kwargs["default_headers"]["X-Session"]
            self.chat = SimpleNamespace(completions=SimpleNamespace(with_raw_response=self))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def create(self, **payload):
            calls.append(payload)
            return SimpleNamespace(headers={"X-AgentShield-Decision": "allow"},
                                   parse=lambda: SimpleNamespace(model_dump=lambda: {"choices": []}))

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    assert complete("Hello") == {"choices": []}
    assert calls == [{"model": MODEL, "messages": [{"role": "user", "content": "Hello"}],
                      "max_tokens": 128, "stream": False}]


if __name__ == "__main__":
    reply = complete()
    print(reply["choices"][0]["message"].get("content"))
