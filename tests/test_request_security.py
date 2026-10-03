"""HTTP body limits stop oversized input before parsing or protocol dispatch."""
import asyncio

import pytest
from fastapi.testclient import TestClient

from app.main import MAX_REQUEST_BODY_BYTES, RequestBodyLimit


@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/tools/call", "/mcp/test", "/api/policy"])
def test_oversized_body_is_rejected_before_route(app, gateway, path):
    before = gateway.audit.all()
    with TestClient(app) as public:
        result = public.post(path, content=b" " * (MAX_REQUEST_BODY_BYTES + 1))
    assert result.status_code == 413
    assert gateway.upstream_calls == 0
    assert gateway.audit.all() == before


@pytest.mark.parametrize("headers", [[], [(b"content-length", b"1")]])
def test_chunked_body_is_counted_even_without_truthful_length(headers):
    calls, sent, reads = [], [], []
    chunks = iter([
        {"type": "http.request", "body": b"a" * 6, "more_body": True},
        {"type": "http.request", "body": b"b" * 6, "more_body": True},
        {"type": "http.request", "body": b"c" * 6, "more_body": False},
    ])
    async def downstream(scope, receive, send):
        calls.append(True)
    async def receive():
        reads.append(True)
        return next(chunks)
    async def send(message):
        sent.append(message)
    asyncio.run(RequestBodyLimit(downstream, max_bytes=10)(
        {"type": "http", "headers": headers}, receive, send))
    assert not calls
    assert len(reads) == 2  # no further input is consumed once the bound is exceeded
    assert sent[0]["status"] == 413


def test_body_at_limit_is_replayed_without_altering_bytes():
    sent, received = [], []
    chunks = iter([
        {"type": "http.request", "body": b"hello", "more_body": True},
        {"type": "http.request", "body": b"world", "more_body": False},
    ])
    async def downstream(scope, receive, send):
        received.append(await receive())
    async def receive():
        return next(chunks)
    async def send(message):
        sent.append(message)
    asyncio.run(RequestBodyLimit(downstream, max_bytes=10)(
        {"type": "http", "headers": []}, receive, send))
    assert received == [{"type": "http.request", "body": b"helloworld", "more_body": False}]
    assert not sent


def test_ordinary_chat_still_works(client):
    response = client.post("/v1/chat/completions", headers={"Authorization": "Bearer wk_judge"},
        json={"model": "mock/vulnerable-llm", "messages": [{"role": "user", "content": "Hello"}]})
    assert response.status_code == 200
