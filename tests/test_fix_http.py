"""HTTP boundaries reject malformed inputs before dispatch or disclosure."""

import asyncio
import json

import httpx
import pytest

from app.main import MAX_REQUEST_BODY_BYTES, RequestBodyLimit
from app.metrics import Metrics
from app.models import Action


CHAT = "/v1/chat/completions"
AUTH = {"Authorization": "Bearer wk_judge"}
BODY = {"model": "mock/vulnerable-llm", "messages": [{"role": "user", "content": "Hello"}]}


@pytest.mark.parametrize("field,value", [
    ("max_tokens", "many"), ("max_tokens", {}), ("max_tokens", -5),
    ("max_tokens", True), ("max_tokens", 1.5), ("max_tokens", None),
    ("max_completion_tokens", 0), ("temperature", "warm"),
    ("temperature", {}), ("temperature", True), ("temperature", None),
    ("temperature", -1), ("temperature", 3),
])
def test_invalid_sampling_parameters(client, gateway, field, value):
    response = client.post(CHAT, headers=AUTH, json={**BODY, field: value})
    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_request"
    assert gateway.upstream_calls == 0


@pytest.mark.parametrize("payload", [
    '{', '[]', '{"model":"a","model":"b"}',
    '{"extra":{"x":1,"x":2}}', '{"max_tokens":Infinity}',
    '{"temperature":NaN}', '{"extra":1e999}', '{"extra":"\\ud800"}',
    '{"\\udfff":1}', '{"extra":[{"nested":"\\ud800"}]}',
    '[' * 1100 + '0' + ']' * 1100,
])
def test_invalid_json(client, gateway, payload):
    response = client.post(CHAT, headers=AUTH, content=payload)
    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_request"
    assert gateway.upstream_calls == 0


def test_duplicate_tool_arguments_rejected_before_approval(client, gateway):
    response = client.post("/v1/tools/call", headers={"Authorization": "Bearer wk_bank_ops_demo"},
        content='{"tool":"transfer_funds","arguments":{"amount":10001,"amount":1}}')
    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_request"
    assert gateway.approvals.list() == []


@pytest.mark.parametrize("messages", [[], [17], [{"role": {}, "content": "Hello"}],
    [{"role": "user", "content": 42}]])
def test_invalid_messages_are_client_errors(client, gateway, messages):
    response = client.post(CHAT, headers=AUTH, json={**BODY, "messages": messages})
    assert 400 <= response.status_code < 500
    assert "error" in response.json()
    assert gateway.upstream_calls == 0


@pytest.mark.parametrize("path,header", [(CHAT, b"authorization"), (CHAT, b"x-agent-id"),
    ("/v1/models", b"x-agent-id"), ("/api/snapshot", b"x-admin-token")])
def test_nonascii_headers_do_not_crash(client, path, header):
    headers = {b"authorization": b"Bearer wk_judge", header: b"\xff"}
    response = client.get(path, headers=headers) if path != CHAT else client.post(path, headers=headers, json=BODY)
    assert 400 <= response.status_code < 500
    assert "error" in response.json()


@pytest.mark.parametrize("headers,expected_reads", [
    ([(b"content-length", b"11")], 0), ([], 2), ([(b"content-length", b"1")], 2),
])
def test_size_limit_stops_receiving_early(headers, expected_reads):
    reads, sent = [], []
    async def receive():
        reads.append(True)
        assert len(reads) <= 2
        return {"type": "http.request", "body": b"x" * 6, "more_body": True}
    async def send(message):
        sent.append(message)
    async def downstream(scope, receive, send):
        pytest.fail("oversized request reached a route")
    asyncio.run(RequestBodyLimit(downstream, max_bytes=10)(
        {"type": "http", "headers": headers}, receive, send))
    assert len(reads) == expected_reads
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["error"]["code"] == "limits.input_size"


def test_oversized_unused_body_is_rejected(client, gateway):
    response = client.post(CHAT, headers=AUTH, json={**BODY, "extra": "x" * MAX_REQUEST_BODY_BYTES})
    assert response.status_code == 413
    assert "error" in response.json()
    assert gateway.upstream_calls == 0


def test_tool_arguments_cannot_bypass_policy_size_limit(client, gateway):
    response = client.post("/v1/tools/call", headers={"Authorization": "Bearer wk_bank_ops_demo"},
        json={"tool": "send_email", "arguments": {"to": "ops@bank.example", "subject": "test",
                                                  "body": "x" * 40001}})
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "limits.input_size"
    assert gateway.approvals.list() == []


@pytest.mark.parametrize("stream", [False, True])
def test_provider_extensions_cannot_escape(client, gateway, stream):
    text = gateway.store.text().replace("    upstream: mock", "    upstream: ollama", 1)
    assert gateway.store.apply_text(text)["status"] == "applied"
    response = {"id": "offline", "choices": [{"index": 0, "finish_reason": "stop",
        "message": {"role": "assistant", "content": "Safe", "refusal": "jan.kowalski@bank.example",
                    "reasoning": "unscanned-marker"},
        "logprobs": {"content": [{"token": "unscanned-marker"}]}}]}
    gateway.transport = httpx.MockTransport(lambda request: httpx.Response(200, json=response))
    reply = client.post(CHAT, headers=AUTH, json={**BODY, "stream": stream, "logprobs": True})
    assert reply.status_code == 200
    assert "unscanned-marker" not in reply.text
    assert "jan.kowalski@bank.example" not in reply.text
    assert "[EMAIL]" in reply.text
    if stream:
        assert "data: [DONE]" in reply.text


@pytest.mark.parametrize("stream", [False, True])
def test_provider_errors_are_generic(client, gateway, monkeypatch, stream):
    async def failed(*args, **kwargs):
        raise RuntimeError("provider-body-marker http://private-host.example/internal")
    monkeypatch.setattr("app.engine.upstream.complete", failed)
    response = client.post(CHAT, headers=AUTH, json={**BODY, "stream": stream})
    assert response.status_code == 502
    assert response.json()["error"]["type"] == "upstream_error"
    assert "provider-body-marker" not in response.text
    assert "private-host" not in response.text
    assert "judge" in response.json()["error"]["record"]


@pytest.mark.parametrize("status,content", [(500, "provider-body-marker"), (200, "not-json-marker")])
def test_real_provider_errors_do_not_disclose_url_or_body(client, gateway, status, content):
    text = gateway.store.text().replace("    upstream: mock", "    upstream: ollama", 1)
    assert gateway.store.apply_text(text)["status"] == "applied"
    gateway.transport = httpx.MockTransport(lambda request: httpx.Response(status, text=content))
    response = client.post(CHAT, headers=AUTH, json=BODY)
    assert response.status_code == 502
    assert content not in response.text
    assert "localhost" not in response.text
    assert "11434" not in response.text
    record = gateway.audit.tail(1)[0]
    assert content not in record["summary"]
    assert "localhost" not in record["summary"]


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout])
def test_transport_error_details_do_not_enter_audit(client, gateway, error):
    text = gateway.store.text().replace("    upstream: mock", "    upstream: ollama", 1)
    assert gateway.store.apply_text(text)["status"] == "applied"
    def failed(request):
        raise error("provider-transport-marker", request=request)
    gateway.transport = httpx.MockTransport(failed)
    response = client.post(CHAT, headers=AUTH, json=BODY)
    assert response.status_code == 502
    assert "provider-transport-marker" not in response.text
    assert "provider-transport-marker" not in gateway.audit.tail(1)[0]["summary"]


def test_prometheus_labels_are_bounded_and_escaped(client, gateway, monkeypatch):
    snapshot = gateway.snapshot()
    snapshot["counts"]["unbounded-injected-action"] = 1
    snapshot["budgets"] = [{"agent_id": 'x"}\\\nforged_metric 99', "usd_used": 0}]
    monkeypatch.setattr(gateway, "snapshot", lambda: snapshot)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "unbounded-injected-action" not in response.text
    assert "\nforged_metric" not in response.text
    assert 'agent="other"' in response.text
    metrics = Metrics()
    for i in range(100):
        metrics.observe({"action": f"unknown-{i}"})
    assert set(metrics.snapshot()["counts"]) <= {action.value for action in Action} | {"other"}


def test_configured_prometheus_agent_labels_are_escaped(client, gateway, monkeypatch):
    policy, phash, version, disabled = gateway.effective()
    agent_id = 'configured"\\\nlabel'
    agent = policy.agents[0].model_copy(update={"id": agent_id})
    policy = policy.model_copy(update={"agents": [agent]})
    snapshot = gateway.snapshot()
    snapshot["budgets"] = [{"agent_id": agent_id, "usd_used": 0}]
    monkeypatch.setattr(gateway, "snapshot", lambda: snapshot)
    monkeypatch.setattr(gateway, "effective", lambda: (policy, phash, version, disabled))
    response = client.get("/metrics")
    assert 'agent="configured\\"\\\\\\nlabel"' in response.text
    assert "\nlabel" not in response.text


@pytest.mark.parametrize("path,payload", [(CHAT, {**BODY, "messages": [{"role": "user", "content": "\ud800"}]}),
    ("/v1/tools/call", {"tool": "send_email", "arguments": {"body": "\udfff"}})])
def test_surrogates_in_valid_request_envelopes(client, gateway, path, payload):
    response = client.post(path, headers={**AUTH, "X-Session": "http-regression"}, content=json.dumps(payload))
    assert response.status_code == 400
    assert response.json()["error"]["type"] == "invalid_request"
    assert gateway.upstream_calls == 0


def test_anthropic_not_advertised_without_route(client, app):
    assert "app.anthropic_adapter" not in app.state.extensions
    assert "/v1/messages" not in client.get("/openapi.json").json()["paths"]
    assert client.post("/v1/messages", json={}).status_code == 404


def test_valid_unicode_and_sampling_parameters(client):
    response = client.post(CHAT, headers=AUTH, content=json.dumps({**BODY,
        "messages": [{"role": "user", "content": "Cześć 👋"}], "max_tokens": 32, "temperature": 0.5}))
    assert response.status_code == 200
    assert "Cześć 👋" in response.json()["choices"][0]["message"]["content"]
