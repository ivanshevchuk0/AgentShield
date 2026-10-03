"""Gateway-only tool loop. Run directly, or pytest this file for offline checks."""
from __future__ import annotations

import argparse
import json
import time
import uuid

import httpx

BASE_URL = "http://localhost:8080"
API_KEY = "wk_bank_ops_demo"
MODEL = "mock/vulnerable-llm"


def print_decision(response: httpx.Response) -> None:
    body = response.json()
    record = (body.get("error") or {}).get("record") or body.get("record") or body.get("agentshield") or {}
    action = response.headers.get("X-AgentShield-Decision") or record.get("action", "unknown")
    print(f"{response.request.method} {response.request.url.path}: HTTP {response.status_code} "
          f"decision={action} {record.get('summary', '')}")


def wait_for_approval(client: httpx.Client, approval_id: str, timeout: float = 120) -> None:
    print(f"Approval required: {approval_id}. Approve on the dashboard; waiting up to {timeout:g}s.")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get("/api/approvals")
        response.raise_for_status()
        approval = next((a for a in response.json() if a["id"] == approval_id), None)
        if approval:
            status = approval["status"]
            if status == "approved":
                return
            if status != "pending":
                raise RuntimeError(f"Approval {approval_id}: {status}; not retrying")
        time.sleep(1)
    raise TimeoutError(f"Approval {approval_id} was not approved in time")


def post(client: httpx.Client, path: str, payload: dict) -> dict:
    """Retry only approval challenges, never arbitrary failures or tool execution."""
    response = client.post(path, json=payload)
    print_decision(response)
    if response.status_code == 403:
        error = response.json().get("error") or {}
        record = error.get("record") or {}
        approval_id = record.get("approval_id") or error.get("approval_id")
        # Contract control ids are tools.approval / flow.untrusted_before_irreversible;
        # approval_required is the lifecycle, not necessarily the error.code.
        if record.get("action") == "require_approval" and approval_id:
            wait_for_approval(client, approval_id)
            response = client.post(path, json=payload, headers={"X-Approval": approval_id})
            print_decision(response)
    response.raise_for_status()
    return response.json()


def run_agent(client: httpx.Client, prompt: str, max_turns: int = 6) -> str:
    messages = [{"role": "user", "content": prompt}]
    for _ in range(max_turns):
        reply = post(client, "/v1/chat/completions", {
            "model": MODEL, "messages": messages, "max_tokens": 256, "stream": False,
        })
        message = reply["choices"][0]["message"]
        if not message.get("tool_calls"):
            content = message.get("content") or ""
            print(content)
            return content
        messages.append(message)
        for call in message["tool_calls"]:
            # Preserve raw arguments: the gateway rejects duplicate JSON keys.
            result = post(client, "/v1/tools/call", {
                "tool": call["function"]["name"],
                "arguments": call["function"]["arguments"], "call_id": call["id"],
            })
            # The tool endpoint returns a fresh signed id. Use it in both messages.
            call["id"] = result["call_id"]
            messages.append({"role": "tool", "tool_call_id": result["call_id"],
                             "content": result["result"]})
    raise RuntimeError(f"Stopped after {max_turns} model turns")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prompt", nargs="?", default='#tool:read_document {"doc_id":"policy-1"}')
    args = parser.parse_args()
    with httpx.Client(base_url=BASE_URL, timeout=30, trust_env=False, headers={
        "Authorization": f"Bearer {API_KEY}", "X-Session": uuid.uuid4().hex,
    }) as client:
        run_agent(client, args.prompt)


# Tests live here because this assignment owns only examples/, not tests/.
def test_tool_loop() -> None:
    requests = []

    def handle(request):
        requests.append(request)
        body = json.loads(request.content)
        assert request.headers["authorization"] == f"Bearer {API_KEY}"
        assert request.headers["x-session"] == "test-session"
        if request.url.path == "/v1/tools/call":
            assert body == {"tool": "read_document", "arguments": '{"doc_id":"policy-1"}', "call_id": "signed-chat"}
            return httpx.Response(200, json={"call_id": "signed-tool", "result": "Policy text", "action": "allow"})
        assert request.url.path == "/v1/chat/completions"
        assert body["model"] == MODEL
        if len(requests) == 1:
            message = {"role": "assistant", "content": None, "tool_calls": [{"id": "signed-chat", "type": "function",
                       "function": {"name": "read_document", "arguments": '{"doc_id":"policy-1"}'}}]}
        else:
            assert body["messages"][-2]["tool_calls"][0]["id"] == "signed-tool"
            assert body["messages"][-1] == {"role": "tool", "tool_call_id": "signed-tool", "content": "Policy text"}
            message = {"role": "assistant", "content": "Done"}
        return httpx.Response(200, json={"choices": [{"message": message}]}, headers={"X-AgentShield-Decision": "allow"})

    with httpx.Client(base_url=BASE_URL, transport=httpx.MockTransport(handle), headers={
        "Authorization": f"Bearer {API_KEY}", "X-Session": "test-session",
    }) as client:
        assert run_agent(client, "Read policy") == "Done"
    assert len(requests) == 3


def test_approval_retry_and_denial(monkeypatch) -> None:
    import pytest

    monkeypatch.setattr(time, "sleep", lambda _: None)
    for status in ("approved", "denied", "expired", "consumed"):
        requests = []

        def handle(request):
            requests.append(request)
            if request.method == "GET":
                assert request.url.path == "/api/approvals"
                return httpx.Response(200, json=[{"id": "approval-1", "status": status}])
            if request.headers.get("x-approval"):
                assert request.headers["x-approval"] == "approval-1"
                assert request.content == requests[0].content
                return httpx.Response(200, json={"result": "queued", "action": "allow"})
            return httpx.Response(403, json={"error": {"type": "agentshield_blocked", "code": "tools.approval",
                                  "record": {"action": "require_approval", "approval_id": "approval-1"}}})

        with httpx.Client(base_url=BASE_URL, transport=httpx.MockTransport(handle)) as client:
            if status == "approved":
                assert post(client, "/v1/tools/call", {"tool": "transfer_funds", "arguments": {"amount": 10}})["result"] == "queued"
                assert len(requests) == 3
            else:
                with pytest.raises(RuntimeError, match=status):
                    post(client, "/v1/tools/call", {"tool": "transfer_funds", "arguments": {"amount": 10}})
                assert len(requests) == 2


def test_blocks_and_timeout_do_not_retry() -> None:
    import pytest

    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(403, json={"error": {"code": "tools.allowlist", "record": {"action": "block"}}})

    with httpx.Client(base_url=BASE_URL, transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            post(client, "/v1/tools/call", {"tool": "unknown", "arguments": {}})
        with pytest.raises(TimeoutError):
            wait_for_approval(client, "missing", timeout=0)
    assert len(requests) == 1


if __name__ == "__main__":
    main()
