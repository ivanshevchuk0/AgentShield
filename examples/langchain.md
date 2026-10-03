# LangChain: gateway-backed chat

LangChain and `langchain-openai` are **not repository dependencies**. In an
application that already has `langchain-openai`, point `ChatOpenAI` at the gateway:

```python
import uuid
from langchain_openai import ChatOpenAI

session = uuid.uuid4().hex
llm = ChatOpenAI(
    base_url="http://localhost:8080/v1",
    api_key="wk_bank_ops_demo",
    model="mock/vulnerable-llm",
    max_retries=0,
    max_tokens=128,
    default_headers={"X-Session": session},
)
print(llm.invoke("Describe a banking operations assistant.").content)
```

This protects model traffic, not local tool execution. `bind_tools` supplies
schemas to a model; a LangChain tool runner still executes functions locally
unless you replace those functions with gateway calls. The offline mock model
produces calls only with the `#tool:<name> <JSON object>` marker; it is not a
full autonomous planner.

## Route a tool through the gateway

In an existing tool-using application, run from the repository root and register
this function with your framework's normal tool mechanism:

```python
import httpx
from examples.httpx_agent import post

def read_document(doc_id: str) -> str:
    """Read a policy document through Sealdesk."""
    with httpx.Client(
        base_url="http://localhost:8080", timeout=30, trust_env=False,
        headers={"Authorization": "Bearer wk_bank_ops_demo", "X-Session": session},
    ) as gateway:
        return post(gateway, "/v1/tools/call", {
            "tool": "read_document", "arguments": {"doc_id": doc_id},
        })["result"]
```

Use the same `session` for all model and tool calls in one conversation. Do not
execute a local fallback on 403/401/429. The shared `post` helper prints each
decision, polls `GET /api/approvals` for human approval, and retries the exact
request once with `X-Approval`. Denied, expired, or consumed approvals stop the
operation; ordinary blocks never trigger approval polling.

For signed tool provenance, retain the tool endpoint's returned `call_id` in
both the assistant tool call and subsequent tool message. A framework's locally
invented tool id is not gateway provenance. [`httpx_agent.py`](httpx_agent.py)
shows the complete round trip without framework dependencies.

HTTP blocks follow `docs/CONTRACTS.md`: `error.type=agentshield_blocked`,
`error.code=<control id>`, and `error.record` is the decision record. An
approval challenge has `error.record.action=require_approval` and
`error.record.approval_id`. Budget failures are 429; authentication failures
are 401 (impersonation is 403).
