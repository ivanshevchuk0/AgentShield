# Pydantic AI: route model traffic through Sealdesk

Pydantic AI is **not a repository dependency**. For an application that already
uses it, the current `OpenAIChatModel` / `OpenAIProvider` integration is:

```python
import asyncio
import uuid
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from openai import AsyncOpenAI

client = AsyncOpenAI(
    base_url="http://localhost:8080/v1",
    api_key="wk_bank_ops_demo",
    max_retries=0,
    default_headers={"X-Session": uuid.uuid4().hex},
)
model = OpenAIChatModel(
    "mock/vulnerable-llm",
    provider=OpenAIProvider(openai_client=client),
)
agent = Agent(model)
async def main():
    try:
        result = await agent.run("Describe a banking operations assistant.")
        print(result.output)
    finally:
        await client.close()

asyncio.run(main())
```

Keep one `X-Session` per conversation, including its tool requests. The model
name is the gateway's policy name, not a direct upstream provider id. The mock
model needs no upstream API key and is deterministic; it is not a general
planning model.

## Tools are a separate enforcement boundary

Changing the model URL does **not** mediate functions registered with
`@agent.tool` or `@agent.tool_plain`. Those functions execute in your process.
To protect an existing tool, make its implementation call
`POST http://localhost:8080/v1/tools/call`, rather than executing the operation
locally. The bank agent's policy permits `lookup_customer`, `read_document`,
`send_email`, and `transfer_funds`; unknown tool names are rejected.

For example, this synchronous function can be registered as a plain tool in
an existing application (run from the repo root):

```python
import httpx
from examples.httpx_agent import post

session = "replace-with-your-conversation-id"

def read_document(doc_id: str) -> str:
    with httpx.Client(
        base_url="http://localhost:8080", timeout=30, trust_env=False,
        headers={"Authorization": "Bearer wk_bank_ops_demo", "X-Session": session},
    ) as gateway:
        return post(gateway, "/v1/tools/call", {
            "tool": "read_document", "arguments": {"doc_id": doc_id},
        })["result"]
```

Use that same `session` in the model client's `X-Session` header. `post` prints
model/tool decisions when used for those requests; it waits for human approval
on an approval challenge and retries once with `X-Approval`. It never approves
its own requests. Other HTTP errors propagate.

Framework-generated tool-message ids may not preserve gateway-signed provenance.
For the complete signed-id round trip, use [`httpx_agent.py`](httpx_agent.py),
which retains the `/v1/tools/call` response's `call_id` in the conversation.
Unknown/forged ids are treated as untrusted, not accepted as proof of origin.
See [`README.md`](README.md) for offline checks and policy constraints.
