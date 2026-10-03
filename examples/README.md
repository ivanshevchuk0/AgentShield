# AgentShield integration examples

All HTTP examples target the local gateway, not an external model provider:

- Model API: `http://localhost:8080/v1`
- Agent credential: `wk_bank_ops_demo` (demo only)
- Model: `mock/vulnerable-llm`
- Identity comes from `Authorization: Bearer <key>`, not a claimed agent id.

## Run from the repository root

Start the gateway in a separate terminal using the installed project dependencies:

```sh
PYTHONPATH=backend python3 -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8080
python3 examples/openai_sdk.py
python3 examples/httpx_agent.py
```

`openai_sdk.py` uses the OpenAI SDK **only if it is already installed**; otherwise
it sends the same JSON request with httpx. Neither path needs a provider key.
`httpx_agent.py` uses httpx only, prints every chat/tool decision, and executes
all model-proposed tools through `/v1/tools/call`. No local tool bypass exists.

The agent's default prompt reads `policy-1`. Other deterministic mock prompts:

```sh
python3 examples/httpx_agent.py '#tool:lookup_customer {"customer_id":"customer-1"}'
python3 examples/httpx_agent.py '#tool:transfer_funds {"iban":"demo-destination","amount":10,"reference":"demo"}'
```

The transfer uses a non-IBAN demo destination deliberately: the demo tool has
no real banking connection, and input PII redaction would otherwise change a
valid IBAN before the mock model sees it. Do not use this as a payment
validation example. The mock echoes tool results rather than planning further
steps. The loop stops after at most six model turns.

## Approval and errors

An irreversible call may be challenged during **chat generation** as well as
**tool execution**. Both are handled by the same helper:

1. A 403 response contains `error.record.action=require_approval` and an
   `approval_id` in that record (the real gateway also includes it in `error`).
   `error.code` is a control id such as `tools.approval`, not necessarily the
   literal string `approval_required`.
2. The example prints the id and polls `GET /api/approvals`. A human approves
   the pending entry on the dashboard at `http://localhost:8080/`.
3. It retries the **unchanged request**, with the same `X-Session` and
   `X-Approval: <id>`, once. Approval is single-use: the next boundary may
   request a new approval. Approve that separately; do not reuse the old id.

The agent never approves its own requests. Denial, expiry, consumption, or a
120-second wait timeout stops it. All other HTTP failures propagate without
retries: 403 blocks, 429 budgets, 401 authentication. A policy/flow block cannot
be bypassed with approval. Each run gets a fresh session; all its chat/tool
requests share that session. The returned signed tool `call_id` is preserved
in the assistant/tool conversation pair.

The standard policy redacts PII and can withhold malicious tool output. Reading
`invoice-7` is intentionally an indirect-injection scenario, not a success
example. The mock upstream works offline; `semantic.backend` in the supplied
policy is **openrouter**, so suspicious grey-zone input may attempt a remote
judge. For a completely offline deployment set that backend to `heuristic`
(or `stub` for deterministic tests) via your own policy copy. These examples
do not disable controls or edit policy.

## Framework adapters

- [`pydantic_ai.md`](pydantic_ai.md): existing Pydantic AI application setup.
- [`langchain.md`](langchain.md): existing LangChain application setup.

These frameworks are optional, not added dependencies. Base-URL substitution
protects model requests only. Tool runners must route operations through the
gateway separately; the notes explain that boundary and provenance limitations.

## MCP client configuration

[`mcp_client_config.json`](mcp_client_config.json) uses the `mcpServers` stdio
shape used by Claude Code's project `.mcp.json` and Cursor's
`.cursor/mcp.json`. Merge the entry into your client configuration; change the
absolute `PYTHONPATH` to your checkout's `backend` directory and use the Python
interpreter with the project dependencies installed.

**Prerequisite:** the configuration launches `python3 -m app.mcp_stdio`.
That module is not present in the code inspected for this assignment, so the
configuration alone is not a working MCP proxy. Its owner must implement the
stdio entry point and document how it selects/wraps a policy-configured server
(`bank-tools` is the supplied demo server). No speculative command-line flags
or wrapper-specific environment variables are assumed here. HTTP examples
above do not depend on MCP.

## Offline checks (no server or network)

Tests are embedded in the two owned Python files; explicit pytest paths collect
them without adding files outside this assignment:

```sh
python3 -m py_compile examples/openai_sdk.py examples/httpx_agent.py
python3 -m pytest -q examples/openai_sdk.py examples/httpx_agent.py
python3 -m json.tool examples/mcp_client_config.json > /dev/null
```

Tests use `httpx.MockTransport` and a fake optional SDK. They check URL/auth,
model selection, session continuity, signed tool ids, approval retry/denial,
non-retryable blocks, and timeout. They do not claim to test optional frameworks
or an absent MCP wrapper. Authoritative HTTP shapes: `docs/CONTRACTS.md`.
