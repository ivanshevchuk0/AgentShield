# Sealdesk: HackYeah 2026 submission

Goldman Sachs challenge: AI Control Layer.

## Submission overview

**Project name:** Sealdesk

**Tagline:** One control layer between AI agents and the models, tools and money they can reach.

**Problem.** Banks want AI agents that look up customers, read documents, send email and move funds. They cannot deploy them while an agent can leak personal data (PESEL, IBAN, card numbers), obey an instruction injected through a prompt or a document, spend tokens and money without a ceiling, or move funds without a human. A system prompt inside the model is not a control, because the model is the thing being attacked.

**What Sealdesk does.** It runs as one process outside the agent:

- **OpenAI-compatible proxy.** `POST /v1/chat/completions` in the OpenAI shape. The agent changes only its base URL and API key. Each agent is a named identity bound to its key.
- **Deterministic detectors first.** PII with checksums (PESEL, NIP, IBAN, cards, email, phone) is redacted; secrets are blocked; prompt injection in English, Polish, Ukrainian, Russian and German, including homoglyph, spacing, zero-width, base64 and hex variants, is blocked; a signature feed and a canary token cover output payloads and system-prompt leaks.
- **Semantic judge only in the grey zone.** An LLM judge (OpenRouter, `typesafe/jev-1.13`, with `qwen/qwen3.8-flash` fallback) is called only when the deterministic score is uncertain. It can raise risk, never clear a block. Timeout, breaker and its own daily spend cap; fail-closed on grey-zone traffic.
- **Tool governance.** Per-agent tool allow-lists, argument patterns (e.g. email only to `@bank.example`) and value caps (transfer at most 10,000). Tool call ids are HMAC-signed so the agent cannot fake where a tool result came from.
- **Human approval.** Irreversible tools (`transfer_funds`) need a single-use approval, valid 120 s, bound to the agent, tool, exact arguments and policy hash.
- **Information-flow guard.** A secret tool result (customer lookup) pasted into email, or a value from an untrusted document used as a recipient, is blocked. This stays on when every detector is switched off.
- **Budgets.** Per-agent USD per day, tokens per minute, requests per minute, reserved before the upstream call (HTTP 429 when exceeded).
- **Kill switch.** One agent can be stopped at runtime from the console.
- **HMAC audit trail.** Every decision is appended to a hash chain with masked evidence; edits, reordering, deletion and tail truncation are detected.
- **Hot-reloaded policy.** One `policy.yaml`, polled every 0.5 s. A broken edit is rejected and the last good version keeps enforcing. Profiles: `standard`, `dev` (monitor), `strict`.
- **OWASP LLM Top 10 2025 mapping.** Live coverage view: LLM01, LLM02, LLM06, LLM10 covered; LLM03, LLM05, LLM07 partial; LLM04, LLM08, LLM09 listed as gaps.

**Reproduce the demo.** Follow [Quickstart](../README.md#quickstart), start `make run-offline HOST=127.0.0.1`, enter the generated admin token in dashboard Settings, and run `./demo/run_demo.sh` with the same token in the second terminal. No provider key is needed: the assistant is a scripted mock, tools are simulators, and the offline judge is a deterministic heuristic classifier, not an LLM. For a real remote judge, configure `OPENROUTER_API_KEY` and use `make run`.

**Verify the submission.** Run `python3 -m pytest -q` for the current test results, `make smoke` against the running server, and `make verify-audit` after the demo. The eight-step demo checks benign traffic, PII redaction, injection, information flow with detectors off, policy rejection, budgets, approval and audit tampering. [Judge benchmark](JUDGE_BENCHMARK.md) records remote-model measurements; those measurements are separate from offline tests and depend on provider availability.

**Scope.** This is a hackathon demonstration, using synthetic customer records and simulated email/payment tools. Detector coverage and benchmark results describe the tested corpus, not a guarantee that all attacks are detected. A valid audit chain establishes integrity under the retained HMAC key. [MCP integration](../README.md) and [security boundaries](SECURITY.md) describe the implemented controls and limitations.

**Links.**

- Repository: https://github.com/ivanshevchuk0/Sealdesk (branch `warden-core`)
- Live demo: https://agentshield-demo-production.up.railway.app

**Team attribution.** Use the registered team roster in the submission form.

### Form version, 500 characters

```text
Sealdesk is a control layer outside AI agents. Its OpenAI-compatible gateway checks model and tool calls against a hot-reloaded YAML policy: PII redaction, injection detection, tool permissions, human approval, information-flow checks, budgets, a kill switch and an HMAC-chained audit log. Judges can reproduce an offline demo with a scripted assistant, simulated tools and a clearly labelled heuristic judge, or configure a remote LLM judge.
```

### Form version, 1500 characters

```text
Banks want AI agents that look up customers, read documents, send email and move money. Those actions need controls outside the model.

Sealdesk sits between an agent and its models and tools. The agent uses an OpenAI-compatible API. Each model and gateway-mediated tool call is authenticated and checked against a YAML policy that reloads without restart and keeps the last good version after an invalid edit. Deterministic detectors inspect personal identifiers, secrets, prompt injection, encoded content and output payloads. A remote LLM judge reviews uncertain requests and can only raise risk. Tools have allow-lists, argument rules and value limits. Irreversible payments need single-use human approval. An information-flow guard tracks protected tool values into later calls, even when detectors are switched off. Budgets are reserved before dispatch; a kill switch stops an agent. Decisions are recorded in an HMAC-chained audit log with masked evidence.

The reproducible offline demo uses synthetic records, simulated email and payments, a scripted assistant and an explicitly labelled deterministic heuristic judge. A provider key enables the real LLM judge. Tests and an eight-step demo exercise redaction, blocking, budgets, approvals, policy rejection and audit tampering. Benchmark results and security limitations are documented in the repository.
```
