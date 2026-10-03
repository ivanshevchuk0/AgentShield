# AgentShield: HackYeah 2026 submission

Goldman Sachs challenge: AI Control Layer.

## Interim submission (Saturday 20:00)

**Project name:** AgentShield

**Tagline:** One control layer between AI agents and the models, tools and money they can reach.

**Problem.** Banks want AI agents that look up customers, read documents, send email and move funds. They cannot deploy them while an agent can leak personal data (PESEL, IBAN, card numbers), obey an instruction injected through a prompt or a document, spend tokens and money without a ceiling, or move funds without a human. A system prompt inside the model is not a control, because the model is the thing being attacked.

**What AgentShield does.** It runs as one process outside the agent:

- **OpenAI-compatible proxy.** `POST /v1/chat/completions` in the OpenAI shape. The agent changes only its base URL and API key. Each agent is a named identity bound to its key.
- **Deterministic detectors first.** PII with checksums (PESEL, NIP, IBAN, cards, email, phone) is redacted; secrets are blocked; prompt injection in English, Polish, Ukrainian, Russian and German, including homoglyph, spacing, zero-width, base64 and hex variants, is blocked; a signature feed and a canary token cover output payloads and system-prompt leaks.
- **Semantic judge only in the grey zone.** An LLM judge (OpenRouter, Gemini 2.5 Flash Lite) is called only when the deterministic score is uncertain. It can raise risk, never clear a block. Timeout, breaker and its own daily spend cap; fail-closed on grey-zone traffic.
- **Tool governance.** Per-agent tool allow-lists, argument patterns (e.g. email only to `@bank.example`) and value caps (transfer at most 10,000). Tool call ids are HMAC-signed so the agent cannot fake where a tool result came from.
- **Human approval.** Irreversible tools (`transfer_funds`) need a single-use approval, valid 120 s, bound to the agent, tool, exact arguments and policy hash.
- **Information-flow guard.** A secret tool result (customer lookup) pasted into email, or a value from an untrusted document used as a recipient, is blocked. This stays on when every detector is switched off.
- **Budgets.** Per-agent USD per day, tokens per minute, requests per minute, reserved before the upstream call (HTTP 429 when exceeded).
- **Kill switch.** One agent can be stopped at runtime from the console.
- **HMAC audit trail.** Every decision is appended to a hash chain with masked evidence; edits, reordering, deletion and tail truncation are detected.
- **Hot-reloaded policy.** One `policy.yaml`, polled every 0.5 s. A broken edit is rejected and the last good version keeps enforcing. Profiles: `standard`, `dev` (monitor), `strict`.
- **OWASP LLM Top 10 2025 mapping.** Live coverage view: LLM01, LLM02, LLM06, LLM10 covered; LLM03, LLM05, LLM07 partial; LLM04, LLM08, LLM09 listed as gaps.

**What already works (checked on 2026-10-03 around 19:15 CEST).**

| Claim | How it was checked | Result |
|---|---|---|
| Test suite | `python3 -m pytest -q` on branch `warden-core` | 3,709 passed, 19 xfailed (3,728 collected, 24 files), 15 s, offline |
| Detection corpus | `reports/last-run.json` | 137 / 137 cases pass; 60 benign cases, 0 false positives |
| Live demo up | `GET /health` | `status: ok`, mode `enforce`, policy hash `b24057403b48` |
| Benign request allowed | live `POST /v1/chat/completions`, `wk_judge` | HTTP 200, `allow` |
| PESEL redacted before the model | live, valid PESEL | HTTP 200, `redact`, model saw `[PESEL]` |
| Polish injection blocked | live | HTTP 403, `injection.heuristic` |
| Zero budget stops the call | live, `wk_budget_demo` | HTTP 429, `budget.usd`, model not called |
| Tool outside allow-list blocked | live, `research-agent` asks model for `transfer_funds` | HTTP 403, `tools.allowlist` |
| Gateway overhead | `X-AgentShield-Overhead-Ms` on the 5 live calls above; `/api/snapshot` | 0.7 to 1.5 ms per call; snapshot p50 without judge 1.25 ms; with judge p50 about 630 ms |
| Posture | `/api/snapshot` | 100 / 100, grade A, no open gaps |
| Console | live root `/app/` | Demo tab with a 9-scenario attack deck (keys 1 to 9) and Console tab (approvals, agents and kill switch, policy editor, audit integrity and tamper drill) |

The detectors-off flow demo, payment approval, broken-YAML reload and audit tamper drill run in `demo/run_demo.sh` and the dashboard, and are covered by the test suite. They use admin endpoints, so they were not exercised against the live deployment for this text.

**What we finish by Sunday 11:00.**

- Judge benchmark: candidate judge models on our own grey-zone traffic (`demo/bench_judge.py` to `docs/JUDGE_BENCHMARK.md`).
- MCP proxy (`/mcp/{server}`) with tool pinning against rug-pull changes, in the code and tests now, to be wired into the demo.
- Final 3-minute pitch, 2-minute live demo, demo video (`docs/PITCH.md`, `docs/DEMO_VIDEO.md`).
- Refresh the README (it still says the MCP proxy is not in the tree). The public deployment already requires an admin token; `scripts/smoke.sh` checks it after every deploy.

**Links.**

- Repository: https://github.com/ivanshevchuk0/AgentShield (branch `warden-core`)
- Live demo: https://agentshield-demo-production.up.railway.app

**Team.** Roman, Tymofii, Ivan Shevchuk, TODO-fourth-member (fill full names before submitting).

### Form version, 500 characters

```text
AgentShield is one control layer in front of any AI agent. It is an OpenAI-compatible proxy that checks every model call and tool call against one hot-reloaded YAML policy: PII redaction, prompt-injection blocking, tool allow-lists, human approval for payments, an information-flow guard, budgets, a kill switch and an HMAC-chained audit log. Live on Railway; 3,709 tests pass; about 1 ms gateway overhead when the judge is not needed. Sunday: judge benchmark, MCP path, pitch.
```

### Form version, 1500 characters

```text
Banks want AI agents that look up customers, read documents, send email and move money. They cannot deploy them while an agent can leak a PESEL or IBAN, follow an instruction hidden in a document, spend without a ceiling, or send a payment with no human check. A system prompt inside the model is not a control.

AgentShield is one control layer that sits outside the agent. The agent keeps its OpenAI client and changes only the base URL. Every chat completion and tool call is authenticated as a named agent and checked against one YAML policy that reloads without restart and keeps the last good version if an edit is broken. Deterministic detectors handle clear cases (PII with checksums, secrets, injection in 5 languages and encoded forms, a signature feed, a canary). An LLM judge is called only in the grey zone and can only raise risk. Tools are allow-listed with argument rules; payments need a single-use human approval; an information-flow guard blocks a customer secret or an untrusted document value from reaching email or a transfer, even with all detectors off. Per-agent budgets are reserved before the upstream call. A kill switch stops an agent. Each decision is appended to an HMAC-chained audit log. Controls are mapped to OWASP LLM Top 10 2025.

Working now: live demo on Railway, 3,709 tests passing, a 137-case corpus with 0 false positives on 60 benign cases, about 1 ms overhead without the judge. By Sunday: judge benchmark, MCP proxy, final pitch and video.
```
