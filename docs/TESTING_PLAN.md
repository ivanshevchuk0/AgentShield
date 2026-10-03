# Testing plan: hosted gateway, three testers

The gateway runs on Railway. Each tester points their own harness (Codex, Grok, Cursor) at it
and tries to break it. Local `pytest` stays the gate for every commit; this plan covers what
unit tests miss: real clients, real network, real UI.

## Environments

| Service | Branch | Purpose | Reset |
|---|---|---|---|
| `agentshield-demo` | `warden-core` (later `main`) | Jury demo. Nobody attacks it. | Redeploy before the pitch |
| `agentshield-test` | `warden-core` | Attack target for testers | Redeploy whenever state gets noisy |

Both deploy from `Dockerfile` (`railway.json` sets the health check on `/health`; Railway's
`PORT` is honoured).

Variables on each service:

| Variable | Required | Note |
|---|---|---|
| `AGENTSHIELD_ADMIN_TOKEN` | yes | Without it every admin route (policy edit, kill switch, approvals) is open to the internet |
| `AGENTSHIELD_AUDIT_KEY` | yes | HMAC key of the audit chain; otherwise a per-boot key is used |
| `OPENROUTER_API_KEY` | for the semantic judge | Set a hard spend limit on this key in OpenRouter |

Known exposure on a public URL: the demo policy holds the demo agent keys in clear text, and
`/api/policy/raw` and `/api/audit.jsonl` show them. Acceptable for demo keys only; never put a
real provider key in `policy.yaml`.

## Who tests what

**Tester A — agent harness (Codex or Grok).** Configure the harness as an OpenAI-compatible
client: base URL `https://<test-host>/v1`, API key `wk_bank_ops_demo`, model
`mock/vulnerable-llm`. Then:

1. `GW=https://<test-host> ./demo/run_demo.sh` must pass all 8 steps.
2. `python3 demo/agent.py --gateway https://<test-host>` must pass.
3. Streaming: the same prompt with `stream: true` must give the same decision as without it.
4. Tool calls through `/v1/tools/call`: transfer without approval gets 403 plus `approval_id`;
   approve it in the console; retry with `X-Approval`; a second retry with the same id fails.
5. Budget: `wk_budget_demo` must get 429.

**Tester B — red team (Cursor or Grok).** Ask the model to generate bypass attempts, send them
through the gateway, and log every miss:

- Prompt injection in EN/PL/UK/RU/DE, base64, hex, zero-width characters, homoglyphs, and
  instructions split across messages.
- PII written with spaces, dots or full-width digits (PESEL, IBAN, card numbers, phone numbers).
- Secret leakage: API keys in tool arguments, secrets in model output.
- Data-flow: read a secret, then call an outbound tool in the same session; it must be blocked.
- Forged or replayed tool-call ids, and arguments changed after approval.
- Garbage input: huge bodies, invalid JSON, non-ASCII keys in `Authorization`, empty messages.
  Any 500 counts as a bug.

**Owner — UI and operations.** Two tabs (demo, console): live feed, why-card, approvals inbox,
kill switch, policy editor (an invalid edit must keep the last good policy), audit
verify/tamper drill, dark mode, phone width.

## Reporting

One GitHub issue per finding, label `bug` or `bypass`, with:

```
Request: curl … (or the exact harness prompt)
Expected: block / redact / 403 / 429
Actual: status + response body
Audit record seq: …
```

Bypasses that the gateway misses become new rows in `tests/corpus/` before they are fixed,
so the fix is proven by a failing test turning green. Fixes go through PRs into `warden-core`.

## Schedule

| When | What |
|---|---|
| Saturday, before 20:00 | Test service up, A and B start; interim submission from the demo service |
| Saturday night | Fix wave on the filed issues; redeploy test service |
| Sunday 08:00 | Freeze. Only demo-blocking fixes after this |
| Sunday 10:00 | Redeploy demo service, run `run_demo.sh` against it once, tag `v1.0-hackyeah` |
