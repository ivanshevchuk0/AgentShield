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
| `AGENTSHIELD_AUDIT_KEY` | yes | Stable HMAC key; otherwise `audit.key` is generated in the data directory. Keep the same key across redeploys. |
| `AGENTSHIELD_DATA_DIR` | yes for persistence | Set `/data` and mount a separate Railway volume there for each service. |
| `OPENROUTER_API_KEY` | for the semantic judge | Separate restricted key per service; never paste it into policy, reports or shell history. |

Known exposure on a public URL: the demo policy holds the demo agent keys in clear text, and
`/api/policy/raw` and `/api/audit.jsonl` show them. Acceptable for demo keys only; never put a
real provider key in `policy.yaml`.

### Persistent audit storage

The image defaults to `/app/data`; `AGENTSHIELD_DATA_DIR=/data` overrides it without a rebuild.
Mount a Railway volume at `/data` to preserve the audit chain, its head/key, approvals and kill
switch across redeploys. The process stays non-root (uid/gid 1000). The image prepares `/data`,
but a mount replaces its permissions: ensure the mounted directory is owned by `1000:1000`
before starting the service. Do not solve permission errors by running the gateway as root.
Never share a volume between demo and test services. A redeploy preserves daily spend and kill
switch state on a volume; it is not a full reset. Verify the chain after redeploying.

### Free test-service judge (not the jury service)

On **agentshield-test only**, open the authenticated policy editor and change these fields in
`semantic`, leaving the other thresholds and controls intact:

```yaml
backend: openrouter
model: inception/mercury-decide:free
fallback_model: null
base_url: https://openrouter.ai/api/v1
api_key_env: OPENROUTER_API_KEY
trigger: suspicious
```

Keep all testers on `mock/vulnerable-llm`. In the test policy, restrict every agent's
`allowed_models` to `[mock/vulnerable-llm]` (including agents whose list was absent). This
prevents testers from accidentally calling a paid upstream. Use a separate OpenRouter key
restricted to free models with no paid fallback. Confirm the exact `:free` model is available
and priced at zero in OpenRouter before enabling it; availability and free-tier rate limits
can change. If unavailable, use `semantic.backend: heuristic` for offline tests, not a paid
fallback. Keep `fail_mode: closed`; free-tier timeouts may block grey-zone prompts and are
not proof of a bypass. Internal judge budget accounting may still report estimated spend.

Policy edits in the container filesystem are not persisted by the audit volume. Reapply and
verify the test-only policy after each redeploy, or provision a persistent policy via
`AGENTSHIELD_POLICY`. Do not change the jury service's judge for this test plan.

### Smoke after every deploy

From the repository root, with Bash 3.2+ and Python 3 (stdlib only):

```bash
# Load AGENTSHIELD_ADMIN_TOKEN through your secret manager/environment, not a CLI argument.
./scripts/smoke.sh https://<test-host>
make smoke BASE_URL=https://<demo-host>
# Local gateway with no configured admin token:
./scripts/smoke.sh http://127.0.0.1:8080
```

Run after **every** test/demo deploy, and again before the pitch. Export the service's admin
token for a public deployment: smoke then requires an unauthenticated admin request to get
401 and checks that the supplied token works. Without a token, an unprotected local server
prints a warning and skips the 401 assertion; that warning is **not acceptable for a public
service**. A protected server still gets its unauthenticated 401 check without a supplied token.

Each check prints PASS/FAIL; any failure gives a non-zero exit. Checks cover health, root
redirect, HTML/CSP, admin authentication, benign chat, PESEL redaction, deterministic injection,
secret-to-email flow block, zero budget and the live audit chain. These expect the standard
enforcing policy, active demo agents and available daily budget. No remote model is needed.
Smoke never toggles detectors, changes policy, approves calls or flips kill switches, so no
configuration needs restoring. It creates a unique session and ordinary audit/budget records;
it deliberately does not erase those records. The flow check uses the synthetic customer IBAN
and leaves detectors enabled; the separate demo covers the detectors-off scenario.

CI runs the offline suite on Python 3.11/3.12 and builds the image, starts it as non-root with
an admin token and a `/data` volume, then runs this same smoke script. The container and its
anonymous volume are removed even if a check fails.

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
| Sunday 10:00 | Redeploy demo service, run `scripts/smoke.sh` then `run_demo.sh` against it once, tag `v1.0-hackyeah` |
