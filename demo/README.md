# Sealdesk demo

Everything runs offline: the upstream model is `mock/vulnerable-llm` (a deterministic,
deliberately vulnerable model) and the demo tools are in-memory simulators.

## 1. Start the gateway

```bash
cd <repo>
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r backend/requirements.txt
export AGENTSHIELD_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
printf 'Local admin token: %s\n' "$AGENTSHIELD_ADMIN_TOKEN"
python3 -m uvicorn --factory app.main:create_app --app-dir backend --port 8080
```

Keep the server running. In another terminal, return to the repository root and run:

```bash
source .venv/bin/activate
export AGENTSHIELD_ADMIN_TOKEN='<same token printed by the server terminal>'
```

Enter that same private token in dashboard Settings too. The scripts send it as
`X-Admin-Token` on console/admin calls. Without a configured token the console APIs
return 503; a missing or incorrect client token returns 401. Do not use a public demo
agent key as the admin token.

Dashboard: http://localhost:8080/ . For the judge's grey-zone calls set `OPENROUTER_API_KEY`
(optional; without it the judge reports `error` and grey-zone traffic follows `fail_mode`).

## 2. Run the test suite first

```bash
python3 -m pytest -q                      # all tests, offline
python3 -m pytest -q tests/test_corpus.py # labeled corpus -> reports/last-run.json
```

## 3. Scripted demo (curl, 8 steps)

```bash
./demo/run_demo.sh                       # http://localhost:8080
PAUSE=1 ./demo/run_demo.sh               # wait for Enter between steps (live)
GW=http://other-host:8080 ./demo/run_demo.sh
```

| Step | What happens | Expected |
|---|---|---|
| 1 | benign KYC question | 200 allow |
| 2 | Polish prompt with PESEL 44051401359 (and a bad-checksum number) | 200, `[PESEL]` forwarded, bad number untouched |
| 3 | Polish injection, then the same phrase in base64 | 403 `injection.*` |
| 4 | all detectors OFF, `lookup_customer` then `send_email` with its IBAN; poisoned `invoice-7` then mail to `audit@evil.example`; repeat the IBAN in a different session | 403 `flow.*`, 403, then 403 |
| 5 | broken YAML via `POST /api/policy` | rejected, policy hash unchanged, still enforcing |
| 6 | `budget-demo` agent (usd_per_day 0) | 429 `budget.*`, no upstream call |
| 7 | `transfer_funds` -> approval id -> approve -> retry with `X-Approval`; replay; amount over limit | 403, 200, 200, 403, 403 |
| 8 | audit chain verify, tampered fixture, report.md | ok / broken / markdown |

Step 5 never writes `backend/policy.yaml`: the API validates the YAML first and only a valid
policy is written, so the file on disk is never left broken. (To show the file watcher live,
edit the file by hand in an editor during the demo; an invalid save is rejected and the
last good version keeps enforcing.)

The approval example uses a different synthetic IBAN from the earlier secret
customer record. Human approval does not override a flow block on protected data.

### Attack → protection → audit walkthrough

For the jury, run `PAUSE=1 ./demo/run_demo.sh` and keep the dashboard open:

1. **Establish normal behavior (step 1):** a harmless KYC question returns 200. The gateway is useful, not just an always-blocking filter.
2. **Show the attack (step 4):** the agent reads a fake customer record, then tries to email its IBAN to an otherwise allowed `bank.example` recipient. The script temporarily disables detectors so the independent policy boundary is visible.
3. **Show the protection:** the tool call returns 403 with `flow.secret_egress`. The email mock does not execute. Changing `X-Session` still returns 403; the authenticated agent cannot reset its exposure by renaming a session. The script restores detectors afterward.
4. **Show the evidence (step 8):** find the blocked decision in the dashboard's audit view and inspect its control, reason, and masked evidence. The live audit-chain verification succeeds; the deliberately edited fixture fails verification without changing the real log.

You can also verify the live audit chain independently:

```bash
curl -sS http://localhost:8080/api/audit/verify \
  -H "X-Admin-Token: $AGENTSHIELD_ADMIN_TOKEN" | python3 -m json.tool
```

All customer records, email sends, and payments are fake. The takeaway is: do not
trust the AI agent; enforce permissions and data handling outside it, then record
the result. A valid audit chain proves log integrity, not perfect attack detection.

## 4. Agent loop

```bash
python3 demo/agent.py                    # all scenarios
python3 demo/agent.py --scenario exfil   # benign | lookup | leaks | injection | exfil | payment
python3 demo/agent.py --auto-approve     # approve payments without the dashboard
```

The agent (key `wk_bank_ops_demo`) calls `/v1/chat/completions`; tool calls proposed by the
model go through `/v1/tools/call`, and every gateway decision is printed
(`HTTP status, ACTION, control id, OWASP tag, overhead`). In the `payment` scenario it waits up to
60 s (`--approval-wait`) for a human to approve the transfer on the dashboard, then retries.

Demo keys (from `backend/policy.yaml`): `wk_judge` (chat only), `wk_bank_ops_demo` (tools),
`wk_research_demo` (read_document only), `wk_budget_demo` (zero budget).
