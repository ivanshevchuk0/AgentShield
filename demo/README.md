# AgentShield demo

Everything runs offline: the upstream model is `mock/vulnerable-llm` (a deterministic,
deliberately vulnerable model) and the demo tools are in-memory simulators.

## 1. Start the gateway

```bash
cd <repo>
pip install -r backend/requirements.txt
cd backend && PORT=8080 python3 -m app.main
# or: cd backend && uvicorn app.main:create_app --factory --port 8080
```

Set `AGENTSHIELD_ADMIN_TOKEN` before starting the gateway, and export the same value
before running the demo scripts. They send it as `X-Admin-Token` on console/admin calls.
Enter it in the dashboard Settings too. Without a token the console APIs are disabled.

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
