# AgentShield demo video: shot list and narration

Target length 2:30 (hard limit 3:00). Screen recording of the live dashboard at
https://agentshield-demo-production.up.railway.app, 1920x1080, browser zoom 110 %, one terminal window for shot 2 and shot 12.

Before recording:

- Load the dashboard, confirm mode `enforce`, posture 100. Paste the admin token in **Settings** if the deployment needs one.
- Revive any killed agent (Console tab, Agents and budgets).
- Click empty page space so keys 1 to 9 reach the attack deck.
- Record narration separately and lay it over; keep each shot at least as long as its line.
- Do not show the admin token, `.env`, or any real key on screen.

| # | Time | Screen | Action | Narration |
|---|---|---|---|---|
| 1 | 0:00 to 0:12 | Title card: "AgentShield: a control layer for AI agents in banking" | none | "Banks want AI agents that look up customers, read documents and move money. They cannot ship them while an agent can leak personal data, follow injected instructions, or pay without a human. AgentShield is the control layer that sits outside the agent." |
| 2 | 0:12 to 0:22 | Terminal, two lines of Python: `OpenAI(base_url=".../v1", api_key="wk_bank_ops_demo")` | none | "Integration is one line: the agent keeps its OpenAI client and points the base URL at AgentShield. Each agent has its own key and its own policy." |
| 3 | 0:22 to 0:32 | Dashboard, Demo tab, attack deck on the left | Press `1` | "A normal KYC question. Allowed. The gateway added about one millisecond." |
| 4 | 0:32 to 0:44 | Same, Why panel on the right | Press `2`, then `2` | "A PESEL in the prompt is redacted before the model sees it. A number with a bad checksum is left alone, so we do not break every 11-digit string." |
| 5 | 0:44 to 1:00 | Same, pipeline animation | Press `3` four times | "The same injection in English, Polish, base64 and with Cyrillic look-alike letters. All blocked by deterministic rules. The LLM judge was not needed." |
| 6 | 1:00 to 1:25 | Same; zoom on the Why panel on step 3 | Press `5` five times | "Now we switch every detector off. The agent looks up a customer, then tries to email that IBAN to an allowed bank address. Blocked: secret egress. The guard follows where data came from. The same IBAN typed by a user is allowed. Then we switch detectors back on." |
| 7 | 1:25 to 1:32 | Same | Press `6` | "An agent with zero budget. Rejected with 429 before the model is called." |
| 8 | 1:32 to 1:40 | Same; pending badge on the Console tab | Press `7` | "The agent asks to transfer 2,500. It is held for a human." |
| 9 | 1:40 to 1:50 | Console tab, Approvals card | Click **Approve transfer_funds**, go back to Demo tab, press `7` three times | "A person approves. The retry goes through. Replaying the same approval is blocked, and 50,000 is over the cap even with approval." |
| 10 | 1:50 to 2:00 | Demo tab | Press `8` | "Policy is one YAML file reloaded live. A broken edit is rejected and the active policy hash does not change." |
| 11 | 2:00 to 2:10 | Console tab, Agents and budgets | **Kill** `bank-ops-agent`, type the id, confirm; then **Revive** | "One click stops an agent. Every later call is refused until it is revived." |
| 12 | 2:10 to 2:22 | Console tab, Audit integrity card | **Verify now**, then **Run tamper drill** | "Every decision is in an HMAC hash chain. We edit one field in a copy of the log and verification breaks at exactly that record." |
| 13 | 2:22 to 2:32 | Console tab, OWASP coverage card, then title card with repo and live demo links | none | "Controls are mapped to OWASP LLM Top 10 2025, gaps included. 3,709 tests pass offline. It is live now. AgentShield." |

Notes:

- Numbers spoken in shot 13 come from the run on 2026-10-03; re-check `python3 -m pytest -q` before the final cut.
- If a live call fails during recording, re-shoot that shot against a local gateway (`python3 -m uvicorn --factory app.main:create_app --app-dir backend --port 8080`, open `http://localhost:8080`). The deck is identical.
- Optional cut to fit 2:00: drop shots 2, 10 and 11.
