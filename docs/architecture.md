# WARDEN — final architecture (synthesis of 7 reviews, 2026-10-03 ~15:00)

Sources: docs/reviews/r2_*.md (GPT-6.1-sol architect, Opus architect, Opus info-flow, Opus red-team, Grok tests, Grok judge-UX, Grok build plan).
Binding rubric (aicontrol_rules.txt §11): Guardrails 30 · Architecture & perf 20 · Reporting 20 · **Test suite 20** · Implementability 10. Phase-1 floor 50%.
Win condition: **a mentor cannot break it in 8 minutes** — they delete detectors, paste broken YAML, kill the judge, type Polish PESEL / injections, run our suite.

## 1. Decisions (conflicts resolved)

| Topic | Decision | Why |
|---|---|---|
| Models | No GPU. Upstream + judge via **OpenRouter**; `mock/vulnerable-llm` is the default demo upstream; `ollama` backend kept as a config value | Team constraint; demo must survive Wi-Fi loss |
| Judge | Grey zone only `[review, block)`; strict JSON verdict, nonce-delimited input, PII redacted before sending; **can only raise risk**; timeout 1200 ms, breaker 3 fails → open 30 s, own budget line, 10-min cache. Primary `google/gemini-2.5-flash-lite`, fallback `openai/gpt-4o-mini` (verify IDs on openrouter.ai) | Remote model = latency + injection target |
| Judge down | Only grey-zone traffic falls back to `fail_mode`; clean and clearly-bad traffic stay deterministic | "Kill the judge" must not look like an outage |
| Flow guard | Top-level `flow:` (NOT under `controls`), default ON, own value patterns; survives "disable all detectors"; only `flow.enabled: false` turns it off | It is the differentiator; first click must not remove it |
| Tool provenance | Gateway labels tool results it mediates (`/v1/tools/call`, `/mcp/*`); on the chat path the gateway signs every `tool_call_id` it releases (`call_w.<payload>.<hmac>`); unknown/forged id ⇒ untrusted | Client cannot lie about where data came from |
| Approvals | Immediate `403 approval_required` + `approval_id`; human approves on dashboard; agent retries with `X-Approval: <id>`; single-use, bound to tool + canonical args + policy hash, 120 s expiry; never overrides allow-list, kill switch or flow block | No hanging HTTP calls on stage |
| Identity | Agent = API key only (constant-time compare). `allowed_tools` missing/empty ⇒ **no tools**. Mismatching `X-Agent-Id` ⇒ 403 `auth.impersonation` | Task's first listed risk |
| Policy reload | Poll `stat()` every 500 ms + 150 ms debounce; reject empty file, duplicate keys/ids/api keys, unknown refs, `review ≥ block`, unknown actions; **missing control section = disabled** (shown red, in diff); last-good keeps enforcing; per-request snapshot | Red-team items 1–3 |
| Audit | JSONL, each record `hmac_sha256(WARDEN_AUDIT_KEY, prev_hash + canonical_json)`; sidecar `audit.head` (hash + count) catches tail truncation; no raw PII stored (type, offsets, value hash only); tamper demo on `fixtures/tampered.jsonl` | Plain chain can be recomputed |
| Budget | Reserve `max_tokens × price` under a lock before dispatch, settle on usage, keep reservation on upstream error; day spend rebuilt from audit on restart | Race test (50 parallel) |
| Cut | Natural-language policy, shadow replay, OCSF/CEF/framework matrix, 12-way evasion matrix, load-test writeup, Prometheus, Redis, Next.js, consilium, honeytool | 4/4 reviewers |
| Later (after CP5) | MCP tool-description pinning, speculative judge‖upstream, F3–F6 flow rules | Only when everything is green |

## 2. Layout (one process, port 8080)

```
warden/
  config.py      Policy models + validators + PolicyStore (exists; tighten)
  normalize.py   fold(): NFKC, strip Cf/zero-width/bidi/tags, homoglyph map, PL diacritics, lower;
                 candidates(): original, folded, collapsed-spacing, one base64/hex decode (≤4 KiB, printable)
  detectors.py   pii (PESEL/NIP/IBAN/Luhn/email/phone, checksums), secrets, injection (EN/PL/UK/RU/DE weighted),
                 signatures (feeds/signatures.yaml), canary, markdown-exfil; each -> Finding(control_id, start, end, score, via)
  judge.py       Judge(backend: openrouter|ollama|heuristic|stub) + breaker + cache + budget
  flow.py        TaintStore per session: labels, folded spans ≥12 chars, digit-only forms; check_egress(args) -> Finding
  tools.py       allow-list, arg rules (regex / max_values), approvals store (JSONL), kill switch, loop guard
  budget.py      Ledger: reserve/settle/release, rpm/tpm windows, usd/day, judge budget
  upstream.py    mock (scripted vulnerable LLM), openrouter/openai-compatible, ollama
  audit.py       HMAC chain JSONL + head sidecar + verify + report.md builder
  metrics.py     ring buffer 500: p50/p99 overhead split judge/no-judge, counts per control/action, breaker state
  pipeline.py    inspect(text, direction, source, ctx) -> Decision ; chat and tool lifecycles
  app.py         FastAPI routes, auth dependency, reload watcher, static dashboard
  demo_tools.py  lookup_customer (secret), read_document (untrusted, hidden injection), send_email, transfer_funds
dashboard/index.html   single page, polls /api/snapshot every 1 s
feeds/signatures.yaml  historical AI-infra exploits (CVE ids)
tests/                 pytest, offline, stub upstream + stub judge, temp policy copy, fresh audit dir
demo/run_demo.sh       8-step scripted demo (curl), demo/agent.py bank agent loop
```

## 3. Request lifecycle

Chat `POST /v1/chat/completions` (OpenAI-compatible; `stream:true` is buffered, inspected, re-emitted as SSE):
1. Snapshot policy → auth (key → agent) → kill switch → size caps (sum chars, body bytes) → model allow-list (exact, normalised name).
2. Session (`X-Session` or derived) → loop guard (fingerprint of last message; > `max_identical` in window ⇒ block).
3. Label `role: tool` messages by verified `tool_call_id`; feed TaintStore.
4. Inspect each non-system message (user = input, tool = input+`indirect`): deterministic findings → score → block ≥ block_threshold / judge if grey / allow. Redactions applied to forwarded copy.
5. Budget reserve → dispatch upstream → settle.
6. Inspect output text (pii, secrets, canary, markdown-exfil, signatures). For each proposed `tool_call`: allow-list → arg parse (reject duplicate keys, walk all string leaves) → arg rules → **flow check** → approval check → sign id.
7. Audit record → metrics → response with headers `X-Warden-Decision`, `X-Warden-Overhead-Ms`, `X-Warden-Policy`.

Tool `POST /v1/tools/call` (gateway-mediated, used by demo agent and MCP proxy): allow-list → arg rules → flow → approval → execute demo tool / forward to MCP server → label result (secret/untrusted per policy) → scan result for injection → audit.

Block body (403): `{decision, control_id, summary, evidence:{start,end,text_masked,via}, policy_hash, policy_version, audit_seq, approval_id?}`.

## 4. Policy additions

```yaml
semantic: {backend: openrouter, model: google/gemini-2.5-flash-lite, fallback_model: openai/gpt-4o-mini,
           timeout_ms: 1200, usd_per_day: 1.0, api_key_env: OPENROUTER_API_KEY}
controls.pii.entities: [EMAIL, PHONE, PESEL, NIP, IBAN, CREDIT_CARD]
flow:
  enabled: true
  min_chars: 12
  rules: {secret_to_egress: block, untrusted_value_as_target: block, untrusted_before_irreversible: approval}
tools:
  catalog:
    lookup_customer: {labels: [secret]}
    read_document:  {labels: [untrusted]}
    send_email:     {egress: true, target_args: [to], arg_patterns: {to: '^[\w.+-]+@bank\.example$'}}
    transfer_funds: {egress: true, irreversible: true, target_args: [iban], max_values: {amount: 10000}}
agents: [..., {id: budget-demo, api_key: wk_budget_demo, budget: {usd_per_day: 0}}]
kill_switch: []   # agent ids
```

## 5. Tests (`make test` = `pytest -q`, offline, < 10 s)
Corpus `tests/corpus/cases.yaml` (≥130 rows incl. 30 benign banking prompts, Polish) + named tests from r2_grok_tests.md:
allow A01–A09 · redact P01–P11 · secrets S01–S03 · injection I01–I05 · signatures/canary X01–X04 · tools T01–T07 · size L01 ·
reload R01–R07 · budget B01–B05 (incl. parallel race) · judge K01–K06 (timeout, breaker, garbage JSON = max risk, cannot downgrade) ·
flow F01–F07 (detectors off, user-typed value allowed, base64 copy, release header) · audit/loop/monitor C01–C05 + tail truncation.
Report: per-control TPR/FPR + p50/p99 → `reports/last-run.json` (dashboard reads it).

## 6. Dashboard (one page)
Strip (profile, mode, version+hash, last-good/rejected chip, posture score with formula, counts, p50/p99 split, breaker lamp, budgets) ·
Try-it chips (PESEL, NIP, IBAN, injection EN/PL/base64/homoglyph, benign PL, torch.load, read→send flow, transfer, budget-demo) ·
Why-card · live feed · policy panel (toggles, profile, YAML editor, reload banner) · approvals · audit (verify, export JSONL, report.md) · tests panel.

## 7. Demo (8 min, judge drives)
pytest green → benign → PESEL redact (bad checksum allowed) → Polish + base64 injection blocked → **disable all detectors → read_document → send_email blocked `flow.taint`; same IBAN typed by user allowed** → broken YAML, hash unchanged → judge to closed port: grey-zone block < 1.3 s, then breaker → ms → budget-demo blocked, mock counter unchanged → transfer → approval → retry → verify chain ok, tampered fixture fails → report.md.

## 8. Build order (Claude writes code; humans review, test, demo)
- **CP1 16:30**: config hardening, normalize, detectors, pipeline, mock upstream, audit, app; 5 tests (allow, PESEL, bad YAML, 401, budget).
- **CP2 18:00**: corpus ≥60, dashboard v1 (feed + why-card + strip). Rehearsal by non-author.
- **CP3 19:30**: flow + tools/approvals + kill switch; draft submission text + screenshots (P1/P2). **20:00 submit draft.**
- **CP4 00:00**: judge (OpenRouter) + breaker + budget line; signed tool ids; report.md; metrics; corpus ≥130.
- **CP5 04:00**: polish, MCP proxy + pinning if green; streaming SSE re-emit.
- **08:00 freeze** → clean-clone run ×2, slides (8–10), video → **10:30 submit**.
Owners: P1 integration/review + OpenRouter key/credit cap + submission; P2 dashboard; P3 benign/independent tests + demo script + rehearsals.
