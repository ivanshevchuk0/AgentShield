# UX Concept A: "The Glass Gateway". Jury storytelling in 8 minutes

Angle: a Goldman Sachs judge has about 8 minutes and has already seen many teams that day. Within
the first 20 seconds they should know three things: **what is being protected** (a bank agent's
data and money), **who decides** (AgentShield, outside the model), and **what proves it** (a
decision record and a chain that breaks when someone tampers with it). After that the judge drives.

Facts in this doc come from `docs/CONTRACTS.md`, `docs/architecture.md`, `docs/PITCH.md`,
`demo/README.md`, `backend/app/main.py`, `backend/app/engine.py` (`snapshot()`, `build_record`),
`backend/app/posture.py` and the current `frontend/index.html`. Anything the backend does not
provide today is marked **[ASK]** and collected in section 4.8.

---

## 1. Core concept and design principles

**Concept.** The gateway is drawn as a glass box. Every request the judge fires travels left to
right through a visible pipeline of stages. Each stage lights up, stays dark or is skipped, and
the stage that decides stamps the verdict. A *verdict sentence* sits under the pipeline, and an
*evidence rail* on the right links that verdict to its audit link. The screen should read like a
trade blotter plus a circuit diagram. It should not look like a SaaS marketing dashboard.

**The verdict sentence** is the main unit of the UI. Every decision is rendered as one line a
risk officer could read aloud:

> **BLOCKED** · `flow.secret_egress` · IBAN read by `lookup_customer` reused in `send_email.body`
> · 2.8 ms · judge not called · policy v14 `a91f03c2be71` · audit #212 sealed

Principles (opinionated):

1. **The judge drives and we narrate.** Every money moment is one click or one keystroke, and
   each also has a free-text box the judge can type into. A preset that only we control proves
   nothing.
2. **Measured numbers, choreographed motion.** The pipeline animation is a replay of the record,
   labelled as a replay. The ms figures are the real `timings_ms`. We never invent per-detector
   latency the backend does not measure. GS people will ask, and the honest answer is a selling
   point.
3. **Stay deterministic when we can, and say so.** The judge stage shows `skipped` most of the
   time, drawn as a dashed bypass. "The LLM judge was not needed" is the line that shows the
   architecture works.
4. **Never show a raw secret.** We render only `evidence` (already masked) and highlight
   `start`/`end` on text the judge typed in this browser. Server text is always inserted via
   `textContent`.
5. **One dominant colour per state.** Red means stopped, amber means a human is needed, violet
   means changed in flight (redact), green means passed, grey means off or not involved. Nothing
   decorative uses these colours.
6. **Projector first.** Design for 1366×768 at 125% zoom over a washed-out projector. Use large
   type, heavy contrast and no 11px grey-on-grey.
7. **Keep the operator view.** The existing dense dashboard is still useful. It becomes the
   "Ops" tab instead of being thrown away.

---

## 2. Information architecture

One page at `/` with hash routes and no reloads. Two modes share all components:

- **Stage** (`#/stage`, the default when `?stage=1` or on key `S`): jury mode. Large type, one
  focal pipeline, the attack deck and the evidence rail. Feed and toggles are collapsed.
- **Ops** (`#/ops`): the current dense dashboard (strip, feed, toggles, budgets, tests),
  restyled.

Tabs (top bar, keys `1`–`6`):

| Key | View | Purpose | Main endpoints |
|---|---|---|---|
| 1 | **Live** (Stage home) | attack deck, pipeline theater, verdict, evidence rail | `/api/try`, `/v1/tools/call`, `/v1/chat/completions`, `/api/snapshot` |
| 2 | **Policy** | YAML editor, toggles, profiles, reload timeline, before/after diff | `/api/policy/raw`, `POST /api/policy`, `/api/policy/toggle`, `/api/policy/profile/{name}`, `/api/policy/detectors-off|on` |
| 3 | **Approvals** | pending queue with TTL, kill switch per agent | `/api/approvals`, `POST /api/approvals/{id}`, `POST|DELETE /api/kill/{agent_id}` |
| 4 | **Audit** | chain ribbon, verify, tamper fixture, export, report | `/api/audit/verify`, `/api/audit/verify-fixture`, `/api/audit.jsonl`, `/api/report.md`, `/api/events` |
| 5 | **Posture** | score + formula, gaps, OWASP LLM 2025 grid, budgets | `snapshot.posture`, `snapshot.budgets`, **[ASK] coverage** |
| 6 | **Proof** | test suite results, per-control TPR/FPR, p50/p99 | `/api/tests`, `snapshot.latency` |

**Above the fold (Live, 1366×768):**

1. **Shield bar** (sticky, 56px): `AgentShield` · posture grade+score · mode (`enforce` /
   `monitor`) · policy `v{version} {hash[:12]}` with last-reload chip · judge lamp (`breaker`) ·
   p50/p99 overhead · chain status · pending approvals badge · connection dot.
2. **Attack deck** (left, 300px): 7 numbered "money moment" cards plus a free-text input.
3. **Pipeline theater** (centre): stage nodes, a packet animation, the stamp and the verdict
   sentence.
4. **Evidence rail** (right, 340px): why-card (control, OWASP, masked evidence, via, findings),
   then the last 5 audit links of the chain, with the newest just sealed.

Below the fold: live feed (24 rows, filter chips), so the judge sees the history of their own
attacks.

---

## 3. Key screens

### 3.1 Grid and global layout

12-column grid, 24px gutters, max content width 1600px. Stage mode uses a 3-zone CSS grid:
`grid-template-columns: 300px minmax(560px,1fr) 340px`. Below 1200px the evidence rail drops
under the theater. Below 800px (a judge's phone) only the attack deck and verdict sentence show.
Spacing scale: 4/8/12/16/24/32/48.

### 3.2 Live / Stage home

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ ◆ AgentShield   POSTURE A 94   ENFORCE   policy v14 a91f03c2be71 ✓applied 3s   JUDGE ● closed │
│                 p50 1.9ms p99 6.4ms   CHAIN ✓ 212 linked   ⚑ 1 approval      ● live          │
├───────────────────────┬──────────────────────────────────────────────┬───────────────────────┤
│ ATTACK DECK           │ PIPELINE  (replay of record #212)            │ WHY                   │
│ ┌───────────────────┐ │                                              │ ■ BLOCKED             │
│ │1 Leak a PESEL     │ │ AUTH ─ KILL ─ LIMITS ─ VIEWS ─┬ PII ──┐      │ flow.secret_egress    │
│ └───────────────────┘ │  ✓      ✓      ✓      4 views ├ SECRETS┤     │ OWASP LLM06 Excessive │
│ ┌───────────────────┐ │                               ├ INJECT ├─ JUDGE ─ FLOW ─ TOOLS ─  │
│ │2 Polyglot inject  │ │                               ├ SIGS  ─┤  ┄┄skip┄  ■■■   ·       │
│ └───────────────────┘ │                               └ CANARY ┘                          │
│ ┌───────────────────┐ │      ──▶ BUDGET ─ MODEL ─ OUTPUT ─ SEAL                           │
│ │3 Pull the plug    │ │            ·       ·       ·       #212                           │
│ └───────────────────┘ │                                              │ evidence              │
│  4 Rewrite the rules  │ ┌──────────────────────────────────────────┐ │ "…IBAN: PL61 •••• ••••│
│  5 Empty wallet       │ │ BLOCKED  flow.secret_egress              │ │  •••• 2874…"          │
│  6 Move money         │ │ IBAN from lookup_customer → send_email   │ │ via digits  ⓘ         │
│  7 Forge the record   │ │ 2.8 ms · judge not called · v14 · #212   │ │ also: —               │
│ ───────────────────── │ └──────────────────────────────────────────┘ │ CHAIN                 │
│ ▸ type anything…  [⏎] │  detect 0.9 │ judge — │ upstream — │ total 2.8 │ #208─#209─#210─#211─#212│
│ agent: wk_judge ▾     │  (stacked latency bar, real timings_ms)       │                ✓ sealed│
├───────────────────────┴──────────────────────────────────────────────┴───────────────────────┤
│ FEED  [All][Block][Redact][Approval][Allow]   #212 13:41:07 tool bank-ops BLOCK flow.secret… │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Pipeline nodes** map 1:1 to the request lifecycle in `architecture.md` §3. They light up from
record fields only:

| Node | Lights when | Data |
|---|---|---|
| AUTH | always passed unless `primary.control_id` starts `auth.` | `agent_id` |
| KILL | `tools.kill_switch` finding | `policy.kill_switch` |
| LIMITS | `limits.input_size`, `model.not_allowed`, `loop.*` | |
| VIEWS | any finding with `via != "original"`, which shows the decoded view name (`base64`, `folded`, …) | `findings[].via` |
| PII / SECRETS / INJECT / SIGS / CANARY | finding with that `control_id` prefix; greyed + strike when in `detectors_disabled` | `findings[]`, `detectors_disabled` |
| JUDGE | `judge` ∈ {`allow`,`block`} = called; `skipped` = dashed bypass; `timeout`/`circuit_open`/`error`/`budget` = amber lamp + label | `judge`, `timings_ms.judge` |
| FLOW | `flow.*` finding; drawn with a thicker border and an **"independent"** tag, because it survives detectors-off | |
| TOOLS | `tools.*` (allowlist, args, max_value, approval) | `approval_id` |
| BUDGET | `budget.*` | `cost_usd`, `tokens_in` |
| MODEL | `timings_ms.upstream` present = called; absent = "not called" (the budget proof) | `model`, `timings_ms.upstream` |
| OUTPUT | output-direction findings (`direction == "output"`) | |
| SEAL | always; shows `seq` and the first 8 chars of `hash` | `seq`, `hash`, `prev` |

Node states: `idle` (outline), `pass` (thin green tick), `hit-redact` (violet fill),
`hit-block` (red fill + stamp), `hit-approval` (amber fill), `off` (grey hatch, strike, tooltip
"disabled by override"), `skipped` (dashed outline + bypass arc), `not-reached` (30% opacity:
everything after the deciding node on a block).

Deterministic detectors are drawn as a **parallel fan** (PII…CANARY in a column) because they run
on the same views. That is accurate, and it also makes the "VIEWS → 4 detectors at once" step
easy to read. Latency is shown only at the group level: `detect`, `judge`, `upstream`, `total`
as a stacked bar under the theater. **[ASK-S]** optional per-detector timings would allow
per-node ms, but we should ship without it.

**Motion.** On a new record: the packet travels at 90ms per stage, deciding node pulses for
300ms, the stamp drops (scale 1.15 to 1, 180ms, `cubic-bezier(.2,.9,.3,1.2)`), then the verdict
sentence types in instantly (no typewriter, which wastes jury time). The whole replay stays under
1.4s. A **"⟲ replay"** button reruns it. `prefers-reduced-motion`: no packet, nodes switch state
instantly. A tag in the corner reads "replay · timings measured". A new record arriving during a
replay is queued, not interrupted.

**States:**

- *Empty* (fresh boot): the pipeline is drawn idle, and the verdict area reads "Fire anything
  from the deck, or type your own. Nothing reaches the model without passing here." Under it
  is a 1-line explainer of the bank agent: "bank-ops-agent can look up customers, read documents,
  send e-mail and move money."
- *Loading* (request in flight): the packet sits pulsing at AUTH and the deck card shows a
  spinner. The 2s safety timeout leads to the error state.
- *Error* (network / 5xx / non-record body): an outlined red banner with the HTTP status and
  `errMsg`, the pipeline frozen and a "Gateway unreachable, last snapshot 4s ago" chip in the
  shield bar. Never a blank screen.
- *Blocked* (403 `agentshield_blocked`, 429 `budget.*`, 401 `auth.*`): red stamp with the HTTP
  code in small caps (`403`, `429`, `401`), so finance people see it is real HTTP.
- *Redacted*: violet stamp. The verdict shows **what the model actually received**: the judge's
  text with the `start..end` spans replaced by `[PESEL]` chips. This is the before/after moment.
- *Approval required*: amber stamp, a TTL ring counting down from `expires_at`, and the Approvals
  badge in the shield bar bounces once. An inline "Open approval →" button jumps to tab 3.
- *Approved / retried*: green stamp plus a small "consumed approval apr_…" chip.
- *Monitor mode*: stamp outline only, labelled "WOULD BLOCK (monitor)", to show `mode: monitor`
  honestly.

### 3.3 Policy view

```
┌ POLICY ─────────────────────────────────────────────────────────────────────────────────┐
│ IN FORCE v14 a91f03c2be71  profile [dev][standard●][strict]   [Detectors OFF] [ON]      │
├──────────────────────────────────────┬───────────────────────────────────────────────────┤
│ policy.yaml (editor, mono 15px)      │ RELOAD TIMELINE                                   │
│ 12  controls:                        │ 13:40:51 ✓ applied v14 a91f03 changed: pii.action │
│ 13    pii:                           │ 13:40:12 ✗ rejected  dup key 'pii' (line 14)      │
│ 14      action: block   ◀ changed    │          hash stayed a91f… · last-good enforcing  │
│ …                                    │ 13:38:02 ✓ applied v13 77c0de                     │
│ [Validate & apply ⌘⏎] [Break it ⚠]   ├───────────────────────────────────────────────────┤
│                                      │ CONTROLS  (toggle = runtime override)             │
│ ✓ applied in 412 ms                  │ pii        redact  [■■□] on                       │
│   (POST → snapshot hash moved)       │ secrets    block   [■■□] on                       │
│                                      │ injection  block   [■■□] on                       │
│                                      │ flow       independent [■■■] on                   │
│ BEFORE / AFTER  (same input re-run)  │ semantic   grey-zone   [■■□] on                   │
│ v13: REDACTED pii.pesel              │                                                   │
│ v14: BLOCKED  pii.pesel              │                                                   │
└──────────────────────────────────────┴───────────────────────────────────────────────────┘
```

- Editor: a plain `<textarea>` with a line-number gutter (a CSS counter on a mirrored `<pre>`).
  No CodeMirror. Dirty lines are marked by diffing against the last loaded text line by line.
- `POST /api/policy` → 200 `{status:"applied", version, hash, changed}` or 400
  `{status:"rejected", error, rejected_hash, hash}`. On reject, **the header hash chip shakes and
  stays the same value**, and a red line in the timeline quotes `error`. That is the whole "broken
  save does not become policy" story in one frame.
- **"Break it"** button: inserts a duplicate `pii:` key into a copy of the current text and
  POSTs it. It is one click for the judge, who can also type garbage themselves.
- **Time-to-effect** counter: time from POST response to the moment `snapshot.policy.hash` equals
  the returned `hash`. Through the API this is immediate (show ms). For a hand edit of the file in
  an editor (the `demo/README` note), the counter starts when the tab notices `last_reload.ts`
  changing and shows "applied 0.6 s after save" using `last_reload.ts - (file mtime)` →
  **[ASK-P]** add `last_reload.detected_ts` (stat change seen) so we can show
  "detected → applied" honestly.
- **Before / after**: the Policy view remembers the last Live input (text + agent). After an
  applied change a "Re-run last attack under v14" button fires the same `/api/try`, and the two
  verdict sentences stack with the changed part highlighted.

### 3.4 Approvals view

```
┌ APPROVALS ────────────────────────────────────────────────────────────────────┐
│ ⚑ PENDING                                                                     │
│ ┌───────────────────────────────────────────────────────────────────────────┐ │
│ │ ◔ 1:47  transfer_funds  by bank-ops-agent   apr_7c1e…                      │ │
│ │ why: untrusted content in session (read_document invoice-7)                │ │
│ │      → flow.untrusted_before_irreversible                                  │ │
│ │ args hash 4be9…  policy a91f03…  single-use · bound to these args          │ │
│ │                         [ Deny ]   [ Approve ⏎ ]                           │ │
│ └───────────────────────────────────────────────────────────────────────────┘ │
│ RECENT  apr_51aa consumed · apr_0f2d expired · apr_9b10 denied                │
├───────────────────────────────────────────────────────────────────────────────┤
│ KILL SWITCH   bank-ops-agent ● active [Kill]   research ● active [Kill] …     │
└───────────────────────────────────────────────────────────────────────────────┘
```

The TTL ring is computed from `expires_at - now`. At 0 the card greys to "expired" without
waiting for the server. Approve needs a deliberate press (button or `Enter` when focused) and
goes to `POST /api/approvals/{id} {approve:true}`. 409 means "already decided / expired" and is
shown inline. The *why* line comes from the matching record's `primary`, found by `approval_id`
in `recent`.

### 3.5 Audit view: the chain ribbon

```
┌ AUDIT CHAIN ────────────────────────────────────────────────────────────────────────────┐
│ LIVE CHAIN  ✓ ok · 212 records · head 9c4e…   [Verify now] [Export JSONL] [report.md]   │
│ ◻#205─◻#206─◻#207─◻#208─◻#209─◻#210─◻#211─■#212                                         │
│   each link: seq · action colour bar · hash[:6] · hover = prev→hash                     │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ TAMPER TEST  fixture: record 2 rewritten block → allow after signing                    │
│ ◻#1 ─── ◻#2 ─╳─ ◻#3 ─── ◻#4         [Run tamper test]                                  │
│          ▲ "block" → "allow"   verify: ok=false · broken_at 2 · reason: hash mismatch   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

Links are 64×40 tiles joined by 2px connectors. On a broken verify the connector after
`broken_at` snaps: it animates to a gap with a red ╳, the tiles to its right desaturate, and the
shield bar's CHAIN chip flips to red. Data: `GET /api/audit/verify` → `{ok,count,broken_at,reason}`.
`GET /api/audit/verify-fixture` → same plus `fixture`, `tampered`.

### 3.6 Posture view

Big grade letter (A–F) + score. Next to it, the **formula is rendered as a sum**: one horizontal
bar per `posture.controls[]` showing `contribution / weight`, labelled with its `owasp` tag, so
"why 94 and not 100" is visible. `gaps[]` is listed in plain words underneath. A 10-cell
**OWASP LLM 2025 grid** (LLM01…LLM10) uses `covered` / `partial` / `gap`, and LLM04/08/09 are
honestly shown as gaps. **[ASK-C]** `posture.coverage()` exists but is not in the snapshot;
expose it. Budget meters per agent: `usd_used / usd_limit`, with `budget-demo` at `0.00 / 0.00`.

---

## 4. Money moments (the 8-minute script, judge-driven)

Each card on the attack deck = one moment. It is numbered so we can say "press 3". Each one
shows a 1-line *claim* before firing and a 1-line *proof* after. Target is about 60s each. Keys
`1`–`7` fire them when Stage is focused, so you don't need to hit them with a trackpad on
someone's laptop.

### M1. "Type your own PESEL" (redaction with checksums), about 45s
- Claim: "PII is stopped before the model, and we check checksums, not regex shapes."
- Action: the judge types any sentence with a PESEL (prefilled hint `44051401359`, valid). Then
  they change the last digit (`…58`).
- API: `POST /api/try {agent_key:"wk_judge", text, direction:"input"}` → record.
- Proof UI: violet REDACTED stamp. "What the model received" row with `[PESEL]` chip over
  `primary.start..end`. On the bad checksum: green ALLOWED, and the PII node shows "pattern seen,
  checksum failed → not PII". **[ASK-1]** That label needs the detector to emit a non-acting
  finding (e.g. `detail:"checksum_failed"`). Without it we show plain ALLOWED and narrate.

### M2. "Polyglot injection" (multilingual + obfuscation), about 60s
- Claim: "Polish, Ukrainian, base64, homoglyphs, zero-width characters. The same instruction is
  caught every time, without an LLM."
- Action: a card cycles through 4 variants of one instruction (EN → PL → base64 → homoglyph or
  zero-width), one per press. The judge can paste their own.
- API: `/api/try`.
- Proof UI: red BLOCKED, the VIEWS node lights with the decoded view name from `primary.via`
  (`base64`, `folded`), and the why-card says "found only after decoding". JUDGE node is dashed
  **skipped**, and the latency bar shows `judge —`. Line: "no model was needed for this."
- Grey-zone variant (optional, only with `OPENROUTER_API_KEY`): a soft paraphrase that the judge
  scores. The JUDGE node lights, `timings_ms.judge` dominates the bar, and the shield bar's
  `p50_judge_ms` updates. Without a key the node shows amber `error` and the verdict follows
  `fail_mode`. That is honest and still a strong moment ("judge down is not an outage").

### M3. "Pull the plug" (flow guard survives detectors-off), about 90s. **The differentiator.**
- Claim: "Turn off every detector. The agent still cannot exfiltrate customer data."
- Action sequence (one card, 4 sub-steps shown as a mini stepper):
  1. `POST /api/policy/detectors-off`. The fan nodes go grey-hatched, FLOW stays lit with its
     "independent" tag, and posture drops visibly (the score animates down).
  2. `POST /v1/tools/call` `lookup_customer {customer_id:"C-1001"}` (Bearer `wk_bank_ops_demo`,
     `X-Session: <stage session>`). Allowed. The session panel gains a `secret` taint label.
  3. `send_email {to:"ops@bank.example", body:"…IBAN PL61…"}`: an **allowed recipient**, yet
     red BLOCKED `flow.secret_egress`.
  4. "Typed by a human" control: a new session, then the same IBAN typed in the body →
     ALLOWED. Line: "same bytes, different provenance."
  - Optional 5: `read_document invoice-7` → `send_email to audit@evil.example` →
    `flow.untrusted_target`.
- Proof UI: a **session taint strip** above the pipeline, `session dash-x1y2: [secret ← lookup_customer] [untrusted ← read_document]`.
  It is built client-side from the tool records in this session (we issued them, so we know
  them). **[ASK-T]** nice-to-have: `GET /api/session/{id}/taint` returning labels and sources
  (not values), so it is server truth.
- End of moment: one click "Detectors ON" (`/api/policy/detectors-on`).

### M4. "Rewrite the rules live" (policy as code, hot reload, last-good), about 75s
- Claim: "Policy is a file. A good change applies in under a second. A broken one never becomes
  policy."
- Action: (a) **Break it** → `POST /api/policy` with a duplicate key → 400, hash chip shakes and
  stays the same, timeline shows the error. (b) The judge changes `pii.action: redact → block`
  (or clicks profile **strict**: `POST /api/policy/profile/strict`) → 200 with `changed` list.
  (c) "Re-run last attack" → before/after stack: `v13 REDACTED` / `v14 BLOCKED`.
- Proof UI: time-to-effect ms, version bump, and an every-decision footer showing the new
  `policy_version`/`policy_hash`, so the effect is visible on the record itself.

### M5. "Empty wallet" (budget enforced before the model), about 40s
- Claim: "No budget, no model call. We reserve the worst-case cost before dispatch."
- Action: one press sends `POST /v1/chat/completions` with Bearer `wk_budget_demo`, then a
  burst of 10 in parallel.
- Proof UI: red `429 budget.usd`. MODEL node "not called", because `timings_ms.upstream` is
  absent and `tokens_in`/`cost_usd` are 0. The budget meter is `0.00 / 0.00`.
  **[ASK-U]** add `upstream_calls_total` (per model) to the snapshot so a counter can visibly
  *not move* during the burst. That is the strongest proof for a finance audience.

### M6. "Move money" (human in the loop, single-use approval), about 75s
- Claim: "Irreversible actions need a human. Approvals are bound to exact args and cannot be
  replayed."
- Action: `transfer_funds {iban, amount:50, reference}` via `/v1/tools/call` in a session that
  read `invoice-7` → amber `require_approval` with `approval_id`. The judge opens tab 3 and
  presses **Approve** (`POST /api/approvals/{id} {approve:true}`). Back on Live: **Retry**
  sends the same call with `X-Approval: <id>` → green ALLOWED. **Replay** (same header again)
  → red. **Tamper args** (amount 50 → 5000 with the same approval) → red. Then amount 20000 →
  `tools.max_value`.
- Proof UI: TTL ring, "args hash 4be9…" and the approval chip lifecycle
  `pending → approved → consumed`, reflected from `GET /api/approvals`.

### M7. "Forge the record" (tamper-evident audit), about 45s
- Claim: "Every decision is HMAC-chained. Change one byte and verification breaks at that
  record."
- Action: **Verify now** → `GET /api/audit/verify` → green ribbon, count = everything the judge
  just did. **Run tamper test** → `GET /api/audit/verify-fixture` → ribbon snaps at `broken_at`
  with "block → allow" annotation. Then **report.md** opens in a new tab (`GET /api/report.md`),
  which is the artifact a control function hands to audit.
- **[ASK-A]** (high jury value): `POST /api/audit/tamper-drill {seq}` copies the *live* chain to
  a scratch file, flips the `action` of record `seq`, verifies the copy and returns
  `{ok:false, broken_at, reason}` **without touching `audit.jsonl`**. The judge then picks
  *their own* blocked record from M3 and sees it caught. That beats a canned fixture.

**Bonus (if time): kill switch.** `POST /api/kill/bank-ops-agent` → the next tool call is 403
`tools.kill_switch`. The KILL node is red and everything downstream is "not reached". Restore
with `DELETE`.

### 4.8 Backend asks (all small, ranked)

| Id | Ask | Size | Value |
|---|---|---|---|
| ASK-A | `POST /api/audit/tamper-drill {seq}` on a scratch copy, never the live file | ~25 lines | very high (M7 with the judge's own record) |
| ASK-U | `snapshot.upstream_calls` counter (per model) | ~5 lines | high (M5 proof) |
| ASK-C | `snapshot.posture.coverage = coverage(policy)` | 1 line | high (OWASP grid) |
| ASK-ST | `app.mount("/ui", StaticFiles(directory=REPO_DIR/"frontend"))` for module files | 1 line | enables §6 split |
| ASK-T | `GET /api/session/{id}/taint` → `[{label, source_tool, ts}]` (no values) | ~10 lines | medium (server-truth taint strip) |
| ASK-P | `last_reload.detected_ts` in snapshot | ~3 lines | medium (honest reload latency) |
| ASK-1 | non-acting finding for checksum-failed PII | ~10 lines | low/medium |
| ASK-S | optional `timings_ms.stages:{pii,secrets,injection,signatures,canary,flow,tools,budget}` | ~20 lines | low (nice per-node ms) |
| ASK-E | real SSE `GET /api/stream` (see §6) | ~30 lines | low; polling is enough |

Note: `GET /api/events` is **not** a stream. It is a JSON tail of the audit log
(`limit`, `action`, `kind`, `agent_id` filters). Treat it as a history query.

---

## 5. Visual language

### 5.1 Colour tokens

Dark is the stage default (projectors handle dark backgrounds with saturated accents better, and
it reads as a control room). Light is for daylight rooms and printouts. Contrast is measured
against `--surface`, and all text tokens are ≥ 4.5:1. Accent fills carry text in `--on-*`.

```css
:root {                       /* light */
  --bg:#F5F6F8; --surface:#FFFFFF; --surface-2:#EEF0F4; --line:#D5D9E0;
  --fg:#0E1420; --muted:#4A5568;          /* 15.9:1, 7.4:1 on surface */
  --accent:#1F4FD1;                        /* brand: links, focus, selection (7.0:1) */
  --block:#C21F32;  --on-block:#FFFFFF;    /* 5.9:1 */
  --approval:#9A5B00; --on-approval:#FFFFFF; /* amber text 5.6:1; fill uses #F2A93B + dark text */
  --redact:#6A35C9; --on-redact:#FFFFFF;   /* 6.6:1 */
  --allow:#137A3F;  --on-allow:#FFFFFF;    /* 5.4:1 */
  --off:#8A93A3;    --skip:#A9B1BE;        /* non-text, hatch/dash only */
  --focus:#1F4FD1;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { /* same as below */ } }
:root[data-theme="dark"] {
  --bg:#0A0E15; --surface:#121824; --surface-2:#1A2231; --line:#2A3446;
  --fg:#E8EDF5; --muted:#9AA6B8;          /* 14.6:1, 6.8:1 */
  --accent:#6E9BFF;
  --block:#FF5A6A; --on-block:#1A0005;     /* text on dark 5.8:1 */
  --approval:#FFB547; --on-approval:#1A1000;
  --redact:#B48CFF; --on-redact:#12002A;
  --allow:#3DD68C; --on-allow:#00170A;
  --off:#5B6578; --skip:#4A5468; --focus:#9DBBFF;
}
body { background:var(--bg); color:var(--fg); }
```

### 5.2 Severity semantics (fixed mapping, everywhere)

| `action` | Colour | Stamp text | Shape cue (colour-blind safe) |
|---|---|---|---|
| `block` | `--block` | BLOCKED | octagon icon, solid fill |
| `require_approval` | `--approval` | NEEDS HUMAN | hand/flag icon, striped fill |
| `redact` | `--redact` | REDACTED | eye-slash icon, half fill |
| `monitor` | outline of the would-be colour | WOULD BLOCK | dashed border |
| `allow` | `--allow` | ALLOWED | check icon, thin outline |
| disabled/off | `--off` | OFF | 45° hatch + strike-through label |
| skipped | `--skip` | SKIPPED | dashed outline + bypass arc |

HTTP code always appears beside the stamp (`403`/`429`/`401`/`200`). Red is never used for
branding, charts or hover.

### 5.3 Typography

- UI: **Inter** (Google Fonts, 400/600/700), falling back to `system-ui`. Data: **JetBrains
  Mono** 400/600 for control ids, hashes, offsets and YAML.
- Stage scale: stamp 40/44 700 all-caps tracking +4%, verdict sentence 22/30 600, node labels
  14/16 600 caps, body 16/24, small 13/18 (never smaller on stage). Ops scale is one step down.
- Tabular numerals (`font-variant-numeric: tabular-nums`) on every ms, USD and count, so numbers
  do not jitter while polling.

### 5.4 Iconography and density

Inline SVG sprite (one `<svg><symbol>` block, about 14 icons): shield, octagon, hand, eye-slash,
check, hatch, bolt (judge), link (chain), broken-link, key (auth), plug (detectors), wallet
(budget), clock (TTL), skull-switch (kill). Stroke 1.75px, 20px grid, `currentColor`. No icon
fonts, no emoji. Density: Stage is low-density (≤ 7 focal elements on screen). Ops keeps the
current dense tables with 32px rows. Corners are 6px radius, borders 1px `--line`, no shadows
except a 1-level overlay shadow for the approval card.

---

## 6. Frontend architecture (hackathon constraints)

**Recommendation: no framework, no build, native ES modules plus one tiny helper.** The current
`index.html` already works with vanilla JS and a careful `esc()`. A framework adds risk at 4 a.m.
and gives the jury nothing. What we do need is structure and safe rendering.

- **No Alpine/htmx.** htmx wants server-rendered HTML fragments, but our API returns JSON. Alpine's
  inline expression model fights a CSP and invites `x-html`.
- **Preact + htm via CDN: not worth it** for 1 page and 6 views. **Chart.js: no.** The only
  charts are a stacked latency bar, budget meters and posture bars, all of them 10-line
  `<div>`/SVG renders.
- The only CDN item worth it is Google Fonts. Everything else is inline, which matters because
  venue Wi-Fi fails and the demo must work offline. Ship a system-font fallback stack, so the UI
  is fine with no network at all.

**Module split** (needs ASK-ST, a one-line `StaticFiles` mount; fallback: keep one file with
the same sections as `<script type="module">` blocks):

```
frontend/
  index.html          shell, tokens, sprite, <main> mount points
  ui/app.js           router (hash), keyboard map, boot, poll loop
  ui/api.js           fetch wrapper: timeout 4s, JSON/err normalisation, X-Admin-Token passthrough
  ui/store.js         single state object + subscribe(fn); diff by snapshot hash/seq
  ui/dom.js           h(tag, attrs, ...children) → DOM nodes via textContent ONLY; no innerHTML
  ui/pipeline.js      record → node states (pure fn, unit-testable) + replay animator
  ui/views/{live,policy,approvals,audit,posture,proof}.js
  ui/moments.js       the 7 scripted sequences (data + step runner)
  ui/styles.css
```

**State model.** One store:
`{snap, snapHash, lastSeq, records: Map<seq,rec>, mine: Map<request_id,{text, agent}>, session:{id, taint[]}, focus: seq|null, pinned: bool, replayQueue: [], ui:{mode, tab, theme}}`.
Views subscribe and re-render only when their slice changes. Keep a rule of thumb: snapshot →
shield bar/posture/budgets; records → feed/evidence/pipeline; local → `mine` (the judge's raw
text never leaves the browser except in the request they triggered).
`pipeline.js:stateFor(record, snap)` is a **pure function**. Cover it with 10 assertions in a
`ui/selftest.html` that runs it in the browser. That is cheap insurance.

**Polling vs SSE.** Poll `GET /api/snapshot` every **1000 ms** while the tab is visible, every
5s when hidden (`visibilitychange`), with exponential backoff to 8s on errors. Skip re-render if
`recent[0].seq` and `policy.hash` are unchanged. Records the judge triggers come back
synchronously in the HTTP response, so the pipeline replays with **zero polling lag**. Polling
only feeds the background (other agents, `demo/agent.py`). `snapshot.recent` is 30 records, so
there is nothing to gain from SSE at 1 Hz. If ASK-E ever lands, use `EventSource` with polling
as fallback, but do not build it before the demo works.

**XSS safety (all server data is untrusted).** The attacker controls the prompt, tool output and
documents, and our UI renders their echoes. This is an AI-security product, so an XSS in the
dashboard would be fatal on stage.
- Render through `dom.h()` with `textContent`/`setAttribute` only. Ban `innerHTML` in `ui/`
  except for the static sprite (lint with a one-line `grep -n innerHTML frontend/ui` in CI).
  Until the refactor, keep the existing `esc()` on every interpolation, including attributes.
- Highlighting `start..end` is done by splitting the string and creating three text nodes plus a
  `<mark>`, never by building HTML strings.
- `report.md` is opened as `text/markdown` in a new tab and never rendered as HTML in-page.
- Never put server strings into `href`/`src`/`style`. Never `eval`, never `new Function`.
- Add a CSP meta: `default-src 'self'; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; script-src 'self'`
  (requires moving inline script to `ui/*.js`, which ASK-ST enables). The markdown-exfil attack
  (`![x](https://evil.example/…)`) then cannot even fire a request from our own page. That is a
  good line for the jury.
- Admin token: read from `?admin=` once, keep in `sessionStorage` (try/catch), send as
  `X-Admin-Token`, strip it from the URL with `history.replaceState`.

**Accessibility.** Verdict region is `aria-live="assertive"` (one sentence per decision).
The feed is `aria-live="off"`. Pipeline nodes are an ordered list with `aria-label="PII: hit,
redact"`. Every state uses shape + text as well as colour. Visible 3px focus ring in
`--focus`. Full keyboard path: `1`–`7` moments, `R` replay, `A` approve the focused approval,
`V` verify chain, `?` shortcut sheet. Feed rows follow the repo convention: `tabIndex=0`,
`role="button"`, Enter/Space. Honour `prefers-reduced-motion`. Contrast tokens are in §5.1.

**Performance.** Cap the DOM: feed 50 rows, chain ribbon 12 tiles, records Map pruned to 300.
Animate only `transform`/`opacity`. One `requestAnimationFrame` loop for replay. The poll loop
keeps a single in-flight request (abort the previous one with an `AbortController`). Target:
first paint < 300 ms from localhost and < 50 KB total JS+CSS uncompressed.

---

## 7. Prioritized build plan (ranked by jury impact per hour)

Build on the existing `frontend/index.html`. It already has try-it, scenarios, why-card, feed,
toggles, YAML, approvals, kill, verify and tests. Reuse its `api()`, `esc()`, `PRESETS`, `SCEN`
and `callTool` logic.

### First 2 hours: "Stage mode that tells the story" (most of the value)
1. **Shield bar** restyle with posture grade, policy hash chip (shake on reject), judge lamp,
   p50/p99, chain chip. Data is all in the snapshot. *(30 min)*
2. **Pipeline theater v1**: static SVG/CSS nodes + `stateFor(record)` + instant state switch
   (no packet animation yet) + stacked latency bar from `timings_ms` + judge `skipped` dashed
   bypass. *(50 min)*
3. **Verdict sentence + stamp** with HTTP code, replacing the current why-card header.
   *(15 min)*
4. **Attack deck** with M1, M2, M3 (4-step stepper), M6, M7 wired to existing endpoints, keys
   `1`–`7`. *(25 min)*

### By 4 hours: "Money moments land"
5. Packet replay animation + stamp drop + reduced-motion path. *(30 min)*
6. **Session taint strip** (client-side) for M3 and **"what the model received"** redaction row
   for M1. *(30 min)*
7. **Chain ribbon** with the snap animation on `verify-fixture` + report.md button. *(30 min)*
8. **Approval card** with TTL ring from `expires_at`, plus Retry / Replay / Tamper-args buttons
   on Live for M6. *(30 min)*
9. Backend asks **ASK-C, ASK-U** (6 lines total) → OWASP grid and the "model not called" counter
   in M5. *(20 min incl. tests)*

### By 8 hours: "Polish that survives a hostile judge"
10. Policy view: before/after re-run, time-to-effect, reload timeline, "Break it". *(60 min)*
11. **ASK-A tamper-drill** + "pick your record" UX in the Audit view. *(45 min)*
12. Posture view with the formula as stacked bars, gaps, budget meters. *(40 min)*
13. Module split + CSP + `innerHTML` purge (ASK-ST), `selftest.html` for `stateFor`. *(60 min)*
14. Light theme pass, projector check at 1366×768/125%, phone layout, a11y sweep, shortcut
    sheet. *(45 min)*
15. Optional: ASK-T server taint, ASK-P detected_ts, ASK-1 checksum-failed label. *(45 min)*

**Cut if late, in this order:** light theme → module split (keep one file, keep `esc()`) →
posture bars → reload timeline → packet animation. **Never cut:** verdict sentence, judge
`skipped` visual, M3 flow-survives-detectors-off, the hash chip that does not move on reject,
and the chain snap. Those five frames carry the 8 minutes.

**Rehearsal rule:** a teammate who did not build it runs M1→M7 from a cold boot in under 7
minutes, twice, with the Wi-Fi off. Any moment that needs explanation longer than its claim line
gets redesigned, not re-scripted.
