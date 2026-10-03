# UX Concept B: "The control plane a CISO would buy"

Status: ideation only, not built. Author angle: operator / security-team console for a bank.
Facts in this document come from `docs/CONTRACTS.md`, `docs/ARCHITECTURE.md`, `backend/app/main.py`,
`backend/app/engine.py` (`snapshot()`, `_excerpt_for`, `approvals_view`, `kill`) and `frontend/index.html`.
Where the console needs something the backend does not expose yet, it is marked **[API+n]** and listed in §7.

The one-line thesis: **a hackathon toy shows what the gateway can catch; a control plane shows who decided,
under which policy version, how fast, at what cost, and proves nobody edited the record afterwards.**
Every screen below is built around that sentence.

---

## 0. What makes it read as credible vs. "hackathon toy"

Credible signals (do these):

1. **Every number has provenance.** Each decision shows `policy_version` + short `policy_hash`, `audit seq`,
   `request_id`, and the timings breakdown. Hover any KPI and you see the formula (posture already ships
   `formula` and per-gap `contribution`).
2. **The console tells you when it is lying.** A visible staleness clock ("updated 0.8 s ago"), a degraded
   banner when the judge breaker is open, a red banner when a policy edit was rejected *and which version is
   still enforcing*. Toys hide failure; control planes surface it first.
3. **Destructive actions have friction proportional to blast radius.** Kill switch = type the agent id.
   Profile switch to `dev` (monitor mode, fail-open) = shows the posture delta before you confirm.
4. **Honest identity.** Approvals currently record `who="dashboard"`. Show it as exactly that, with a footnote
   "prod: SSO identity + four-eyes". A jury trusts a stated limitation more than an implied feature.
5. **Monospace for identifiers, tabular numerals for metrics, no emoji, no gradients, no "AI sparkle".**
   Datadog/Wiz look comes from density, alignment and restraint, not decoration.
6. **Deep links.** `#/decisions/1234` opens that exact record. A CISO forwards links; toys cannot be linked.
7. **Export that an auditor would accept:** `audit.jsonl` + `report.md` + chain verification result with
   count and head hash, all one click from the Audit screen.

Toy signals (avoid): live counters that animate for drama, a giant red "THREATS BLOCKED" number with no
denominator, random-looking charts with no axes, raw JSON as the only drill-down, toggles that act with
no confirmation and no audit echo.

---

## 1. Personas and jobs-to-be-done

| Persona | Context | Top jobs (in priority order) | Primary screen | Success metric |
|---|---|---|---|---|
| **Security operator** (SOC L1/L2) | Second monitor, all shift, keyboard-driven | 1. Notice a block spike within seconds. 2. Explain one decision in < 30 s (which control, what span, which policy). 3. Contain: kill an agent. | Overview, Live decisions | Time from event to understood |
| **Approver** (desk head / ops lead) | Interrupted, mobile-ish, 120 s TTL | 1. See exactly what the agent wants to do (tool + canonical args). 2. See *why* it needs approval (untrusted data earlier in the session). 3. Approve/reject before expiry. | Approvals inbox | Zero expired-by-neglect approvals |
| **Platform engineer** (owns agents + policy) | Ships policy changes, tunes thresholds | 1. Edit YAML, validate before it goes live. 2. See the diff and the posture impact. 3. Roll back fast when a change misfires. 4. Watch budgets per agent. | Policy, Agents & budgets | Change applied without an outage; rollback < 10 s |
| **Auditor / compliance** | Periodic, read-only, skeptical | 1. Prove the log was not edited (chain verify). 2. Export evidence. 3. Map controls to OWASP LLM 2025. | Audit, Posture & report | Evidence package in one click |
| **Jury / mentor** (HackYeah) | 8 minutes, tries to break it | 1. Understand the product in 20 s. 2. Attack it (disable detectors, broken YAML, kill judge) and *see* the system stay safe. 3. Verify claims (tests, latency, chain). | Overview + Playground | "I could not break it, and I saw why" |

Design consequence: Overview must answer "is anything wrong right now?" for the operator *and* "what is this
product?" for the jury in the same viewport. The jury's attack path (§3.10) is a first-class flow, not a demo hack.

---

## 2. Information architecture and navigation

```
┌ Global status bar (always visible, 36 px) ────────────────────────────────────────────────────────┐
│ AgentShield  ▸ policy v14 #a3f9c1 · standard · enforce │ Judge ● closed │ Chain ● ok 1,284 │ ⟳ 0.8s │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Left nav (200 px, collapses to 56 px icons) ┐
│  Overview                 g o               │
│  Decisions        (live)  g d               │
│  Approvals           [2]  g a               │
│  Agents & budgets         g b               │
│  Policy                   g p               │
│  Audit                    g u               │
│  Posture & reports        g r               │
│  ───────────                                │
│  Playground (try / attack) g t              │
│  Tests                     g x              │
└─────────────────────────────────────────────┘
```

Routing is hash-based (`#/overview`, `#/decisions?q=action:block`, `#/decisions/1284`, `#/approvals/apr_x`,
`#/agents/bank-assistant`, `#/policy/diff`, `#/audit`, `#/posture`). The filter query lives in the hash so a
filtered view is shareable.

The global status bar is the single most important component. It holds five "lamps" that never move:
policy (version, hash, profile, mode, last reload status), judge breaker, audit chain, kill-switch count
(only shown when > 0, red), and the staleness clock. Clicking a lamp navigates to the owning screen.

### Command palette (Cmd/Ctrl-K)

Fuzzy over verbs + entities. Entities come from the snapshot (`agents`, control names, profiles).

```
> kill bank-ass▌
  ⏻  Kill agent  bank-assistant            opens confirm modal
  ⌕  Show decisions for agent bank-assistant
  ⌂  Open agent bank-assistant
```

Commands: `go <screen>`, `find seq <n>`, `filter <query>`, `kill <agent>`, `revive <agent>`,
`profile <standard|dev|strict>`, `toggle <control>`, `detectors off|on`, `verify chain`, `verify tampered fixture`,
`export audit`, `export report`, `try "<text>"`. Every mutating command opens the same confirm dialog the
button would; the palette is a faster path, never a less-safe one.

### Keyboard map

| Key | Action |
|---|---|
| `g` + letter | navigate (see nav) |
| `/` | focus filter bar |
| `j` / `k` | next / previous row in any table |
| `Enter` / `Esc` | open drawer / close drawer or modal |
| `Space` | pause / resume live stream |
| `[` `]` | previous / next finding inside an open decision |
| `a` / `r` | approve / reject the focused approval (still shows a confirm with args) |
| `c` | copy permalink of focused record |
| `?` | shortcut sheet |

Filter grammar (client-side over the buffer, with `agent`, `action`, `kind` pushed to the server where
`/api/events` already supports them): `action:block control:pii.* agent:bank-assistant kind:tool owasp:LLM06
via:base64 judge:yes text:"invoice"`. Chips render below the bar; Backspace removes the last chip.

---

## 3. Key screens

Common layout: status bar, left nav, content area with a 12-column grid, right-side drawer (560 px) for
details so the operator never loses list position.

### 3.1 Overview (operator glance + jury first impression)

```
┌ Overview ──────────────────────────────────────────────────────────── last 15 min ▾ ─────────┐
│ ┌Decisions/min───────┐┌Blocked──────┐┌Approval queue┐┌Overhead p50/p99┐┌Posture──────────────┐│
│ │ 42   ▁▂▂▃▅▃▂▂▁▂▃   ││ 9.1% (31)   ││ 2 · oldest 74s││ 3.1 / 11.8 ms  ││ 86 /100  ▲ gaps: 2  ││
│ │ stacked by action  ││ ▲ +4 vs prev││ SLA ● ok      ││ judge 410/1190 ││ LLM01..LLM10  8/10  ││
│ └────────────────────┘└─────────────┘└──────────────┘└────────────────┘└─────────────────────┘│
│ ┌Decisions over time (stacked area, 10 s buckets) ───────────────┐┌Top controls fired (bar)──┐ │
│ │ ▇ block ▇ require_approval ▇ redact ▇ monitor ░ allow          ││ pii.pesel        ███ 14  │ │
│ │  ...                                                           ││ injection.heur.  ██ 9    │ │
│ │                                                                ││ flow.secret_egr. █ 4     │ │
│ └────────────────────────────────────────────────────────────────┘└──────────────────────────┘ │
│ ┌Fleet (agents) ─────────────────────────────────────────────────────────────────────────────┐ │
│ │ Agent           Status   Req/min  Block%  Spend today / limit      Last decision            │ │
│ │ bank-assistant  ● live   12       6%      $0.21 / $0.50  ████░░░   14:02:11 block pii.pesel │ │
│ │ research-bot    ● live   3        0%      $0.04 / $1.00  ░░░░░░░   14:01:50 allow           │ │
│ │ budget-demo     ■ capped 0        100%    $0.00 / $0.00  ███████   14:00:02 block budget.usd│ │
│ │ ops-agent       ⏻ KILLED —        —       $0.10 / $0.50            13:58:40 kill (dashboard)│ │
│ └────────────────────────────────────────────────────────────────────────────────────────────┘ │
│ ┌Latest blocks (5) ─────────────────────────────── see all → ┐┌System health ───────────────┐ │
│ │ 14:02:11 bank-assistant  pii.pesel   LLM02  "…[PESEL]…"     ││ Policy  v14 applied 13:55    │ │
│ │ 14:01:58 bank-assistant  flow.secret_egress  LLM06          ││ Feed    27 sigs #77ab ok     │ │
│ └─────────────────────────────────────────────────────────────┘│ Judge   closed · $0.03 today │ │
│                                                                │ Chain   ok · 1,284 records   │ │
│                                                                └──────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

Components: `KpiTile` (value, delta, sparkline, formula tooltip), `StackedArea`, `BarList`, `FleetTable`,
`MiniDecisionList`, `HealthList`. The KPI tile for "Blocked" always shows the denominator.

### 3.2 Decisions (live stream)

```
┌ Decisions ─────────────────────────────────────────────────────────────────────────────────────┐
│ [/ action:block agent:bank-assistant           ] [action ▾][kind ▾][agent ▾][owasp ▾]  ● LIVE  │
│  chips: (action:block ×) (agent:bank-assistant ×)                          ⏸ Paused · 17 new ↑ │
├────┬──────────┬──────────────────┬───────┬──────────────┬─────────────────────────┬──────┬─────┤
│seq │time      │agent             │kind   │decision      │primary control / summary│OWASP │ms   │
├────┼──────────┼──────────────────┼───────┼──────────────┼─────────────────────────┼──────┼─────┤
│1284│14:02:11.4│bank-assistant    │chat   │■ BLOCK       │pii.pesel · output leak  │LLM02 │ 3.2 │
│1283│14:02:10.9│bank-assistant    │tool   │◆ APPROVAL    │flow.untrusted_before_irr│LLM06 │ 1.1 │
│1282│14:02:09.0│research-bot      │chat   │◐ REDACT      │pii.iban (2 findings)    │LLM02 │ 2.7 │
│1281│14:02:08.2│research-bot      │chat   │✓ ALLOW       │—                        │      │ 2.1 │
│1280│14:02:07.7│—                 │policy │■ REJECTED    │policy edit rejected: dup│      │  —  │
└────┴──────────┴──────────────────┴───────┴──────────────┴─────────────────────────┴──────┴─────┘
```

Rules: fixed 28 px rows (compact) / 36 px (comfortable); virtualized list over a ring buffer; new rows insert at
top only when the user is at scroll-top and not hovering, otherwise the "17 new" pill accumulates. Admin
records (`kind: policy|approval|kill`) render in the same stream with a neutral row tint: the operator sees
"who changed what" interleaved with what it caused. Rows are `tabIndex=0`, `role="button"`, Enter/Space opens.

### 3.3 Decision record drawer (the "why-card", enterprise version)

```
┌ Decision #1284 ───────────────────────────────────────────── ⧉ copy link  ⤓ JSON  ✕ ─┐
│ ■ BLOCKED · pii.pesel · LLM02 Sensitive information disclosure                        │
│ bank-assistant · session s_8f2 · chat · output · 14:02:11.412 · req 7c1e…             │
│ policy v14 #a3f9c1 (standard, enforce)   audit seq 1284  hash 9b0e… prev 41aa…        │
├ Evidence (masked excerpt, offsets from record) ───────────────────────────────────────┤
│  …Customer record: name Jan K., PESEL ▌[PESEL]▐, IBAN ▌[IBAN]▐, balance 12 400 PLN…    │
│            span 118–129 via original        span 137–165 via original                 │
├ Findings (3) ──────────────────────────────── [ ] next  ────────────────────────────┤
│  ■ pii.pesel        block   118–129  original   checksum valid  ev 4405****359  LLM02  │
│  ■ pii.iban         block   137–165  original   checksum valid  ev PL61****2874 LLM02  │
│  · injection.heur.  0.18    —        folded     below review threshold (0.45)          │
├ Timings (waterfall, ms) ──────────────────────────────────────────────────────────────┤
│  detect    ▇ 2.1                                                                       │
│  judge       (not called: deterministic block)                                         │
│  upstream  ░░░░░░░░░░░░░░░░░░░░░░░░ 412 (mock/vulnerable-llm)                          │
│  total     ▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇ 416   gateway overhead 3.2 ms                      │
├ Cost ───────────── tokens in 312 / out 88 · $0.00041 · model mock/vulnerable-llm ─────┤
├ Related ───── same session (6) · same control last 15 min (14) · approval apr_… ──────┤
└────────────────────────────────────────────────────────────────────────────────────────┘
```

Highlighting: the record already carries `excerpt` (≤ 400 chars, PII/secrets masked in place, offset-preserving)
and `excerpt_offset`, so `finding.start - excerpt_offset` indexes into it. Render by slicing the string into
text nodes and wrapping spans in `<mark data-sev>` created via `document.createElement`, never HTML strings.
Findings with `start: null` (matched only in a decoded view such as `base64`/`unicode_tags`) show a "decoded view
only" badge with the `via` name instead of a highlight; that is a feature to point at, not a gap.

Waterfall: plain CSS bars scaled to `timings_ms.total`; judge bar coloured by verdict status
(`allow|block|timeout|circuit_open|error|budget|disabled`). "Gateway overhead" = total − upstream, the number
the rubric cares about.

### 3.4 Approvals inbox

```
┌ Approvals ──── Pending (2) · Decided today (9) · Expired (1) ────────────────── SLA 120 s ─┐
│ ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ◔ 0:46 left   transfer_funds   bank-assistant   apr_3k…   policy v14 #a3f9           │ │
│ │ Why approval: flow.untrusted_before_irreversible: session read untrusted              │ │
│ │               `read_document(invoice-7)` at 14:01:40 (#1271) before an irreversible   │ │
│ │ Arguments (canonical):                                                                │ │
│ │   iban       PL61 1090 1014 0000 0712 1981 2874   ⚠ value seen in untrusted tool out  │ │
│ │   amount     9 900.00   (max 10 000)                                                  │ │
│ │   reference  "invoice-7"                                                              │ │
│ │ Single use · bound to tool + args + policy hash · approver: dashboard                 │ │
│ │                                  [ Reject  r ]          [ Approve transfer  a ]       │ │
│ └──────────────────────────────────────────────────────────────────────────────────────┘ │
│ ┌ ◑ 1:32 left  send_email  research-bot  … (collapsed) ────────────────────────────────┐ │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

SLA timer: ring + mm:ss computed from `expires` (epoch seconds, from `approvals_view`) against server time
(see clock skew, §4). Colour steps: > 60 s neutral, 30–60 s amber, < 30 s red + title-bar badge
("(2) AgentShield"), 0 → card moves to Expired with a strike. Approve button label names the tool
("Approve transfer"), never a bare "OK". Reject is visually equal weight (no dark pattern toward approve).
A flow-guard **block** is never approvable; if the card's related record shows one, the Approve button is
absent and the card explains why (this matches the backend rule "never overrides allow-list, kill switch or
flow block").

### 3.5 Agents & budgets

```
┌ Agent: bank-assistant ─────────────────────────────── ● live   [ ⏻ Kill switch ] ─┐
│ Key fingerprint wk_…a91 · models: mock/vulnerable-llm · tools: lookup_customer,    │
│ read_document, send_email, transfer_funds                                          │
├ USD today ─────────────────────────────────────┐┌ Rate windows ───────────────────┐ │
│ $0.50 ┤·························· limit          ││ rpm   12 / 60   ████░░░░░░░░    │ │
│       │                  ╱ projected (dotted)    ││ tpm   3.1k / 20k ███░░░░░░░░░   │ │
│ $0.25 ┤──── warn_at ───╱─────────                ││ max tokens/req   2000           │ │
│       │        ╱───╱                             │└─────────────────────────────────┘ │
│ $0    ┼──────────────────────────────────── now  │  Projected exhaustion: 17:40     │ │
├ Decisions mix (24h) ▇▇▇▇▇▇▇░░ · Top controls · Tools called (allowed vs denied) ───────┤
└────────────────────────────────────────────────────────────────────────────────────────┘
```

Burn-down is a cumulative-spend line against the flat daily limit (more legible than a "remaining"
line that falls: operators read "how close to the ceiling"). Projection = linear fit over the last 15 min,
dotted, labelled with time of exhaustion. Without a server series [API+6], the client accumulates samples
from snapshot polls and says "since page load" on the axis; honest and good enough for the demo.

### 3.6 Policy (editor, diff, validation, profile, rollback)

```
┌ Policy ── enforcing v14 #a3f9c1 · standard · enforce · applied 13:55:02 ──────────────────┐
│ Profile: ( standard ) ( strict ) ( dev ⚠ monitor + fail-open )     Detectors: [all on]   │
├ Controls ──────────────────────────────┬ Editor (YAML) ───────────────────── [Validate] ─┤
│ prompt_injection  ● on   block         │  12 │ mode: enforce                             │
│ pii               ● on   redact        │  13 │ approval_ttl_s: 120                       │
│ secrets           ● on   block         │  14 │ controls:                                 │
│ signatures        ● on   block         │  15 │   prompt_injection:                       │
│ canary            ● on   block         │ ▶16 │     review_threshold: 0.45   ← changed    │
│ semantic (judge)  ● on   grey zone     │  …                                            │
│ flow (top-level)  ● on   survives "all │ ✓ Valid · 2 changes · posture 86 → 86         │
│                    detectors off"      │                                                │
├ Diff vs enforcing ─────────────────────┴────────────────────────────────────────────────┤
│ - review_threshold: 0.40                                                                 │
│ + review_threshold: 0.45                                                                 │
│                                         [ Discard ]   [ Apply v15 (hot reload < 1 s) ]   │
├ History ────────────────────────────────────────────────────────────────────────────────┤
│ v14 #a3f9c1 applied   13:55:02  changed: controls.prompt_injection   [diff] [roll back]  │
│ —   #ee01b2 REJECTED  13:54:40  duplicate agent id 'bank-assistant'  [show error]        │
│ v13 #77d0aa applied   13:40:11  changed: profile                     [diff] [roll back]  │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

Editor: a `<textarea>` with a line-number gutter (no Monaco: 3 MB, offline risk). Diff: line diff in JS
(Myers, ~80 lines, or a vendored `diff` ESM). Validation calls a dry-run endpoint [API+3]; until it exists,
"Validate" is disabled and Apply returns the real verdict (the backend already returns 400 with `error`,
`version`, `hash`, `rejected_hash`). Toggling a control or detectors off shows the posture delta inline
and is echoed into the stream as a `kind: policy` record (already logged by the backend).

### 3.7 Kill switch confirmation

```
┌ Kill agent bank-assistant? ───────────────────────────────────────────────┐
│ Effect: every request with this agent's key is blocked (tools.kill_switch, │
│ 403) until revived. In-flight upstream calls finish; their output is still │
│ inspected. Logged to the audit chain.                                      │
│ Last 5 min: 61 requests, 4 blocks, $0.08.                                  │
│ Reason (goes to audit): [ suspected exfil via invoice-7          ]  [API+5]│
│ Type the agent id to confirm: [ bank-assist▌ ]                             │
│                                    [ Cancel ]   [ ⏻ Kill bank-assistant ]  │
└────────────────────────────────────────────────────────────────────────────┘
```

Revive is one click plus a lighter confirm. If the agent is also listed in `policy.yaml` `kill_switch`, the
backend notes "still listed in policy.yaml"; the UI shows that note and explains revive needs a policy edit.

### 3.8 Audit integrity

```
┌ Audit ────────────────────────────────────────────────────────────────────────────────┐
│ Chain ✓ VERIFIED · 1,284 records · head 9b0e…c2 · HMAC-SHA256 · verified 14:02:15     │
│ [ Verify now ]  [ Verify tampered fixture ]  [ ⤓ audit.jsonl ]  [ ⤓ report.md ]        │
├ Chain strip (last 40 records, each a cell; red cell = broken link) ────────────────────┤
│ ▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢▢                                               │
├ Tampered fixture result ───────────────────────────────────────────────────────────────┤
│ ✕ FAILED as expected · broken_at seq 2 · reason: hash mismatch (record edited)         │
│ Explanation: each record's hash = HMAC(key, prev_hash + canonical JSON). Editing #2    │
│ changes its hash, so #3's prev no longer matches. audit.head catches tail truncation.  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

Side-by-side "our log ✓ / tampered fixture ✕" is the single most convincing 10 seconds for an auditor juror.

### 3.9 Posture & compliance report

Score ring (0–100) with the formula visible ("100 − Σ open-gap weights"), a gap list with each gap's weight
and a "fix" deep link (e.g. `mode.monitor` → Policy screen, profile pill). Below: OWASP LLM Top 10 2025
matrix, rows LLM01–LLM10, columns: controls mapped (from `posture` `owasp` tags and the CONTRACTS mapping),
enabled now, decisions in window, test cases passing (from `/api/tests`). Uncovered rows (e.g. LLM04
data/model poisoning, LLM08 vector/embedding, LLM09 misinformation) say "out of scope: see THREAT_MODEL §6"
instead of hiding. Export buttons: `report.md` (exists), "Print / PDF" via a print stylesheet (free).

### 3.10 Playground (jury attack path)

The existing Try-it chips and scenarios move here, grouped as **"Attack it yourself"**: PESEL (valid vs bad
checksum), Polish injection, base64 injection, homoglyph, torch.load signature, read→send flow, transfer
approval, budget-demo, judge timeout marker. Each run opens the same decision drawer as production traffic.
A sticky "attack checklist" sidebar ticks off what the jury has tried (local only), which turns the 8-minute
demo into a guided tour without us talking.

### 3.11 States (every data region implements all of these)

| State | Trigger | Treatment |
|---|---|---|
| Loading (first) | no snapshot yet | skeleton rows with fixed heights (no layout shift), status lamps grey "connecting" |
| Empty | 0 events / 0 approvals | one sentence + action: "No decisions yet. Send traffic or open Playground." Approvals: "Inbox zero. Approvals appear when an agent calls an irreversible tool after reading untrusted data." |
| Error (request) | fetch fails / 5xx | inline error in the card with HTTP status + Retry; global lamp amber; never clear the last good data |
| Stale | last OK snapshot > 3 s old | status clock turns amber "stale 7 s"; > 15 s red banner "Console disconnected: data frozen at 14:02:11"; live numbers get a hatched overlay and `aria-live` announcement; LIVE pill becomes "RECONNECTING" with backoff countdown |
| Degraded judge | `judge.breaker` = `open` / `half_open` | amber banner: "Semantic judge unavailable: breaker open. Grey-zone traffic follows fail_mode=closed (blocked). Deterministic detectors unaffected." Half-open shows "probing". Judge bars in waterfalls show `circuit_open` |
| Breaker open, fail-open profile | breaker open + `fail_mode=open` | red, not amber: grey zone is now allowed through; posture gap shown |
| Policy rejected | `policy.last_reload.status=rejected` | red banner pinned under status bar until dismissed: "Edit rejected 14:03:22: {error}. Still enforcing v14 #a3f9c1 (last good)." Link to diff of rejected text if stored [API+2] |
| Detectors disabled | `detectors_disabled` non-empty | persistent striped red bar: "6 detectors disabled by dashboard override. Flow guard still ON." with "Re-enable all" |
| Monitor mode | `policy.mode=monitor` | whole console gets an amber top border + "MONITOR MODE: nothing is blocked" in status bar |
| Agent killed | id in `kill_switch` | red ⏻ in fleet, count lamp in status bar |
| Feed rejected | `feed.last_error` | health list row red, previous signature set still active |
| Unauthorized | 401 on admin POST (`AGENTSHIELD_ADMIN_TOKEN` set) | modal asking for admin token, kept in memory only (not localStorage) |

---

## 4. Data visualization and real-time strategy

### Chart choices

| Question | Chart | Why not something else |
|---|---|---|
| What is happening now? | stacked area by action, 10 s buckets, 15 min | Shows composition and volume at once; lines would hide the block share |
| Which control fires most? | horizontal bar list with counts | Long control ids need horizontal labels; pie charts cannot compare 12 slices |
| Is latency healthy? | two KPI tiles (p50/p99, judge vs no-judge) + sparkline | p99 is a single number decision-makers know; histograms are for drill-down |
| Where did time go in one request? | waterfall | The canonical tracing visual (Datadog APM), instantly read by engineers |
| Will this agent run out of budget? | cumulative line vs limit + dotted projection | Ceiling framing; projection answers "when" |
| Is the log intact? | chain strip of cells | Makes "chain" literal; a broken cell is unmistakable |
| OWASP coverage | matrix table with status glyphs | Auditors want rows they can tick, not a radar chart |

Implementation: hand-rolled SVG (area, bars, line) with ~150 lines of shared scale helpers. No Chart.js /
ECharts: offline, CSP-friendly, and we need maybe 4 chart types. All charts have a visible axis, units, and a
text alternative (`<title>` + an "as table" toggle).

### Real-time update strategy

Current state: frontend polls `/api/snapshot` every 1 s; snapshot embeds `recent` (last 30). `/api/events` is a
JSON tail endpoint, not SSE. At > 30 decisions/s the stream silently drops rows. Decision:

1. **Snapshot poll at 2 s** for KPIs, lamps, budgets, posture (small, idempotent, cache-friendly).
2. **Cursor poll for events at 1 s**: `GET /api/events?after_seq=<last>&limit=500` [API+1]. Audit `seq` is a
   perfect monotonic cursor, so this is lossless and resumable after a disconnect.
3. **SSE as the 8 h upgrade**: `GET /api/events/stream` with `id: <seq>`; browser `EventSource` sends
   `Last-Event-ID` on reconnect, which maps 1:1 to `after_seq`. Same client reducer consumes both, so SSE is a
   transport swap, not a rewrite. Polling stays as automatic fallback when `EventSource` errors twice.
4. Pause both polls when `document.hidden`; resume with an immediate fetch. Exponential backoff 1→2→4→8 s on
   errors, with jitter.

Why not SSE first: one uvicorn worker, proxies on venue Wi-Fi, and reconnect bugs at 4 a.m. The cursor poll
is 15 lines and cannot lose events.

### High event rates

- Ring buffer of 5,000 records in memory (≈ 5 MB worst case); oldest evicted; "older events: load from server"
  button calls `/api/events?before_seq=` [API+1].
- Incoming batches are reduced into the store once per `requestAnimationFrame`; aggregates (per-bucket counts,
  per-control counts) are updated incrementally, never recomputed from the full buffer.
- The table is virtualized (fixed row height, render ~40 visible rows + overscan 10).
- When paused or scrolled, only the "N new" counter updates.
- If > 200 events/s arrive, the stream shows "sampling: showing 1 in N allow rows; all blocks shown". Blocks,
  approvals and admin records are never sampled.
- Clock skew: compute `skew = serverTime - Date.now()` from the HTTP `Date` header or `server_time` [API+4];
  SLA timers and "x s ago" use server-adjusted time.

---

## 5. Visual system

### Tokens (CSS custom properties on `:root`, dark under `prefers-color-scheme` + `[data-theme]`)

| Token | Light | Dark | Use / contrast note |
|---|---|---|---|
| `--bg` | `#F6F7F9` | `#0B0F14` | page |
| `--surface` | `#FFFFFF` | `#121821` | cards, drawer |
| `--surface-2` | `#F1F3F6` | `#18202B` | table header, zebra |
| `--border` | `#D8DDE4` | `#273242` | 1 px hairlines |
| `--fg` | `#0F172A` | `#E6EAF0` | body text (≥ 15:1 / ≥ 13:1) |
| `--muted` | `#4B5565` | `#9AA4B2` | secondary text (≥ 7:1 on surface) |
| `--accent` | `#1D4ED8` | `#7AA2FF` | links, focus ring, primary button |
| `--sev-block` | `#B42318` | `#FF7A70` | ≥ 6:1 on surface both themes |
| `--sev-approval` | `#8A4B00` | `#F5B544` | ≥ 6:1 |
| `--sev-redact` | `#6B3FC2` | `#B99AF8` | ≥ 6:1 |
| `--sev-monitor` | `#175CD3` | `#84ADFF` | ≥ 5:1 |
| `--sev-allow` | `#067647` | `#4ED38F` | ≥ 5.5:1 |
| `--sev-*-bg` | 8% tint of fg colour | 16% tint | chip backgrounds; chip text uses the full colour |
| `--mark` | `#FFE58A` | `#5C4A0E` | evidence highlight; text on it stays `--fg` |

Rules: severity is always glyph + label + colour (■ BLOCK, ◆ APPROVAL, ◐ REDACT, ● MONITOR, ✓ ALLOW), so it
survives colour blindness and greyscale printing. Red is reserved for block/broken/killed; the brand accent is
blue so "red" never means "clickable". Focus ring: 2 px `--accent` + 2 px offset, never removed.

### Severity semantics

Ordered exactly like backend `SEVERITY`: allow 0 < monitor 1 < redact < require_approval < block. The primary
decision chip shows the strongest action; findings list sorts by severity, then by offset.
"Admin" records (policy/approval/kill) use neutral grey with an icon, so they never inflate perceived threat.

### Type scale (system UI stack + `ui-monospace`)

| Role | Size / line | Weight |
|---|---|---|
| Display (score, big KPI) | 28/32 | 600, tabular-nums |
| H1 screen title | 18/24 | 600 |
| H2 card title | 12/16 uppercase, +0.06em | 600, `--muted` |
| Body | 13/20 | 400 |
| Table compact | 12/16 | 400 |
| Mono (ids, hashes, args) | 12/16 | 400 |

### Spacing and density

4 px base: 4, 8, 12, 16, 24, 32. Radius 6 (cards), 4 (chips). Two density modes via `[data-density]` on
`<html>`: **compact** (row 28 px, card padding 12) default for operators, **comfortable** (row 36 px,
padding 16) for projector demos. Toggle in the status bar, remembered in `localStorage` (wrapped in
try/catch). A "Presentation" option = comfortable + 115% font scale + dark theme for the stage.

---

## 6. Frontend architecture

### Options evaluated

| Option | For | Against | Verdict |
|---|---|---|---|
| Vanilla JS + ES modules | zero deps, current code base | current code renders with `innerHTML` + `esc()`; re-rendering whole cards every second kills focus, scroll and text selection; every new screen multiplies manual DOM patching | good for 1 screen, not 9 |
| **Preact + htm, vendored ESM, no build** | 4 kB + 1 kB; components, keyed list diffing, hooks; htm templates escape all interpolations by default (text nodes); runs from static files offline | team must learn hooks; must ban `dangerouslySetInnerHTML` | **pick** |
| Alpine.js | tiny, HTML-first | expression evaluation from attributes needs `unsafe-eval` under CSP (or the CSP build); `x-html` is a footgun; weak for virtualized high-rate lists | no |
| Vite + Preact/React/TS | best DX, types | Node in the Python image or a committed `dist/`, a build step that can break at 4 a.m., two sources of truth | no for the hackathon; it is the post-hackathon path and the component code ports unchanged |

**Decision: Preact + htm + `@preact/signals` vendored into `frontend/vendor/` as ES modules, no bundler.**
Signals give a global store without prop drilling and update only the text nodes that changed, which is what
a 1 s polling console needs.

### File layout

```
frontend/
  index.html                 shell: <div id=app>, <script type=module src=/ui/main.js>, no inline JS
  ui/
    main.js                  router mount, polling start
    vendor/preact.mjs htm.mjs hooks.mjs signals.mjs   (pinned versions, sha256 noted in README of PR)
    lib/
      api.js                 fetch wrapper: timeout 5 s, JSON guard, admin token header, error typing
      store.js               signals: snapshot, events ring, approvals, ui (filters, paused, density)
      poller.js              snapshot + events cursor + backoff + visibility; SSE adapter later
      router.js              hash router: pattern -> component, params, query
      filter.js              parse "action:block control:pii.*" -> predicate
      format.js              time, ms, usd, short hash, relative time with server skew
      highlight.js           excerpt + findings -> array of {text, finding|null} segments
      charts.js              scales + SVG area/bar/line components
      diff.js                line diff for policy
    components/
      StatusBar.js Nav.js Palette.js Drawer.js ConfirmDialog.js KpiTile.js Chip.js Table.js VirtualList.js
    screens/
      Overview.js Decisions.js DecisionDrawer.js Approvals.js Agents.js Policy.js Audit.js Posture.js
      Playground.js Tests.js
    styles/tokens.css app.css print.css
```

FastAPI serves it with one mount: `app.mount("/ui", StaticFiles(directory=REPO_DIR/"frontend"/"ui"))` [API+0].
`/` keeps returning `index.html`.

### State model

```
snapshot   : Signal<Snapshot | null>      replaced every poll; lastOkAt, lastError
events     : Ring<Record> (5000) + Map<seq, Record>; lastSeq; aggregates {perBucket, perControl, perAgent}
approvals  : Signal<Approval[]>           polled 2 s while Approvals screen or badge visible
policy     : {raw, hash, version, draft, validation, history}
ui         : {route, query, paused, newCount, density, theme, drawerSeq, adminToken (memory only)}
derived    : stale = now - lastOkAt > 3000; degradedJudge; rejectedPolicy; fleetRows; budgetSeries
```

Mutations (kill, approve, toggle, apply policy) are **not optimistic**: button shows spinner, waits for the
server response, then forces an immediate snapshot fetch. A control plane must never display a state the
server has not confirmed.

### Routing

Hash router, ~40 lines: `#/decisions/:seq`, `#/approvals/:id`, `#/agents/:id`, `#/policy/:tab`, query after
`?`. Drawer state is part of the route so Back closes the drawer. Unknown route → Overview with a toast.

### XSS safety (all server data is untrusted: it contains attacker-supplied prompts by design)

- Render only through htm/Preact text interpolation (creates text nodes). **Ban list** enforced by a test that
  greps `frontend/ui` for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`,
  `document.write`, `eval(`, `new Function` and fails on any hit.
- Evidence highlighting builds segments in JS and renders `<mark>{segment}</mark>`; never builds markup strings.
- URLs from data (e.g. exfil `https://evil.example/...`) are shown as text, never as `href` or `src`.
  The markdown-image exfil demo must not load the image in the console itself.
- Downloads use server endpoints (`/api/audit.jsonl`, `/api/report.md`), not blob URLs built from record
  content. `report.md` is shown as preformatted text, not rendered markdown.
- CSP header on `/` and `/ui/*` [API+7]:
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
  frame-ancestors 'none'; base-uri 'none'`. With no inline scripts this is strict and free to add.
- Admin token kept in memory only; never in URL or localStorage.

### Testing

- **Playwright smoke** (Python `pytest-playwright` keeps a single toolchain, but it adds a dep, so run it in a
  separate optional job, not in the offline `pytest -q` suite): boot `create_app` with temp policy + data dir on
  a random port, then:
  1. Overview renders status bar with policy hash matching `/health`.
  2. Playground "PESEL" → stream row with BLOCK/REDACT appears → drawer shows `[PESEL]` mark → permalink reloads
     to the same drawer.
  3. XSS canary: try text `<img src=x onerror=window.__pwned=1>` → assert `window.__pwned` undefined and the
     literal text visible.
  4. Broken YAML apply → red rejected banner, status hash unchanged.
  5. Transfer scenario → approval card with countdown → approve → record `kind: approval` in stream.
  6. Kill → confirm requires typing id → fleet shows KILLED → revive.
  7. Audit: verify ok; tampered fixture shows FAILED at seq 2.
- Unit tests for `filter.js`, `highlight.js`, `diff.js` run in the same Playwright page via
  `page.evaluate(import(...))`, so no Node test runner is needed.
- The ban-list grep test is plain pytest and runs offline in the main suite.

### Performance budget

| Metric | Budget |
|---|---|
| JS shipped (vendored libs + app, uncompressed) | ≤ 120 kB |
| First render with data on localhost | ≤ 300 ms |
| Poll handling (snapshot 30 recent + 500 events) | ≤ 8 ms main-thread per tick |
| Stream at 200 events/s | 60 fps scroll, no long task > 50 ms |
| Memory after 1 h at 50 events/s | ≤ 60 MB (ring buffer bounded) |
| Snapshot payload | ≤ 40 kB (drop `recent` from snapshot once cursor poll exists, or keep it at 30) |

---

## 7. Backend API additions (minimal, mapped to `backend/app/main.py`)

Ordered by necessity. Everything else the console needs already exists.

| # | Addition | Where | Size | Why |
|---|---|---|---|---|
| API+0 | `app.mount("/ui", StaticFiles(...))` | next to `@app.get("/")` | 2 lines | serve module files; today only `index.html` is served |
| API+1 | `GET /api/events` gains `after_seq`, `before_seq`, `seq`, `approval_id`, `session_id` filters | extend `events()`; `audit.tail` filter by `seq > after_seq` | ~15 lines | lossless cursor polling, pagination, related-records links, approval → triggering record |
| API+1b | `GET /api/events/{seq}` single record | new route over `audit` | ~8 lines | deep links when the record is older than the client buffer |
| API+2 | `GET /api/policy/history` → `store.history` entries (status, ts, hash, version, changed, error) plus stored text of the last 10 applied versions and the last rejected text | new route; `PolicyStore` keeps texts (needs owner sign-off: `policy.py` is frozen per CONTRACTS) | ~25 lines | history list, diffs, rejected-edit view |
| API+2b | `POST /api/policy/rollback/{hash}` | new route = `store.apply_text(saved_text)` | ~10 lines | one-click rollback that goes through the same validation + audit path |
| API+3 | `POST /api/policy/validate` {yaml} → {ok, error, changed, posture_after} without applying | new route; parse + validate like `apply_text` but no swap | ~20 lines | Validate button, posture delta before apply |
| API+4 | snapshot adds `server_time`, `audit_head_seq`, judge `opened_at`/`cooldown_s` | `Gateway.snapshot()` | ~5 lines | skew-correct timers, "new events" detection, breaker countdown |
| API+5 | `POST /api/kill/{agent_id}` accepts optional `{reason}` stored in the kill audit record | `kill()` + `gw.kill(agent_id, reason)` | ~5 lines | accountable containment |
| API+6 | `GET /api/budgets/series?agent_id=&window=1h` → per-minute cumulative usd/tokens from audit records | new route; aggregate `cost_usd`, `tokens_in/out` | ~25 lines | burn-down that survives page reload |
| API+7 | CSP + `X-Content-Type-Options: nosniff` + `Referrer-Policy: no-referrer` on `/` and `/ui` | small middleware | ~10 lines | XSS defence in depth; credibility with security jurors |
| API+8 (8 h) | `GET /api/events/stream` SSE, `id: seq`, honours `Last-Event-ID` | new route; asyncio queue fed by `audit.append` hook | ~40 lines | push instead of poll |
| API+9 (8 h) | `GET /api/agents` → id, allowed_tools, models, budget limits, key fingerprint (last 3 chars), killed | new route from `policy.agents` | ~15 lines | agent detail header; never return the key itself |

Not needed: anything for OWASP coverage (posture already returns `owasp` per gap), tests (`/api/tests`), report
(`/api/report.md`), audit export, approvals list/decide, profiles, toggles, detectors on/off.

---

## 8. Prioritized build plan

Ranked by jury impact per hour. Each tier is shippable on its own; stop at any boundary.

### 2 hours: "it looks like a product, and it is safe"

1. API+0 (static mount) and split `index.html` into the module layout with Preact + htm vendored. Port existing
   panels as-is first (no feature loss), removing every `innerHTML`; add the ban-list pytest. (45 min)
2. Global status bar with the five lamps + staleness clock + the four banners (rejected policy, degraded judge,
   detectors disabled, monitor mode). This alone makes attacks visible. (30 min)
3. Decisions table + decision drawer with masked-excerpt highlighting, findings list, timings waterfall, policy
   hash/version, permalink `#/decisions/:seq`. (45 min)

### 4 hours (add): "operator and approver workflows"

4. API+1 cursor polling + ring buffer + pause/"N new" pill + filter bar grammar. (40 min)
5. Approvals inbox with SLA countdown, "why approval" link to the triggering record (API+1 `approval_id`),
   tool-named approve button, non-approvable flow blocks explained. (40 min)
6. Kill-switch modal with type-to-confirm (+ API+5 reason) and fleet table on Overview. (25 min)
7. Audit screen: verify, tampered-fixture side-by-side, exports, chain strip. (25 min)
8. Overview KPIs + stacked area + top-controls bars (hand SVG). (30 min)
9. Playground with attack checklist (move existing chips). (20 min)

### 8 hours (add): "control plane depth"

10. Policy editor: textarea + gutter, API+3 validate, diff vs enforcing, posture delta, API+2/2b history and
    rollback, profile switch with confirm for `dev`. (90 min)
11. Agents & budgets: API+6 series, burn-down with projection, rate windows, API+9 agent header. (60 min)
12. Posture & OWASP matrix + print stylesheet for PDF export. (40 min)
13. Command palette + keyboard map + shortcut sheet. (45 min)
14. API+7 CSP headers, density/presentation mode, dark theme polish, WCAG contrast pass with axe in
    Playwright. (40 min)
15. Playwright smoke suite (7 flows in §6). (45 min)
16. API+8 SSE with polling fallback, sampling of allow rows at high rates. (40 min, only if all green)

Cut first if time runs out: SSE (16), command palette (13), budget series (keep client-side accumulation).
Never cut: status bar banners, decision drawer, approvals timer, audit tamper view. Those four are the demo.
