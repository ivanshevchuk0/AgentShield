# AgentShield policy reference

The policy is one YAML document. `parse_policy` in `backend/app/policy.py` validates it and returns a `Policy`. The running gateway loads `backend/policy.yaml` (override with `AGENTSHIELD_POLICY`). The four files in `examples/policies/` are complete, already-expanded postures. Loading one replaces the catalog. They are not overlays on top of the shipped file.

| File | Profile | What a request sees |
|---|---|---|
| `examples/policies/dev.yaml` | `dev` | `mode: monitor`, `fail_mode: open`. Detector actions match standard (PII `redact`, secrets `block`). The offline heuristic judge is used. Budgets are wide. `budget-demo` is 0.25 USD/day, not zero. |
| `examples/policies/standard.yaml` | `standard` | `mode: enforce`, `fail_mode: closed`. PII `redact`. Injection block 0.80, review 0.30. Judge is OpenRouter, grey zone only, threshold 0.70. Budgets match the shipped catalog, including `budget-demo` at 0 USD/day. |
| `examples/policies/strict.yaml` | `strict` | PII `block`. Injection block 0.60, review 0.15. Judge trigger `always`, threshold 0.50, `scan_output: true`, backend `heuristic`. Irreversible tools after untrusted context are `block`, not `approval`. Budgets, loop, input cap, and the transfer cap are tighter. |
| `examples/policies/bank-production.yaml` | `bank-production` | PII `block`. Duties are split: `bank-ops-agent` cannot transfer, `payments-agent` can only transfer, `research-agent` is read-only. Every agent pins `allowed_models`. Judge stays grey-zone only. `warn_at` is 0.70. |

`backend/policy.yaml` is the live catalog and the one the demo script expects. Its `profiles.dev` and `profiles.strict` overlays are the small switch set (monitor + fail-open; PII block, injection 0.60/0.15, semantic always at 0.50). The example files expand a full posture each, and each overlay in those files is `{}`.

## How a file becomes the live policy

`parse_policy` rejects a document whose stripped text is shorter than 50 characters, a root that is not a mapping, and a document missing `version`, `models`, or `agents`. Duplicate keys anywhere in the YAML are rejected. Unknown keys are rejected (`extra` is forbidden on every model).

`profile` selects an overlay from `profiles`. `deep_merge` copies the file, then overlays that profile: nested mappings merge, and any other value, including a list, replaces the base. The name `standard` is legal when `profiles` has no `standard` key. Any other name must be a key in `profiles` or the file is rejected.

An empty overlay changes nothing. That is why the example files put the posture in the body. Deleting a key inside an overlay does not delete the base key. To turn a control off from an overlay, set `enabled: false` or set the section to `null`.

Two different numbers are both called version:

- `version` in the YAML is a label (`Policy.version`). The snapshot exposes it as `policy.name`.
- `PolicyStore.version` is an integer counter. It starts at 1 after the first good load and increments on every applied reload. The snapshot exposes it as `policy.version`. Response header `X-AgentShield-Policy` is `<counter>:<hash>`.

The hash is the first 12 hex characters of SHA-256 over the UTF-8 text of the file.

## Hot reload and fail-safe

The app stats the policy file every 0.5 s (`POLL_INTERVAL_S` in `backend/app/main.py`). `PolicyStore.poll` applies a change after the mtime and size have stayed still for 0.15 s. The poller waits an extra 0.2 s when it first sees a change, so a save is live in under a second. Each request takes a new snapshot. A request already in flight keeps the snapshot it started with.

A good file replaces the in-memory policy and bumps the counter. A bad file does not. `apply_text` (the path behind `POST /api/policy`) parses first and only then writes a temp file and `os.replace`s it into place, so a rejected upload does not leave a broken catalog on disk. A raw editor save of a broken file is also rejected, and the previous policy keeps enforcing. Deleting the file is rejected the same way.

On apply, the store records `status: applied`, the new counter, the hash, `profile`, `mode`, `apply_ms`, and `changed`: dotted keys whose values differ. Keys under `profiles` are omitted from that diff. The list in the event is capped at 50. The gateway writes an audit row, kind `policy`, action `allow`, whose summary lists the changed keys.

On reject, the store records `status: rejected`, the error, and `active_version` / `active_hash` of the policy that is still enforcing. The gateway writes kind `policy`, action `block`, primary control `policy.rejected`. That id does not block traffic. It only marks the audit row. `GET /api/snapshot` shows the same fact under `policy.last_reload` (`status`, `error`, `changed`) while `policy.hash` stays on the last good file.

These edits are rejected:

- empty or truncated file, invalid YAML, or a root that is not a mapping
- missing `version`, `models`, or `agents`
- duplicate YAML keys, duplicate agent ids, or two agents whose resolved keys are equal
- a model, tool, profile, or kill-switch id that is not defined
- `review_threshold` greater than or equal to `block_threshold`
- an argument regex that does not compile
- a wrong enum (`action`, `direction`, `mode`, `fail_mode`, `backend`, label, entity, upstream)
- a number outside the bounds in the tables below
- any key that is not in this reference

`short_error` keeps the first line, at most 300 characters, or up to four pydantic errors. `POST /api/policy` and `POST /api/policy/profile/{name}` return HTTP 400 with `{status, error, version, hash, changed, rejected_hash}` when validation fails, and HTTP 200 with `{status, error: null, version, hash, changed}` when it applies. `version` and `hash` in that body are the active policy. `rejected_hash` is the hash of the text that was refused.

If `AGENTSHIELD_ADMIN_TOKEN` is set, policy writes, profile changes, detector toggles, approvals, and the kill switch require header `X-Admin-Token`. When it is unset, those routes are open. `GET /api/policy/raw`, `GET /api/snapshot`, and the other read routes do not check the token. The raw route returns the file bytes as text, with `X-Policy-Hash` and `X-Policy-Version`, not the merged view. After `set_profile("strict")` on the shipped catalog, the raw file still shows `pii.action: redact` in the body and `action: block` under `profiles.strict`. The snapshot and the next request use the merge, so PII blocks.

## Missing control section means disabled

This rule applies only to the six keys of `controls`: `prompt_injection`, `pii`, `secrets`, `signatures`, `canary`, `loop`.

If the key is absent, or the value is `null`, that control is disabled. The model defaults are not filled in. `controls.active(name)` is `None`, the gateway does not run that detector, and the snapshot shows `present: false`, `enabled: false`. Posture gains a gap `<name>.disabled`. An empty `controls: {}` disables all six.

If the key is present, omitted fields inside it do take the defaults in the tables below. `pii: {}` is enabled, action `redact`, all six entities, direction `both`. `enabled: false` on a present section also disables it (`active` is `None`) but the snapshot shows `present: true`.

`flow` and `semantic` are not under `controls`. Omitting `flow` uses `FlowCfg()`, which is enabled. Omitting `semantic` uses `SemanticCfg()`, which is enabled, backend `heuristic`, trigger `suspicious`, threshold 0.70. Turn them off with `flow.enabled: false` and `semantic.enabled: false`. A missing `semantic` key is not "judge disabled".

`POST /api/policy/detectors-off` is a process override, not a file edit. It sets `enabled: false` on `prompt_injection`, `pii`, `secrets`, `signatures`, `canary`, and `semantic`. It does not turn off `flow` or `loop`. The file hash does not change. The snapshot shows `overridden: true` and lists those names in `detectors_disabled`. `detectors-on` clears the detector and loop overrides and leaves a `flow` override in place if one was set. `POST /api/policy/toggle` with `{control, enabled}` accepts those six names plus `loop` and `flow`. An unknown control is HTTP 400, status `rejected`, and the hash is unchanged.

Flow still runs after detectors-off. The three flow rules are the only thing that stops a secret or untrusted tool result from leaving once the detectors are off. User-typed text is not tainted. Only a tool result the gateway itself mediated is labeled.

## What each posture changes on a request

`mode: monitor` rewrites findings whose action is block, redact, or require_approval into action `monitor`, and prefixes `detail` with `would_block`, `would_redact`, or `would_require_approval`. The original text is forwarded. These control-id prefixes are not downgraded: `auth.`, `budget.`, `model.`, `limits.`, `tools.kill_switch`. A zero USD budget still returns HTTP 429 in dev. That is why `examples/policies/dev.yaml` gives `budget-demo` 0.25 USD instead of 0: the monitor path stays visible. The other three samples keep the zero cap.

`fail_mode` is consulted only when the judge was supposed to run and did not return `allow` or `block` (`timeout`, `error`, `circuit_open`, `budget`). On grey-zone traffic, `closed` adds a block finding (`semantic.unavailable`, or `semantic.budget` when the judge's own USD line is spent). `open` adds a monitor finding and keeps the deterministic decision. Scores below `review_threshold`, and anything a detector already blocked, do not wait on the judge. `trigger: always` also calls the judge when nothing has blocked yet, including when the score is under the review threshold. `scan_output: true` extends that to output inspections. A judge verdict can add a block. It does not clear a deterministic block.

`block_response: error` returns the JSON error body. `message` returns HTTP 200 with an assistant refusal for a content block. Budget responses stay 429, and `auth.missing` / `auth.invalid` stay 401. `auth.impersonation` is 403. Approval required is 403 either way.

PII action `redact` masks spans in the forwarded copy when the winning action is redact. Action `block` does not forward the text. `redact` only rewrites `pii.*` spans. Setting `secrets`, `signatures`, or `canary` to `redact` records that action and does not mask the value. Injection `redact` is rewritten to `block` by the gateway. The samples use `block` for those controls.

The tool path stops before execution only for `block` and `require_approval`. A flow rule set to `redact` would not stop the tool. The samples use `block` or `approval`.

Posture score is `100 - sum(weight of each open gap)`, clamped to 0..100. Weights in `engine.posture`: monitor mode 25, auth disabled 20, flow disabled 20, prompt injection 15, PII 10, secrets 10, signatures 5, canary 3, loop 2, semantic disabled 5, fail-open 5, and 3 for each agent whose merged `usd_per_day` is null. A zero cap is a budget, not a gap. `GET /api/snapshot` returns the score, the formula, and the gap strings.

## Key reference

Defaults below apply when that section is present and the key is omitted. "Required" means the document or the parent object is rejected without it. Bounds are inclusive unless noted.

### Top level

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | string | required | Human label for this document. Not the reload counter. Example: `"2026.10.03"`. |
| `mode` | `enforce` or `monitor` | `enforce` | `enforce` applies the winning action. `monitor` logs what would have happened, with the exceptions above. |
| `profile` | string | `standard` | Overlay name merged on top of the body before validation. |
| `fail_mode` | `open` or `closed` | `closed` | Grey-zone behavior when the judge returns no verdict. |
| `require_auth` | bool | `true` | `true`: a missing bearer key is `auth.missing` (401). `false`: anonymous is accepted. An unknown key is `auth.invalid` (401) either way. A mismatched `X-Agent-Id` is `auth.impersonation` (403). |
| `block_response` | `error` or `message` | `error` | Shape of a content block. Does not change 401 or 429. |
| `max_input_chars` | int, ≥ 100 | `40000` | Sum of message content lengths. Over the cap: `limits.input_size`, HTTP 403. Empty `messages` is the same control. |
| `approval_ttl_s` | int, ≥ 5 | `120` | Seconds a pending approval stays usable. Single use, bound to agent, tool, canonical args, and policy hash. |
| `controls` | mapping | all six disabled | Detector sections. See the missing-section rule. |
| `flow` | mapping | enabled | Information-flow guard. Independent of `controls`. |
| `semantic` | mapping | enabled, heuristic | Grey-zone judge, plus its own USD cap. |
| `models` | mapping | required | At least the models agents are allowed to call. The mapping key is the name the client sends. |
| `budgets` | mapping | one `default` budget with every cap null | Named budgets. `budget_for` starts from the key `default`. |
| `agents` | list | required | One object per API key. |
| `tools` | mapping | `{}` | Tool catalog. A name not listed here is `tools.unknown`. |
| `mcp_servers` | mapping | `{}` | Accepted and stored. This tree does not start an MCP client. |
| `kill_switch` | list of agent ids | `[]` | Those agents get `tools.kill_switch` on chat and on tool calls. Not downgraded in monitor mode. Runtime `POST /api/kill/{id}` unions into this set until `DELETE`. An id still in the file stays killed. |
| `profiles` | mapping of mappings | `{}` | Overlays, keyed by profile name. Not a second catalog. |

### `controls.prompt_injection`

Present-section defaults. The control id on a hit is `injection.heuristic` or `injection.obfuscated` (OWASP LLM01).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false` skips the scorer. |
| `action` | `block`, `redact`, or `monitor` | `block` | Applied when the score is at or above `block_threshold`. `redact` is forced to `block`. |
| `direction` | `input`, `output`, or `both` | `input` | Which inspection direction runs the scorer. |
| `block_threshold` | float, 0..1 | `0.80` | At or above: block, no judge call. Must be greater than `review_threshold`. |
| `review_threshold` | float, 0..1 | `0.30` | At or above, and below the block threshold: grey zone. Findings are recorded as monitor, then the judge may raise them. |
| `scan_tool_results` | bool | `true` | Score tool-result text (indirect injection). `false` skips `source: tool`. |

### `controls.pii`

Control ids: `pii.email`, `pii.phone`, `pii.pesel`, `pii.nip`, `pii.iban`, `pii.credit_card` (LLM02). A bad PESEL, NIP, IBAN, or card checksum is not a finding. Names and balances are not entities.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false` skips PII. |
| `action` | `block`, `redact`, or `monitor` | `redact` | `redact` replaces spans in the forwarded text with `[PESEL]`, `[IBAN]`, `[EMAIL]`, and the same for the other entities. `block` stops the request. |
| `direction` | `input`, `output`, or `both` | `both` | User messages are input. Model output is output. |
| `entities` | list of `EMAIL`, `PHONE`, `PESEL`, `NIP`, `IBAN`, `CREDIT_CARD` | all six | Only listed entities are scanned. |

### `controls.secrets`

Control ids: `secrets.aws`, `secrets.github`, `secrets.openai`, `secrets.anthropic`, `secrets.openrouter`, `secrets.slack`, `secrets.google`, `secrets.stripe`, `secrets.pem`, `secrets.jwt`, `secrets.connstr`, `secrets.generic` (LLM02).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false` skips the secret scan. |
| `action` | `block`, `redact`, or `monitor` | `block` | Use `block`. `redact` does not mask a secret in the forwarded text. |
| `direction` | `input`, `output`, or `both` | `both` | Both, so a leaked key in a completion is caught. |

### `controls.signatures`

Control id: `signatures.<feed id>`. Direction output is tagged LLM05; other directions LLM03. The feed file is hot-reloaded on its own. A broken feed keeps the previous feed.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false` skips the feed. |
| `action` | `block`, `redact`, or `monitor` | `block` | Action passed into the feed scan. |
| `direction` | `input`, `output`, or `both` | `both` | Compared with each feed row's own direction. |
| `feed_file` | string | `feeds/signatures.yaml` | Relative to the policy file's directory if that path exists, otherwise `backend/feeds/signatures.yaml`. The samples use the default so a copy placed in `backend/` still resolves. |

### `controls.canary`

Control id: `canary` (LLM07). Literal token match. The gateway does not insert the token into the prompt.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false` skips the scan. |
| `action` | `block`, `redact`, or `monitor` | `block` | Action on a hit. |
| `direction` | `input`, `output`, or `both` | `output` | The shipped and sample files use `output`, so a token sitting in a user message is not this control. |
| `tokens` | list of strings | `["WRDN-CANARY-7F3A"]` | Any listed string is a hit. The bank sample adds `BANK-CANARY-2026`. |

### `controls.loop`

Control ids: `loop.repeat`, `loop.session_limit` (LLM10). Not part of detectors-off. No `direction` key; adding one rejects the file. State is in this process only.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false`, or a missing section, skips the guard. |
| `action` | `block`, `redact`, or `monitor` | `block` | Action when a limit trips. Monitor mode downgrades it. |
| `max_identical` | int, ≥ 1 | `3` | More than this many identical fingerprints inside the window fires `loop.repeat`. The fingerprint is the last chat message, or the tool name plus arguments. |
| `window_seconds` | int, ≥ 1 | `120` | Sliding window for the identical-message count. |
| `max_requests_per_session` | int, ≥ 1 | `60` | Session length cap. Fires `loop.session_limit`. The counter is not reset by the window. |

### `flow`

Not under `controls`. Default when the whole key is omitted: enabled, `min_chars` 12, rules block / block / approval. Control ids: `flow.secret_egress`, `flow.untrusted_target`, `flow.untrusted_before_irreversible` (LLM06).

A tool result is labeled from `tools.<name>.labels`. `secret` and `untrusted` are the labels the rules read. `internal` is a legal label and is stored, and these three rules do not match on it. F1 and F2 fire when a protected value from a gateway-mediated result in this session shows up again (folded alphanumeric, digit form, base64, hex, or URL-decoded). F4 fires when the session has any `untrusted` label and the tool is `irreversible`, even if the arguments do not contain the untrusted bytes. A value the user typed is not tainted.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false` is the only file setting that turns the guard off. |
| `min_chars` | int, ≥ 6 | `12` | Minimum length passed into the reuse check. Below 12 the matcher uses 6-character shingles. |
| `rules.secret_to_egress` | `block`, `redact`, or `monitor` | `block` | F1, when an egress tool's arguments contain a secret tool value. Use `block` or `monitor`. |
| `rules.untrusted_value_as_target` | `block`, `redact`, or `monitor` | `block` | F2, when a target argument contains an untrusted tool value. |
| `rules.untrusted_before_irreversible` | `approval`, `block`, or `monitor` | `approval` | F4. `approval` is `require_approval` and creates a pending approval. `block` does not offer that path. |

### `semantic`

Not under `controls`. The judge runs only when `enabled` is true, nothing has already blocked, and either the text is in the grey zone or `trigger` is `always`, and the direction is input or `scan_output` is true. PII spans are redacted before the text is sent. Remote text is truncated to 4000 characters and wrapped as data. Control ids: `semantic.judge` (a real verdict at or above `threshold`), `semantic.unavailable` (timeout, error, open breaker, missing key), `semantic.budget` (the judge's own daily USD). All LLM01.

`usd_per_day: 0` makes every call return status `budget` before a model is contacted. The samples keep it above zero. A missing `OPENROUTER_API_KEY` on backend `openrouter` or `openai` returns status `error` and does not raise. The heuristic backend does not read the key. `denied_topics` are a case-insensitive substring for `heuristic`, and a list in the prompt for a remote backend. Cache is 10 minutes, keyed by SHA-256 of the text plus `model`. The breaker opens after `breaker_failures` consecutive timeouts or errors, and the next call after `breaker_cooldown_s` is half-open.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | `false`: status `disabled`, no finding from the judge. Posture gap `semantic.disabled`. |
| `backend` | `openrouter`, `openai`, `ollama`, `heuristic`, `stub` | `heuristic` | `stub` is for tests (`[[risk=0.9]]`, `[[timeout]]`, `[[garbage]]`). |
| `model` | string | `google/gemini-2.5-flash-lite` | Remote model id. The heuristic samples set `heuristic` so the field is not a remote name. |
| `fallback_model` | string or null | `openai/gpt-4o-mini` | Second remote model after an error. `null` disables fallback. Ignored by heuristic and stub. |
| `base_url` | string | `https://openrouter.ai/api/v1` | OpenAI-compatible origin. The client posts to `<base_url>/chat/completions`. |
| `api_key_env` | string | `OPENROUTER_API_KEY` | Environment variable read for remote backends. The key is not stored in the policy. |
| `trigger` | `suspicious` or `always` | `suspicious` | `suspicious` is the grey zone only. `always` also judges clean-looking text that did not already block. |
| `threshold` | float, 0..1 | `0.70` | Risk at or above this becomes a `semantic.judge` finding with `action`. |
| `timeout_ms` | int, 50..10000 | `1200` | Covers the primary call and the fallback together. |
| `breaker_failures` | int, ≥ 1 | `3` | Consecutive timeout or error count that opens the breaker. |
| `breaker_cooldown_s` | int, ≥ 1 | `30` | Seconds before a half-open probe. |
| `usd_per_day` | float, ≥ 0 | `1.0` | Judge spend cap. Separate from agent budgets. Remote calls reserve an estimate; heuristic calls charge 0 but a cap of 0 still returns `budget`. |
| `action` | `block`, `redact`, or `monitor` | `block` | Action of a `semantic.judge` hit. |
| `scan_output` | bool | `false` | Also judge output inspections. |
| `denied_topics` | list of strings | `[]` | Topic list for the heuristic substring check and for the remote prompt. |

### `models.<name>`

The client-facing name is the mapping key (`mock/vulnerable-llm`, `openrouter/openai/gpt-4o-mini`). `model_allowed` requires the name to be in this mapping, and, when the agent sets `allowed_models`, in that list too. `allowed_models: null` or omitted means every name in `models`. A miss is `model.not_allowed` (LLM10, HTTP 403), and monitor mode does not downgrade it.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `upstream` | `mock`, `openrouter`, `openai`, or `ollama` | required | Where `complete` sends the chat. `mock` is the offline scripted model. |
| `upstream_model` | string or null | null | Model id sent to that upstream. Mock ignores it. |
| `base_url` | string or null | null | Per-model origin. The ollama row in the dev and standard samples sets `http://localhost:11434/v1`. |
| `input_per_1m` | float, ≥ 0 | `0` | USD per 1,000,000 input tokens. Used for the reservation and the settled cost. |
| `output_per_1m` | float, ≥ 0 | `0` | USD per 1,000,000 output tokens. The reservation prices `max_tokens` at this rate. |
| `compute_usd_per_second` | float, ≥ 0 | `0` | Added to the settled USD as `compute_s * price`. Not part of the reservation estimate. |

Where a sample lists the model, the prices are: mock 3.00 / 15.00, gpt-4o-mini 0.15 / 0.60, gemini flash-lite 0.10 / 0.40, ollama compute 0.0004 USD/s. Strict omits ollama. Bank-production lists only mock and gpt-4o-mini. Mock is priced, so the demo spends budget units with no network.

### `budgets.<name>` and `agents[].budget`

`budget_for(agent)` starts from `budgets.default` (or an all-null budget if that key is missing) and replaces only the fields set on the agent. A field left out of the agent is inherited. A field set on the agent replaces the default, including a lower one. There is no "agent caps cannot go below the default" rule.

A null cap skips that check. A cap of 0 blocks (`limit == 0`), including when the estimated USD is 0. `warn_at` is a fraction in `(0, 1]`. When the value is at or above `limit * warn_at` and not over the limit, the ledger adds a monitor finding and still admits the request. Crossing the limit blocks. Monitor mode does not downgrade `budget.*`.

Checked in `Ledger.reserve`, before the upstream call:

| Key | Control id | Default | Check |
|---|---|---|---|
| `max_tokens_per_request` | `budget.max_tokens` | null (no check); if set, ≥ 1 | Blocks when estimated input tokens (`ceil(len/4)`) plus the reserved output exceed the cap. Reserved output is the request's `max_tokens` or `max_completion_tokens` when the client sets one; otherwise `min(cap, 1024)`, or 1024 when the cap is null. |
| `requests_per_minute` | `budget.rpm` | null; if set, ≥ 0 | Requests admitted in the last 60 seconds, plus this one. Release does not refund the request count. |
| `tokens_per_minute` | `budget.tokens_per_minute` | null; if set, ≥ 0 | Tokens admitted in the last 60 seconds, plus this reservation. |
| `usd_per_day` | `budget.usd` | null; if set, ≥ 0 | Settled USD today, plus outstanding reservations, plus this reservation (`input estimate * input price + max output * output price`). |
| `compute_seconds_per_day` | `budget.compute` | null; if set, ≥ 0 | Settled compute seconds today. The in-flight request is not estimated, so one call can land past the cap; the next admission blocks once settled seconds are at or above the cap. |
| `warn_at` | (same id, action monitor) | `0.80` | Warning fraction for every cap that is set. |

The reservation is taken under a lock. A successful call settles on reported usage. An upstream exception settles the reserved input and max output (HTTP 502, the USD is not refunded). Day spend is rebuilt from the audit log on process start. The minute windows are memory in this process. HTTP status for every `budget.*` block is 429, and the mock model is not called.

Sample default budgets:

| | dev | standard | strict | bank-production |
|---|---|---|---|---|
| `usd_per_day` | 20 | 2 | 0.50 | 1 |
| `tokens_per_minute` | 200000 | 40000 | 10000 | 20000 |
| `requests_per_minute` | 600 | 120 | 30 | 30 |
| `max_tokens_per_request` | 8000 | 4000 | 1500 | 2000 |
| `compute_seconds_per_day` | 7200 | 900 | 120 | 300 |
| `warn_at` | 0.90 | 0.80 | 0.60 | 0.70 |

Agent USD overrides (other fields inherit unless the file sets them):

| Agent | dev | standard | strict | bank-production |
|---|---|---|---|---|
| `bank-ops-agent` | 5.00 | 0.50, and 2000 tokens/request | 0.10, 800 tokens/request, 10 rpm | 0.40, 1500 tokens/request, 20 rpm. No `transfer_funds`. |
| `payments-agent` | not in this file | not in this file | not in this file | 0.10, 800 tokens/request, 6 rpm. Transfer only. Inherits 20000 tokens/minute and `warn_at` 0.70. |
| `research-agent` | inherits 20 | inherits 2 | 0.05 | 0.20 |
| `judge-sandbox` | 2.00 | 1.00 | 0.20 | 0.50 |
| `budget-demo` | 0.25 | 0 | 0 | 0 |

### `agents[]`

Identity is the API key, compared in constant time. `api_key_env` wins when that variable is set; otherwise `api_key` is used. Demo keys are written into the catalog on purpose so the jury can call them. `GET /api/policy/raw` returns the loaded policy text, which includes those keys.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | required | Stable agent id. Unique in the file. `X-Agent-Id`, when sent, must match it. |
| `api_key` | string or null | null | Bearer token. Duplicate resolved keys are rejected. |
| `api_key_env` | string or null | null | Environment variable that overrides `api_key` when set. |
| `description` | string | `""` | Comment for operators. Not enforced. |
| `allowed_models` | list of model names, or null | null | `null` or omitted: every key in `models`. A list is exact. Unknown names are rejected at load. |
| `allowed_tools` | list of tool names | `[]` | Missing or empty means no tools (`tools.allowlist`). Unknown names are rejected at load. |
| `budget` | budget object or null | null | Field-wise override of `budgets.default`. |

Shipped demo keys, reused by every sample: `wk_bank_ops_demo`, `wk_research_demo`, `wk_judge`, `wk_budget_demo`. The bank sample adds `wk_payments_demo` on `payments-agent`.

### `tools.<name>`

Checked in order: kill switch, catalog (`tools.unknown`), agent allow-list (`tools.allowlist`), argument rules, then flow, then approval for `irreversible`. An approval does not override a kill switch, an allow-list miss, a failed argument rule, or a flow block. Duplicate JSON keys and non-objects are `tools.args`. All of these are LLM06 except where noted.

`arg_patterns` uses a full match and the value must be a string, so a missing argument fails. `deny_arg_patterns` uses a search over every string leaf. `max_values` requires a finite number (booleans fail) at or below the cap, so a missing amount fails closed. Argument regexes are not decoded before the match. Flow decoding is separate.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `labels` | list of `secret`, `untrusted`, `internal` | `[]` | Labels stored on the tool result. `secret` and `untrusted` feed the flow rules. |
| `egress` | bool | `false` | F1 applies to this tool's arguments. |
| `irreversible` | bool | `false` | Needs a matching approval, and F4 applies when the session has seen `untrusted`. |
| `target_args` | list of strings | `[]` | Argument names checked for untrusted values (F2). |
| `arg_patterns` | mapping of name to regex | `{}` | The argument must fully match. Control `tools.arg_pattern`. |
| `deny_arg_patterns` | mapping of name to regex | `{}` | Any string leaf that matches is `tools.arg_pattern`. |
| `max_values` | mapping of name to number | `{}` | Numeric ceiling. Control `tools.max_value`. |

Samples share the demo tools:

- `lookup_customer` — label `secret`
- `read_document` — label `untrusted`
- `send_email` — egress, target `to`, pattern `^[\w.+-]+@bank\.example$`. The bank sample also denies `ignore previous` and `system prompt` in `subject` and `body`.
- `transfer_funds` — egress, irreversible, target `iban`. Amount cap 10000 (dev, standard), 1000 (strict), 2500 (bank). The bank sample denies the same phrases in `reference`.

### `mcp_servers.<name>`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | string or null | null | Stored. `asgi://demo` in the samples is not dialed. |
| `command` | list of strings or null | null | Stored. No stdio MCP process is spawned. |

### `profiles.<name>`

Any mapping. It is not validated until that profile is selected and merged. The shipped `backend/policy.yaml` overlays, which `POST /api/policy/profile/{name}` switches without rewriting the rest of the body:

| Name | Overlay |
|---|---|
| `dev` | `mode: monitor`, `fail_mode: open` |
| `standard` | `{}` |
| `strict` | `controls.pii.action: block`, injection block 0.60 and review 0.15, `semantic.trigger: always`, `semantic.threshold: 0.50` |

`set_profile` rewrites the physical line that starts with `profile:` and keeps a trailing comment on that line. An unknown name is rejected and the file is not written. The example files only register their own profile, so `set_profile("strict")` against `dev.yaml` is rejected. To move the running gateway onto a sample, `POST /api/policy` with `{"yaml": "<the whole file>"}` or point `AGENTSHIELD_POLICY` at it and restart.

## What judges see when they change a rule

1. Edit `backend/policy.yaml` in an editor, or `POST /api/policy` with the new document. Within a second the snapshot `policy.hash` changes, `policy.version` (the counter) goes up by one, and `policy.last_reload.status` is `applied`. `changed` lists the dotted keys. The next `POST /v1/chat/completions` uses the new rules. Header `X-AgentShield-Policy` shows the new counter and hash. The audit feed gains a `policy` row.

2. Paste a short or broken document. HTTP 400, `status: rejected`, `error` explains the first problem, `hash` stays on the last good file. A following injection or PESEL request behaves as it did before the paste. The audit row says the edit was rejected and which version is still enforcing. The same happens if the file on disk is truncated or deleted: the process keeps the last good snapshot.

3. `POST /api/policy/profile/strict` on the shipped catalog. The raw YAML `profile:` line now says `strict`. Snapshot `policy.profile` is `strict` and `controls.pii.action` is `block`. A PESEL that was redacted is now blocked (`pii.pesel`, HTTP 403). `profile/dev` sets monitor and fail-open: the same PESEL is allowed through, the record action is `monitor`, and the detail starts with `would_redact`. Posture drops by 25 for monitor mode and by 5 for fail-open. `profile/nope` is HTTP 400 and changes nothing.

4. `POST /api/policy/detectors-off`. Hash unchanged. Snapshot `flow_enabled` stays true. `detectors_disabled` lists injection, PII, secrets, signatures, canary, and semantic. A PESEL is no longer redacted. `lookup_customer` then `send_email` of that IBAN is still blocked with `flow.secret_egress`. `detectors-on` restores the file's flags.

5. Delete the `pii:` block from a valid document and upload it. Status `applied`. Snapshot `controls.pii.present` is false. Posture gap `pii.disabled` (weight 10). PESEL text is forwarded. Put the block back and it enforces again. Set `flow.enabled: false` in a valid document and the flow block from step 4 stops happening. That is the one switch that disables flow.

6. `POST /api/kill/bank-ops-agent`, then a chat with `wk_bank_ops_demo`. HTTP 403, `tools.kill_switch`, including if mode is monitor. `DELETE /api/kill/bank-ops-agent` clears the runtime bit. An id written into `kill_switch` in the file stays off until the file changes.

7. Call `budget-demo` (`wk_budget_demo`) on standard, strict, or bank-production. HTTP 429, `budget.usd`, and the mock model does not run. On the dev sample the same key is a 0.25 USD cap, so a cheap call is admitted and a `warn_at` of 0.90 only warns once spend is near that cap.

8. On bank-production, `wk_bank_ops_demo` calling `transfer_funds` is `tools.allowlist`. `wk_payments_demo` can call it, amounts above 2500 are `tools.max_value`, and the first call without `X-Approval` is `tools.approval` (or `flow.untrusted_before_irreversible` when the session has read an untrusted document). The approval id comes back on the 403. `POST /api/approvals/{id}` with `{"approve": true}`, then the same call with header `X-Approval`, consumes it. A second retry needs a new approval. Switching the policy hash (any applied edit) invalidates an approval that was bound to the previous hash.
