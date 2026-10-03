# AgentShield threat model

Date: 2026-10-03. Scope is the control layer described in `docs/CONTRACTS.md` and implemented under `backend/app/`. This document does not add controls.

AgentShield is an inline gateway in front of a chat model and a small tool catalog. It authenticates an agent by API key, inspects text that crosses the gateway, authorizes tool calls, and appends an HMAC audit record. It is not a host agent, a sandbox, a vector store, or a patch for the products named in the signature feed.

Normative control ids are the list in `docs/CONTRACTS.md`. OWASP LLM tags on decision records come from `engine.owasp_for` (same mapping as the contract, with two extra rules: `auth.*` is tagged LLM06, and `model.*` is tagged LLM10). Signatures are tagged LLM03 on input and LLM05 on output.

## 1. Assets

| Asset | Where it lives | What the gateway does with it |
|---|---|---|
| Customer and payment data | Tool results (`lookup_customer` returns a name, PESEL `44051401359`, IBAN `PL61109010140000071219812874`, and a balance) and any of the same entity types in prompts or model output | PII entities in policy are EMAIL, PHONE, PESEL, NIP, IBAN, CREDIT_CARD. Default action is redact. Names and balances are not entities. |
| Credentials in transit | Prompts, tool results, model output | `secrets.*` patterns (AWS, GitHub, OpenAI, Anthropic, OpenRouter, Slack, Google, Stripe, PEM, JWT, connection strings, generic assignments). Evidence stored with `mask`, never the raw value. |
| Agent API keys | `agents[].api_key` in `backend/policy.yaml`, or `api_key_env` | Constant-time compare (`hmac.compare_digest`). The shipped policy contains public demo keys. `GET /api/policy/raw` requires the admin token and masks inline keys. |
| Canary token | `controls.canary.tokens`, default `WRDN-CANARY-7F3A` | Scanned on output. The gateway does not plant the token into a system prompt. |
| Policy catalog | `backend/policy.yaml`, hot-reloaded | Last valid snapshot keeps enforcing when a write is empty, truncated, or fails validation. A missing control section disables that control. `flow` stays enabled unless `flow.enabled: false`. |
| Audit trail | `audit.jsonl` plus `audit.head` under the data directory | HMAC-SHA256 over `prev + canonical JSON`. The HMAC key is `AGENTSHIELD_AUDIT_KEY`, else `data/audit.key` created on first start (mode `0600` when the OS allows). |
| Tool-call provenance | In-memory `TaintStore`; signed ids `call_w.<payload>.<hmac>` | Labels and hashes of protected spans from gateway-mediated tool results. Raw tool output is not kept in the store. Lost on process restart. |
| Approval journal | JSONL via `ApprovalStore` | Pending, approved, denied, consumed, expired. Arguments are stored as a SHA-256 of canonical JSON, not as the argument values. Single use, TTL `approval_ttl_s` (120). Bound to agent, tool, args hash, and policy hash. |
| Spend counters | In-memory `Ledger`, rebuilt for the current day from audit on startup | USD/day, tokens/minute, requests/minute, max tokens per request, compute seconds/day. The judge has a separate `semantic.usd_per_day`. |
| Signature feed | `backend/feeds/signatures.yaml` | Regex indicators. A rejected reload keeps the previous feed. |

## 2. Trust boundaries

```
agent / caller                untrusted
  |  Bearer key, X-Agent-Id, X-Session, X-Approval, messages, tool args
  v
AgentShield process           trusted only while the host and this process are intact
  |  policy snapshot, detectors, flow, ledger, audit HMAC, demo tools
  +--> model provider          content untrusted; the provider sees the forwarded prompt
  |      mock (in-process) | openrouter | openai | ollama
  +--> semantic judge          separate model call, grey zone only by default
  |      text is nonce-delimited; PII spans are redacted first; secrets are not
  +--> demo tools              in-process REGISTRY (database, files, email, payments)
  +--> policy file, feed,      local files; whoever can write them can change enforcement
       audit.jsonl, audit.head after the validators
dashboard HTTP                same process, port of the FastAPI app
```

Boundaries, and the assumption on each side:

- **Agent.** The caller is untrusted. A Bearer key selects the agent. A mismatched `X-Agent-Id` is `auth.impersonation`. An empty `allowed_tools` means no tools. A `tool_call_id` verifies only when it is `call_w.<payload>.<hmac>` for this process's call key; any other id is untrusted. The caller can still type a value itself. User-typed text is not tainted.
- **Gateway.** Trust ends at the process. The detectors, flow guard, allow-list, and audit chain all run here. A caller who never sends the traffic through `POST /v1/chat/completions` or `POST /v1/tools/call` is outside every control.
- **Model provider.** Output text and proposed tool calls are inspected after they return. The provider's own logs, training, and side channels are outside the gateway. `mock/vulnerable-llm` is deterministic and local. `openrouter`, `openai`, and `ollama` send the forwarded prompt to `base_url`.
- **Tools and MCP.** Runtime execution in `Gateway.tool_call` is `tools.run_tool` on the in-process registry. `policy.mcp_servers` is accepted by the schema (`bank-tools` is `asgi://demo` in the shipped file). No MCP client, tool-list fetch, or description pin exists in `backend/app/`. A tool that the agent calls on its own is out of band.
- **Policy file.** `PolicyStore` rejects an empty or invalid file and keeps the last good policy. It does not authenticate the writer on disk. All console reads and writes require `X-Admin-Token`; without `AGENTSHIELD_ADMIN_TOKEN`, console APIs are disabled.
- **Audit log.** `verify()` detects an edit, reorder, deletion, or tail truncation when `audit.head` is the checkpoint that was written with the log. Replacing the log and the head together is not detectable from inside the directory. Console read endpoints require admin authentication. Admission is persisted before dispatch; persistence failure stops further operations with 503.

Demo tools that matter to the boundary: `lookup_customer` is labeled `secret`; `read_document` is labeled `untrusted` (the fixture `invoice-7` carries a hidden instruction, including a zero-width variant); `send_email` is egress with `to` restricted to `@bank.example`; `transfer_funds` is egress and irreversible, `amount` max 10000, and needs a human approval.

## 3. Controls that exist

Enforcement order on chat: auth, kill switch, input size, model allow-list, loop guard, per-message inspect, budget reserve, upstream, output inspect, tool-call authorization, audit. On `POST /v1/tools/call`: auth, loop, allow-list, argument rules, flow, approval, execute, taint, inspect the result, audit.

`mode: monitor` rewrites block, redact, and require-approval findings to monitor, except ids that start with `auth.`, `budget.`, `model.`, `limits.`, or `tools.kill_switch`. Those still enforce. The dashboard "detectors off" override disables `prompt_injection`, `pii`, `secrets`, `signatures`, `canary`, and `semantic`. It leaves flow, loop, auth, budgets, tool rules, and the kill switch on.

| Family | Ids the code emits | Default effect |
|---|---|---|
| PII | `pii.email` `pii.phone` `pii.pesel` `pii.nip` `pii.iban` `pii.credit_card` | Redact spanned matches. PESEL, NIP, IBAN, and card require a valid checksum. |
| Secrets | `secrets.aws` `secrets.github` `secrets.openai` `secrets.anthropic` `secrets.openrouter` `secrets.slack` `secrets.google` `secrets.stripe` `secrets.pem` `secrets.jwt` `secrets.connstr` `secrets.generic` | Block. |
| Injection | `injection.heuristic` `injection.obfuscated` | Score `1-Π(1-w)` over EN/PL/UK/RU/DE phrase rules. A match that exists only in a decoded view adds 0.2 and `injection.obfuscated`. Score ≥ 0.80 blocks without a judge. Score in [0.30, 0.80) is the grey zone. |
| Signatures | `signatures.<feed id>` | Block on regex match in the configured direction. Ids in the shipped feed are listed in §5. |
| Canary | `canary` | Block when a configured token appears. Default direction is output. |
| Judge | `semantic.judge` `semantic.unavailable` `semantic.budget` | Called only when nothing has already blocked, and only for grey-zone input unless `semantic.trigger` is `always`. `scan_output` is false in the shipped policy. A verdict can add a block. It does not clear a deterministic block. Grey-zone traffic with a dead judge follows `fail_mode` (`closed` blocks, `open` allows). |
| Flow | `flow.secret_egress` `flow.untrusted_target` `flow.untrusted_before_irreversible` | F1 block, F2 block, F4 approval. Independent of the detector toggles. |
| Tools | `tools.allowlist` `tools.unknown` `tools.args` `tools.arg_pattern` `tools.max_value` `tools.approval` `tools.kill_switch` | Unknown tool, tool not on the agent's list, bad JSON, pattern miss, value over max, missing single-use approval, kill switch. An approval never overrides the allow-list, the kill switch, or a flow block. |
| Loop | `loop.repeat` `loop.session_limit` | More than 3 identical fingerprints in 120 seconds, or more than 60 requests in the session. |
| Budget | `budget.usd` `budget.tokens_per_minute` `budget.rpm` `budget.max_tokens` `budget.compute` | Reservation before dispatch. HTTP 429. Crossing `warn_at` (0.80) records a monitor finding. |
| Auth | `auth.missing` `auth.invalid` `auth.impersonation` | 401, 401, 403. |
| Model and size | `model.not_allowed` `limits.input_size` | Exact model name must be in `models` and, when the agent sets `allowed_models`, on that list. Input cap is `max_input_chars` (40000). |

`policy.rejected` appears on audit rows when a reload is refused. It is not in the contract control list and it does not block traffic; the previous policy stays in force.

Views used by the scanners, from the contract: original, folded (NFKC, invisible and tag characters removed, homoglyphs, Polish and Ukrainian diacritics, lowercase), collapsed spacing, unicode-tag decode when those characters are present, and one level of base64 or hex for tokens of at least 16 characters under a 4096-byte cap with a printable ratio of at least 0.85. Flow argument checks also URL-decode.

## 4. Threats

ATLAS ids marked **certain** are the published technique ids checked for this document: LLM Prompt Injection `AML.T0051` with Direct `AML.T0051.000` and Indirect `AML.T0051.001`, LLM Jailbreak `AML.T0054`, LLM Data Leakage `AML.T0057`. Ids marked **older matrix** appear in MITRE SAFE-AI material and may have been renamed on the current atlas.mitre.org matrix: ML Supply Chain Compromise `AML.T0010`, Exfiltration via ML Inference API `AML.T0024`, LLM Plugin Compromise `AML.T0053`. Names with no id in the last column were not assigned a number here.

LLM ids are the 2025 list: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.

ASI ids are the OWASP Top 10 for Agentic Applications (published 2025-12-09, also circulated as the 2026 edition): ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.

| Threat | Control ids | LLM 2025 | ASI | ATLAS |
|---|---|---|---|---|
| Direct instruction override, role tokens (`<|im_start|>`, `[INST]`, `### system`), "reveal the system prompt", DAN, developer mode, Policy Puppetry | `injection.heuristic`; `signatures.dan`, `signatures.developer_mode`, `signatures.policy_puppetry`; grey zone: `semantic.judge` | LLM01 | ASI01 | `AML.T0051.000` certain; `AML.T0054` certain for the jailbreak rows |
| Same payload hidden by zero-width or bidi characters, homoglyphs, spaced letters, or one level of base64/hex/unicode tags | `injection.obfuscated` when the phrase hits only after a view; the same signature rows if the decoded text matches | LLM01 | ASI01 | `AML.T0051` certain. "LLM Prompt Obfuscation" is on the current matrix; **id not confirmed** |
| Indirect injection in a mediated tool result (demo: `read_document` / `invoice-7`, including the zero-width variant) | `injection.*` with `scan_tool_results: true` and `source=tool`; result also labeled `untrusted` for flow | LLM01 | ASI01. Persistent memory is ASI06; this store is session-scoped and in-memory, so ASI06 coverage is the session only | `AML.T0051.001` certain |
| PII in a prompt or a completion (email, phone, valid PESEL, valid NIP, valid IBAN, Luhn card) | `pii.email` `pii.phone` `pii.pesel` `pii.nip` `pii.iban` `pii.credit_card` | LLM02 | ASI03 only for data the agent is about to pass on; the control is disclosure, not authorization | `AML.T0057` certain |
| Provider-shaped secrets and generic `key`/`password`/`token` assignments | `secrets.aws` `secrets.github` `secrets.openai` `secrets.anthropic` `secrets.openrouter` `secrets.slack` `secrets.google` `secrets.stripe` `secrets.pem` `secrets.jwt` `secrets.connstr` `secrets.generic` | LLM02 | ASI03 when the secret is an inherited credential | `AML.T0057` certain |
| System-prompt or canary echo on the model output | `canary` if the configured literal is present. Phrase rules cover "reveal system prompt" on input only | LLM07 | ASI01 when the leak is the attacker's goal | "Extract LLM System Prompt" is on the current matrix; **id not confirmed** |
| Model output that is shell, `eval`/`exec`, a reverse shell, encoded PowerShell, `rm -rf /`, a metadata IP, or a path traversal | `signatures.curl_bash` `signatures.os_system` `signatures.subprocess` `signatures.eval` `signatures.exec` `signatures.import` `signatures.shell_reverse` `signatures.powershell_encoded` `signatures.destructive_rm` `signatures.metadata_ssrf` `signatures.path_traversal` | LLM05 (output tag). Input matches are tagged LLM03 by `owasp_for` | ASI05 for the code-execution strings; ASI02 when the string is a tool argument | `AML.T0053` older matrix (plugin / tool compromise). No OS sandbox is claimed |
| Markdown image with an `http(s)` URL on model output (EchoLeak class) | `signatures.markdown_image_exfil` (direction output) | LLM05 | ASI02 | `AML.T0057` certain for the data-leak goal. "LLM Response Rendering" is on the current matrix; **id not confirmed** |
| Text that mentions or contains a known AI-infra exploit pattern (table in §5) | `signatures.<id>` for that feed row | LLM03 on input, LLM05 on output | ASI04 | `AML.T0010` older matrix. The feed does not scan files, images, or weights |
| Secret tool output copied into an egress tool argument | `flow.secret_egress` | LLM06 | ASI02, ASI01 | "Exfiltration via AI Agent Tool Invocation" is on the current matrix; **id not confirmed**. `AML.T0024` older matrix is inference-API exfil, a related but different channel |
| A value from untrusted tool output placed in a target argument (`to`, `iban`) | `flow.untrusted_target` | LLM06 | ASI01, ASI02 | `AML.T0051.001` certain as the enabling step |
| Any untrusted label in the session before an irreversible tool | `flow.untrusted_before_irreversible` | LLM06 | ASI02, ASI09 | none with a confirmed id. The effect is a human gate, not detection of the payload |
| Tool not in the catalog, or not on this agent's list | `tools.unknown` `tools.allowlist` | LLM06 | ASI02, ASI03 | `AML.T0053` older matrix |
| Duplicate JSON keys, non-object args, pattern miss, numeric max exceeded | `tools.args` `tools.arg_pattern` `tools.max_value` | LLM06 | ASI02 | none with a confirmed id |
| Irreversible tool without a live, single-use, hash-bound approval | `tools.approval` | LLM06 | ASI02, ASI09 | none with a confirmed id |
| Agent placed on the kill switch | `tools.kill_switch` | LLM06 | ASI10 for "stop this agent"; there is no drift detector | none with a confirmed id |
| Missing key, unknown key, or `X-Agent-Id` that does not match the key | `auth.missing` `auth.invalid` `auth.impersonation` | LLM06 (tag the gateway writes) | ASI03 | none with a confirmed id. This is application authentication, not an ML technique |
| Model name absent from the catalog or from the agent's `allowed_models` | `model.not_allowed` | LLM10 (tag the gateway writes). The risk also sits beside LLM03 and LLM06 | ASI03, ASI04 | `AML.T0010` older matrix, and only for "this name is not on the list" |
| Input over `max_input_chars`, empty `messages`, identical retries, session length, reserved spend, judge daily USD | `limits.input_size` `loop.repeat` `loop.session_limit` `budget.usd` `budget.tokens_per_minute` `budget.rpm` `budget.max_tokens` `budget.compute` `semantic.budget`; `signatures.fork_bomb` is a text match only | LLM10 | ASI08 only as a local brake on one session. Multi-agent cascade is not modeled | "Cost Harvesting" is on the current matrix; **id not confirmed** |
| Grey-zone text the phrase list does not fully explain, including the two denied topics in policy (material non-public information; personalised investment advice) | `semantic.judge` when the judge runs. Denied topics are judge categories, not their own ids | LLM01 for the record tag. The two topics are the only LLM09-related check, and only inside the judge | ASI01 | `AML.T0051` certain when the text is an injection. No ATLAS id is claimed for the denied-topic list |
| Judge timeout, breaker open, malformed verdict, missing API key, or judge budget exhausted on grey-zone traffic | `semantic.unavailable` or `semantic.budget`, then `fail_mode` | LLM01 | ASI08 for the breaker (one component fails closed or open) | none |

Rows with no control id, stated so they are not implied:

| Threat | Why it is out of scope |
|---|---|
| LLM04 training, fine-tune, or weight poisoning | No training pipeline and no weight loader. A `torch.load(` string in a prompt is an indicator, not a scan of a checkpoint file. |
| LLM08 embedding or vector-store attacks | No retrieval index. |
| LLM09 false answers beyond the two denied topics | No fact check. The judge must be in the path, and `scan_output` is false, so a fluent false completion is not scored. |
| ASI06 long-term memory or RAG poisoning | Taint and loop state die with the process. Nothing is written into a memory the next session reloads. |
| ASI07 agent-to-agent messages | One gateway, one caller. No second agent channel to authenticate. |
| A stolen Bearer key used as itself | The key is the identity. `auth.impersonation` covers a mismatched header, not theft of the key. |

## 5. Signature feed and CVEs

The feed is an offline regex list (`backend/feeds/signatures.yaml`, 28 rows). A hit means the text contained the pattern. It does not mean the named product is present, vulnerable, or patched. Several rows match the product name or the CVE id, so a sentence that discusses the CVE matches too. The loader rejects nested quantifiers; an invalid file does not replace a feed that already loaded.

| Feed id | CVE or reference | What the pattern actually matches |
|---|---|---|
| `torch_load` | CVE-2025-32434 | The text `torch.load(`. The CVE is unsafe checkpoint loading in PyTorch. The pattern is not a version check and does not open a file. |
| `keras_lambda` | CVE-2024-3660 | `keras.layers.Lambda(` or a Keras `class_name` of `Lambda`. The CVE is code execution when a Lambda layer is deserialized. |
| `shadowray` | CVE-2023-48022 | The word `shadowray`, `ray job submit`, the path `/api/jobs/`, or the CVE id. The CVE is unauthenticated job submission on Ray. `/api/jobs/` is broader than the advisory. |
| `langflow` | CVE-2025-3248 | The path `/api/v1/validate/code` or the CVE id. The CVE is unauthenticated code execution on that Langflow endpoint. |
| `mcp_inspector` | CVE-2025-49596 | The name `mcp inspector` (space or hyphen) or the CVE id. The CVE is unauthenticated use of MCP Inspector's proxy. The pattern does not speak the protocol. |
| `mcp_remote` | CVE-2025-6514 | The name `mcp-remote` or the CVE id. The CVE is command injection in that package. The pattern does not match a crafted authorization URL by itself. |
| `probllama` | CVE-2024-37032 | The word `probllama`, the CVE id, or `/api/create` followed within 120 characters by `../`. The CVE is path traversal on Ollama's create API. |
| `markdown_image_exfil` | CVE-2025-32711 | A markdown image whose URL is `http://` or `https://`, output direction only. The CVE (EchoLeak) is zero-click exfiltration through rendered model output. Reference-style links, HTML, and CSS are not this pattern. |
| `log4shell` | CVE-2021-44228 | `${` then optional space then `jndi:`. |
| `pickle`, `pickle_reduce` | Python pickle docs | `pickle.load(`, `pickle.loads(`, `pickle.Unpickler(`, `__reduce__`, `__reduce_ex__`. |
| `trust_remote_code` | Hugging Face transformers docs | `trust_remote_code` set to `true`. |
| `unsafe_yaml` | PyYAML docs | `!!python/object`, `!!python/name`, `!!python/module`. |
| `curl_bash` | command injection | `curl` or `wget` piped to `bash` or `sh` on one line. |
| `os_system`, `subprocess`, `eval`, `exec`, `import` | Python docs | Those call shapes. |
| `shell_reverse` | command injection | `bash -i >& /dev/tcp/` or the `sh` form. |
| `powershell_encoded` | command injection | `powershell` with `-enc` or `-encodedcommand`. |
| `metadata_ssrf` | SSRF | `169.254.169.254` or `metadata.google.internal`. |
| `path_traversal` | path traversal | `../`, `..\`, or the URL-encoded forms. |
| `destructive_rm` | command injection | `rm -rf /` (and the listed flag variants) at the root. |
| `fork_bomb` | fork bomb | The classic `:(){ :|:& };:` spelling. |
| `dan`, `developer_mode`, `policy_puppetry` | LLM01 references | The listed jailbreak phrases, input direction. |

## 6. What each control does not stop

**Injection phrases and the obfuscated-view bonus.** Messages with `role: system` are not inspected on the chat path, so a payload placed there is forwarded and is not scored. A paraphrase that shares no listed imperative stays under the review threshold and is allowed without a judge call. Benign wording such as "ignore the previous draft" is specified to stay low, so nearby phrasing can too. Decode covers one nesting level, a 4096-byte cap, and a printable ratio of 0.85. A second encoding, a binary blob, or an image is invisible to the views. The judge does not run on output unless `scan_output` is turned on. In `mode: monitor` a high score is recorded and the text is still forwarded.

**PII redact.** A PESEL, NIP, IBAN, or card with a bad checksum is not a finding. That is deliberate. Entity types outside the six names are not scanned (person names, postal addresses, account balances, dates of birth). A match that exists only in a decoded view has no original span, and `redact()` ignores findings without spans, so the forwarded string can still contain that encoding. Overlapping spans are applied right to left. A value split across two messages is two separate inspects. `role: system` messages are not inspected and are forwarded as the caller wrote them. Redaction is applied to the forwarded copy only when the decision action is redact, so `mode: monitor` leaves the original text in place.

**Secret patterns.** Low entropy, fewer than five distinct characters, or a listed placeholder (`password`, `changeme`, `your_api_key`, and the other literals in the scanner) does not match `secrets.generic`. Formats that are not in the pattern list do not match. A secret split across messages, or carried as a hash the pattern does not recognize, does not match. JWT matches require a three-part token whose header and payload are JSON and whose header has a string `alg`.

**Canary.** The control is a literal scan. A system prompt that leaks without the token is untouched by `canary`. The gateway does not insert the token. Direction in the shipped policy is output, so the token sitting in a user message is not this control. Anyone who can read the policy file or `GET /api/policy/raw` knows the token.

**Signatures.** They are strings on text the gateway is shown. They do not patch CVE-2025-32434, CVE-2024-3660, CVE-2023-48022, CVE-2025-3248, CVE-2025-49596, CVE-2025-6514, CVE-2024-37032, CVE-2025-32711, or CVE-2021-44228, and they do not see traffic aimed at Ray, Langflow, Ollama, or MCP Inspector directly. A pickle payload that is not the source text `pickle.loads(` does not match. EchoLeak variants that are not a markdown image with an http URL do not match, and that row does not run on input. A fork-bomb string is not a process limit.

**Semantic judge.** It is skipped when a deterministic block already fired, and on output while `scan_output` is false. Below the review threshold it is not called (`trigger: suspicious`). With `fail_mode: open`, a grey-zone request is allowed when the judge times out, the breaker is open, the verdict is garbage, the daily USD line is spent, or the API key is missing. The shipped `fail_mode` is `closed`, which blocks that grey-zone case. The remote judge receives the text after PII redaction only; a secret that did not itself block would be in that body. Untrusted text is wrapped in a random nonce and truncated to 4000 characters. That reduces prompt injection against the judge. It does not make the judge a trusted party. Cache is 10 minutes keyed by SHA-256 of text plus model. The heuristic backend is keywords plus `denied_topics`, not a second opinion from a model. No key produces status `error` and does not raise out of `classify`.

**Flow.** F1 fires when a protected value from a **gateway-mediated** tool result in this session reappears in an egress tool's arguments. F2 fires when an untrusted value reappears in a listed target argument. F4 fires when the session has any `untrusted` label and the tool is irreversible. A value the user typed is not tainted, including a copy of an IBAN the user already saw. A tool the agent calls without going through the gateway is invisible. Paraphrase that breaks the folded alphanumeric match, the digit run, the email, the IBAN-like token, or the 12-character shingle (6 when `min_chars` is lowered) is invisible. `min_chars` is 12 in policy, so a shorter secret relies on the entity patterns (digit runs of at least 8, emails, IBAN-like tokens). Matching also looks at base64, hex, and URL-decoded forms of the arguments. Flow state is memory in this process. There is no F3 and no F5 or F6. `flow.enabled: false` turns the three rules off. Monitor mode downgrades them.

**Tool allow-list, argument rules, approval, kill switch.** Rules exist only for tools in `policy.tools` and only on calls the gateway authorizes. `send_email.to` must match `^[\w.+-]+@bank\.example$`. `transfer_funds.amount` must be a number ≤ 10000. Other argument names have no rule unless the policy adds one. `tools.arg_pattern` does not decode the argument before the regex. Approval is one shot, 120 seconds, same agent, same tool, same canonical args, same policy hash. The journal stores the hash, so an approver who only has the approval row does not see the IBAN or the amount. A flow block or a kill switch still wins over an approval. The kill switch stops that agent id at this gateway. It does not revoke a key already copied, and it does not stop a process that is not this gateway.

**Auth.** Missing and unknown keys are rejected when `require_auth` is true. A correct key is the agent, even if a person stole it. There is no user directory, no mTLS, and no per-tool credential toward a bank. Demo keys are in the policy file that the raw-policy route serves.

**Model allow-list and budgets.** `model.not_allowed` is an exact configured name. It does not inspect the weights behind an allowed name. Budgets reserve `max_tokens × price` before dispatch and settle on reported usage. The token estimate used at reserve time is `ceil(len/4)`. Compute limits apply when the model sets `compute_usd_per_second` (the ollama row). A request that is allowed still costs money at the provider. `warn_at` does not block. Loop state is per process, not a shared counter across replicas. `signatures.fork_bomb` does not stop a loop that never prints that string.

**Policy reload and audit.** A bad file does not change the live policy. A good file does, including a good file that sets `mode: monitor`, deletes a control section, or sets `flow.enabled: false`. Disk writes are not authenticated. The HMAC chain does not survive replacement of both `audit.jsonl` and `audit.head`. Findings in the log use masked snippets (two characters kept at each end, twelve stars at most), offsets, and control ids. That is not a hash of the value. The in-memory flow store is the component that keeps hashes.

**Dashboard access.** Snapshot, events, raw policy, approval list, audit export, report, metrics, and console writes require the admin token. With no `AGENTSHIELD_ADMIN_TOKEN`, these endpoints return 503. The static dashboard remains accessible so operators can enter their token in Settings.

## 7. Residual risk

These are the gaps a reviewer can hit with the system as built.

1. **Compromised gateway host.** Whoever can debug the process, read `data/audit.key`, or replace `policy.yaml` with a valid file owns enforcement and the audit key. No control runs above the process.
2. **Out-of-band tools.** An agent with its own HTTP client, shell, or MCP session that does not pass through `POST /v1/tools/call` is not allow-listed, not tainted, and not scanned.
3. **Paraphrase and channel mismatch.** Flow looks for the same value (folded, digit-only, or a shingle), including inside base64, hex, and URL encoding. A summary, a translation, or a screenshot does not match. Markdown-image exfil is one output pattern. Email body text that does not contain a tracked secret does not raise F1.
4. **Checksum and entity gaps.** Invalid PESEL, NIP, IBAN, and card numbers are forwarded on purpose. Names and balances from `lookup_customer` are not PII entities.
5. **Judge dependence in the grey zone.** Clear blocks stay local. Ambiguous text depends on the judge or on `fail_mode`. The dev profile sets `fail_mode: open` and `mode: monitor`.
6. **Remote model and remote judge.** OpenRouter and the configured judge see text the gateway forwards. The judge call redacts PII spans and leaves everything else, including a secret that did not itself block. The upstream body keeps caller `role: system` messages unchanged. Other roles are replaced only when the inspect action is redact. Output blocking happens after the provider has already generated the completion.
7. **Unauthenticated reads, and an optional admin token.** Policy source, including inline demo keys and the canary, is readable. Approval decisions are a boolean over an args hash.
8. **Session memory only.** Restart clears taint and loop counts. A poisoned document has to be read again through the gateway to be labeled again.
9. **Indicator feed false sense of patch.** Discussing CVE-2025-49596 in a prompt matches `signatures.mcp_inspector`. Sending the real MCP Inspector exploit to a process that is not this gateway matches nothing here.
10. **LLM04, LLM08, LLM09, ASI06 beyond the session, ASI07.** No component implements them. Denied topics are two strings on the judge.
11. **Monitor mode and detectors-off.** Both are supported and both are audited. Detectors-off still leaves flow. Monitor mode does not leave flow enforcing.

## 8. Roadmap

Only items already written in `docs/ARCHITECTURE.md` §1. Nothing else is promised.

After the current build, and only once the existing suite is green:

- Pin MCP tool descriptions, and add an MCP proxy if that work is reached. Today `mcp_servers` is configuration only.
- Run the judge and the upstream call speculatively in parallel. Today the judge runs in the grey zone before dispatch, and a deterministic block does not call it.
- Flow rules F3 through F6. Today the implemented rules are F1 `secret_to_egress`, F2 `untrusted_value_as_target`, and F4 `untrusted_before_irreversible`.

Explicitly cut, so they are not residual work hiding under another name: natural-language policy, shadow replay, an OCSF/CEF/framework matrix, a 12-way evasion matrix, a load-test writeup, Prometheus, Redis, Next.js, a multi-model consilium, and a honeytool.

## 9. Sources

- `docs/CONTRACTS.md` — control ids, OWASP tag map, module behavior.
- `docs/ARCHITECTURE.md` — trust decisions, cuts, and the later list. Where this file disagrees with the code, the code is what runs: audit evidence is `mask`, the HMAC environment variable is `AGENTSHIELD_AUDIT_KEY`, tool execution is the in-process registry, and the block body is the contract shape in `CONTRACTS.md`.
- `backend/app/policy.py`, `backend/policy.yaml` — catalog that is loaded.
- `backend/app/engine.py` — lifecycle, `owasp_for`, monitor-mode exceptions, judge gating, admin-token absence on read routes (`main.py`).
- `backend/app/flow.py`, `backend/app/governance.py`, `backend/app/guardrails/secrets.py`, `backend/app/guardrails/signatures.py`, `backend/feeds/signatures.yaml` — match conditions behind the limits in §6.
- OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10).
- OWASP Top 10 for Agentic Applications, 9 December 2025 (ASI01–ASI10).
- MITRE ATLAS technique pages and the SAFE-AI report for the ids marked certain or older-matrix. Unconfirmed ids are left blank on purpose.
