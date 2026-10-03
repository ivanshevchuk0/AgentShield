# Security boundaries

AgentShield treats every client message, including `system` and `developer`, as
untrusted input for inspection. Shared decision models and agent API shapes are unchanged.

## Console access

Set `AGENTSHIELD_ADMIN_TOKEN` to a random token before starting the gateway:

```bash
export AGENTSHIELD_ADMIN_TOKEN="$(openssl rand -hex 32)"
make run
```

Enter the same token in the console Settings. All `/api/` endpoints and `/metrics`
require `X-Admin-Token`. Without a configured token they return 503; missing or
incorrect tokens return 401. Agent routes use their separate agent credentials.
Docker Compose forwards the admin token from `.env`.

The policy editor masks inline `api_key` values as `__AGENTSHIELD_REDACTED__`.
Saving an unchanged marker preserves the existing credential for that agent id,
including after list reordering. New identities need a real key or `api_key_env`.
Use environment-backed keys for deployments; repository demo keys are public.

## Flow and budgets

Tool-result exposure is tracked per authenticated agent across all client sessions.
Changing `X-Session`, changing a body session id, or omitting the header cannot
clear this history. Different authenticated agents have separate flow histories.
This is intentionally conservative: if an agent has seen a protected value,
typing the same value in a different session does not make it safe. Labels and
keyed fingerprints are saved as signed `flow_state` audit records before results
are returned; raw tool results are not stored. Restart restores this history when
the same audit directory and key are retained. Audit write failure stops dispatch.

Only one completion choice is supported (`n` omitted or `1`). Token limits must
be positive JSON integers; booleans, strings, nulls, and conflicting limit fields
are rejected with 400. The gateway forwards exactly the output limit it reserves,
including its default. Input reservation estimates include tool schemas and other
provider payload fields. Input token accounting is still an estimate.

## Audit availability

A durable dispatch admission is written before a model request or tool execution.
If that write fails, dispatch is stopped. If the final result write fails after an
operation, the gateway returns 503 and blocks subsequent operations; it cannot
undo a provider call or tool side effect that has already completed. Health becomes
503 as well. Repair audit persistence and restart after verifying the chain.

Run the offline regressions with `python3 -m pytest tests/test_security_regressions.py`.

## Request and response inspection

HTTP request bodies are limited to 1 MiB before JSON parsing across gateway,
console, and MCP routes. Requests over the limit return 413, including streamed
bodies without an accurate Content-Length. Policy input and budget limits still
apply after parsing.

Assistant `content` and `refusal` text receive the same output checks. Provider
extensions that the gateway cannot inspect (reasoning, audio, annotations,
logprobs, and arbitrary extra fields) are omitted from the returned completion.
Only the supported text/function-call subset is exposed.

PII redaction requires reliable original-text offsets. Encoded or normalized
sensitive text that cannot be safely redacted is blocked in enforce mode; the
same applies to unsupported secret-redaction policies. Audit excerpts use the
full privacy catalog independently of enabled controls and omit evidence that
cannot be safely masked. Classifier input uses the full PII catalog as well.

MCP inspection covers nested tool schemas, embedded text resources, structured
results, and server error text. Opaque image/audio/blob results are unsupported
and withheld because this gateway only inspects text.

## Remaining review limitations

The semantic judge currently evaluates at most the first 4,000 characters of
an input. Its verdict does not establish coverage of longer message suffixes.
Client-supplied chat tool schemas and historical tool-call arguments are included
in budget estimates but are not comprehensively inspected as message text.
These remain follow-up work; the regression suite does not establish complete
prompt-injection protection.
