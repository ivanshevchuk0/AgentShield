# Semantic judge benchmark — 2026-10-03

## Recommendation

Use pinned `typesafe/jev-1.13`, with `qwen/qwen3.8-flash` as the independent chat fallback, and keep threshold **0.70**. Both classified all 90 cases correctly on each of three passes in the selection run and again in a separate threshold-0.70 validation run. This is corpus accuracy, not a production safety guarantee.

JEV is cheaper and faster: validation p50/p95 **609/810 ms**, versus Qwen **1775/2307 ms**. Pinning avoids silently changing classifiers through `~typesafe/jev-latest`; the alias is included for catalog completeness, not an independent replication. JEV's observed benign risk ceiling was 0.26 and attack floor 0.82 in the selection run. Keeping 0.70 provides separation without tuning to the sweep's highest perfect threshold (0.80).

Exact proposed block for the policy owner; **backend/policy.yaml was not edited**:

```yaml
semantic:
  enabled: true
  backend: openrouter
  model: typesafe/jev-1.13
  fallback_model: qwen/qwen3.8-flash
  base_url: https://openrouter.ai/api/v1
  api_key_env: OPENROUTER_API_KEY
  trigger: suspicious
  threshold: 0.70
  timeout_ms: 4000
  breaker_failures: 3
  breaker_cooldown_s: 30
  usd_per_day: 1.00
  action: block
  scan_output: false
  denied_topics:
    - material non-public information about listed companies
    - personalised investment advice
```

Keep the existing top-level `fail_mode: closed`. The 4000 ms timeout is deliberate: every Qwen selection sample exceeded 1200 ms, and two JEV samples exceeded 1200 ms. Both models returned 270/270 valid verdicts when separately re-tested with 4000 ms. The runtime shares this deadline across primary and fallback; fallback runs after eligible errors, **not after primary timeout**. A delayed primary error can still leave too little time for Qwen. These runs measure each model independently, not combined failover or Railway-hosted gateway latency. The policy owner must accept the higher worst-case grey-zone delay; clean and deterministic-block traffic does not invoke the judge.

## Model discovery

Fetched the public catalogs on 2026-10-03, retained verbatim:

- `reports/bench_judge_models.json`: `https://openrouter.ai/api/v1/models`.
- `reports/bench_judge_decision_models.json`: `https://openrouter.ai/api/v1/models?output_modalities=decisions`.

The unfiltered catalog omitted decision-output entries. The filtered endpoint returned **10**, all benchmarked, including `respan/span-01-lite`, its `:free` alias, and `~typesafe/jev-latest`. Runtime decision routing already supports these IDs. Decision requests use `/api/alpha/decisions`: category probabilities become `risk = 1 - P(safe)`; Respan uses the supported yes/no (`noul`) question and its manipulation probability.

Selected current cheap/fast chat families: GPT-6 Luna (catalog created September 22), Qwen 3.8 Flash (August 26), Gemini 3.8 Flash (September 2), Gemini 3.5 Flash-Lite (July 21), Grok 4.7 (September 21), Ling 3.1 Flash (October 2), plus the latest listed Haiku and Llama Scout families. Haiku 4.5 and Llama 4 Scout are older releases but were the newest listed members of those families. **Gemini 2.5 Flash-Lite is the sole superseded-generation baseline.** Batch variants were excluded because the gateway is synchronous. Catalog availability did not imply successful execution with the shipped judge request; failures remain in the table.

## Method and reproduction

`demo/bench_judge.py` already contained **90 unique cases**, so no corpus expansion was needed: 35 attacks, 16 classifier-targeting attacks, 39 benign look-alikes. Languages: EN 52, PL 10, UK 9, RU 10, DE 9. Examples cover covert transfers, fake authority, document-borne instructions, audit evasion, customer preferences, role-play, and bank-account administration.

- Selection: **19 models × 90 cases × 3 passes = 5130 attempts**, concurrency 6 per model, models sequential, timeout 5000 ms, reported threshold 0.50.
- Validation: JEV and Qwen, **540 additional attempts**, three identical passes, threshold 0.70, timeout 4000 ms, same concurrency.
- Real `Judge.classify`, shipped current prompts/parsers, reasoning disabled, temperature 0, chat output cap 80 tokens. No fallback during benchmarking. Each sample gets a fresh Judge: no application-cache hits, no breaker suppression, no artificial suffix changing repeated text. Provider-side caching is not disabled.
- Every remote benchmark invocation used `railway run --service agentshield-demo` from the linked repo, injecting the key into the subprocess. No credentials were printed or saved. This runs locally with Railway-injected configuration; it does not execute inside Railway's deployed container.
- Accuracy = correct/valid answers. Attack recall combines ordinary and judge-targeting attacks. FPR = blocked/valid benign answers. Latency measures completed valid classifications, excluding semaphore wait; p50 is median, p95 is nearest-index percentile. Failures are shown separately and **are not counted as correct attacks**. Fail-closed gateway behaviour would block unavailable benign requests too, so answer-only FPR understates operational rejection rates for failing models.
- Cost/1000 is total Judge-recorded cost divided by all attempts, including failures. `usage.cost` is used when available; the runtime otherwise estimates $0.001 per in-flight failure or missing usage. HTTP-rejected calls are recorded as zero. These are recorded charges/estimates, not a reconciled provider invoice.

Reproduce discovery:

```sh
curl -s https://openrouter.ai/api/v1/models -o reports/bench_judge_models.json
curl -s 'https://openrouter.ai/api/v1/models?output_modalities=decisions' -o reports/bench_judge_decision_models.json
```

Reproduce selection (the defaults in the script contain the same 19 IDs):

```sh
cd /Users/illialiudogovskyi/warden/repo
railway run --service agentshield-demo -- sh -c 'cd /Users/illialiudogovskyi/warden/wt-fix && python3 demo/bench_judge.py --repeat 3 --out reports/bench_judge.json'
```

Reproduce validation:

```sh
railway run --service agentshield-demo -- sh -c 'cd /Users/illialiudogovskyi/warden/wt-fix && python3 demo/bench_judge.py --models typesafe/jev-1.13,qwen/qwen3.8-flash --repeat 3 --threshold 0.7 --timeout-ms 4000 --out reports/bench_judge_validation.json'
```

## Selection results

Percentages are answer-only, at **threshold 0.50**. Each row attempted 270 calls. A dash means no valid verdict, not zero risk. Raw per-case risks, reasons, language accuracies and threshold sweeps are in `reports/bench_judge.json`.

| Model | Accuracy % | Attack recall % | Benign FPR % | p50 ms | p95 ms | USD/1k attempts | Failures/270 |
|---|---:|---:|---:|---:|---:|---:|---:|
| typesafe/jev-1.13 | 100 | 100 | 0 | 623.5 | 831.9 | 0.0260 | 0 |
| togethercomputer/tev1-4b-experimental | 93.3 | 94.1 | 7.8 | 619.4 | 848.5 | 0.0198 | 1 |
| liquid/d1 | 94.4 | 100 | 12.9 | 668.1 | 1145.4 | 0.0154 | 1 |
| inception/mercury-decide:free | 91.5 | 100 | 19.8 | 663.3 | 1170.4 | 0 | 70 |
| upstage/solar-decide | 100 | 100 | 0 | 1094.0 | 4014.5 | 0.1666 | 38 |
| jaredpalmer/kev-4b | 80.0 | 100 | 46.2 | 901.4 | 1192.8 | 0.0120 | 0 |
| respan/span-01 | 88.9 | 82.4 | 2.6 | 598.8 | 833.4 | 0.0069 | 0 |
| respan/span-01-lite | 88.9 | 82.4 | 2.6 | 589.6 | 752.2 | 0 | 0 |
| respan/span-01-lite:free | 90.8 | 86.2 | 2.3 | 583.8 | 755.8 | 0 | 53 |
| ~typesafe/jev-latest | 100 | 100 | 0 | 620.8 | 858.9 | 0.0260 | 0 |
| openai/gpt-6-luna | 98.1 | 98.0 | 1.7 | 1673.7 | 2608.2 | 0.0639 | 1 |
| qwen/qwen3.8-flash | 100 | 100 | 0 | 1876.1 | 2315.4 | 0.0888 | 0 |
| google/gemini-3.8-flash | — | — | — | — | — | 0 | 270 |
| google/gemini-3.5-flash-lite | — | — | — | — | — | 0 | 270 |
| x-ai/grok-4.7 | — | — | — | — | — | 0 | 270 |
| meta-llama/llama-4-scout | — | — | — | — | — | 0 | 270 |
| inclusionai/ling-3.1-flash | — | — | — | — | — | 0 | 270 |
| anthropic/claude-haiku-4.5 | 99.6 | 100 | 0.9 | 1768.3 | 2106.4 | 0.8161 | 1 |
| google/gemini-2.5-flash-lite (baseline) | 96.3 | 93.5 | 0 | 815.1 | 1108.7 | 0.0628 | 0 |

Failures: TEV one connection error; Liquid one timeout; Mercury 70 HTTP 429s; Solar 38 timeouts; Respan Lite Free 53 HTTP 429s; Luna one timeout; both current Geminis and Grok 270 HTTP 400s each; Scout 270 HTTP 404s; Ling 150 HTTP 400s and 120 HTTP 429s; Haiku one parsing `ValueError`. Error payloads were not retained; HTTP status alone does not establish whether request compatibility, routing, or provider availability caused rejection. These models are not viable recommendations with the current adapter and account based on this run.

At 0.50 the baseline caught only **79.2% of classifier-targeting attacks**, versus JEV/Qwen's 100%. Liquid reached perfect answer-only accuracy at 0.90, but that model-specific cut conflicts with the desired shared primary/fallback threshold. Respan's best recall under 5% FPR was 94.1% at 0.15; speed/free pricing does not compensate for the misses. Solar's perfect valid answers mask a 14.1% timeout rate.

## Validation and spend

`reports/bench_judge_validation.json`, threshold **0.70**, timeout **4000 ms**:

| Model | Valid | Accuracy % | Attack recall % | Benign FPR % | p50 / p95 ms | USD/1k attempts |
|---|---:|---:|---:|---:|---:|---:|
| typesafe/jev-1.13 | 270/270 | 100 | 100 | 0 | 608.6 / 809.6 | 0.0260 |
| qwen/qwen3.8-flash | 270/270 | 100 | 100 | 0 | 1774.7 / 2306.9 | 0.0889 |

Combined recorded spend: **$0.383154**, comfortably below the $2 task ceiling. No older-generation fallback was added just to obtain a successful row.

## Limits and owner follow-up

This is a hand-authored development corpus, not a held-out or independently labelled security evaluation. The existing classifier prompt explicitly describes some corpus look-alikes. Repeats measure runtime variability, not 270 independent semantic examples; the second run is configuration validation, not held-out validation. English dominates. Denied-topic enforcement, arbitrary long documents, PII-redaction integration, gateway admission, adversarial adaptation, combined failover, and deployed-network latency are not established by these numbers. Some cases are clean or deterministic-block traffic; the benchmark forces classification rather than claiming every case actually enters the grey zone.

Policy owner: review and apply the proposed block and timeout trade-off. Guardrails owner: investigate advertised chat-model HTTP failures without exposing provider payloads or credentials. Neither backend file was changed here. Before the pitch, confirm the deployed policy and do a live grey-zone smoke test; do not present 100% on this corpus as universal attack detection.
