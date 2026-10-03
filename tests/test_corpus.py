"""Corpus regression: every row of tests/corpus/cases.yaml through Gateway.inspect (offline).

Writes per-control TPR/FPR + inspect latency p50/p99 to reports/last-run.json (dashboard reads it).
The judge runs on the deterministic `heuristic` backend (override: CORPUS_JUDGE=stub).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import statistics
import time
import uuid
from pathlib import Path

import pytest
import yaml

from app.models import Action, Context
from app.policy import PolicyStore

ROOT = Path(__file__).resolve().parents[1]
CASES_FILE = ROOT / "tests" / "corpus" / "cases.yaml"
REPORT_FILE = ROOT / "reports" / "last-run.json"

CASES: list[dict] = yaml.safe_load(CASES_FILE.read_text(encoding="utf-8"))["cases"]
RESULTS: dict[str, dict] = {}



def test_corpus_shape():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    assert len(CASES) >= 130
    assert sum(c["id"].startswith("BEN-") for c in CASES) >= 35
    for c in CASES:
        assert c["direction"] in ("input", "output"), c["id"]
        assert c["expect"] in ("allow", "redact", "block"), c["id"]
        assert (c["control"] is None) == (c["expect"] == "allow"), c["id"]


def _text(case: dict) -> str:
    text = case["text"]
    if case.get("tags"):
        text += "".join(chr(0xE0000 + ord(ch)) for ch in case["tags"])
    return text


def _matches(control_id: str, expected: str) -> bool:
    return control_id == expected or control_id.startswith(expected + ".")


def _outcome(action: Action) -> str:
    # MONITOR = finding recorded, nothing changed -> counts as allow for the corpus
    if action in (Action.ALLOW, Action.MONITOR):
        return "allow"
    if action == Action.REDACT:
        return "redact"
    return "block"  # BLOCK and REQUIRE_APPROVAL both stop the request


@pytest.fixture(scope="module")
def gateway(tmp_path_factory):
    try:
        from app.engine import Gateway
    except ImportError as exc:  # modules still stubs while the team builds in parallel
        pytest.skip(f"gateway not importable yet: {exc}")
    work = tmp_path_factory.mktemp("corpus")
    raw = yaml.safe_load((ROOT / "backend" / "policy.yaml").read_text(encoding="utf-8"))
    raw.setdefault("semantic", {})["backend"] = os.environ.get("CORPUS_JUDGE", "heuristic")
    raw["semantic"].pop("fallback_model", None)
    feeds = ROOT / "backend" / "feeds"
    if feeds.exists():
        shutil.copytree(feeds, work / "feeds")
    policy_path = work / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
    store = PolicyStore(policy_path)
    data_dir = work / "data"
    data_dir.mkdir()
    gw = Gateway(store, data_dir)
    loop = asyncio.new_event_loop()
    yield store, gw, loop
    loop.close()
    _write_report()


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case, gateway):
    store, gw, loop = gateway
    policy, phash, pversion = store.snapshot()
    direction = case["direction"]
    ctx = Context(
        request_id=f"corpus-{case['id']}-{uuid.uuid4().hex[:6]}",
        agent_id="judge-sandbox",
        session_id=f"corpus-{case['id']}",
        policy_hash=phash,
        policy_version=pversion,
        direction=direction,
        source="user" if direction == "input" else "model",
    )
    text = _text(case)
    started = time.perf_counter()
    decision = loop.run_until_complete(gw.inspect(text, ctx, policy))
    elapsed_ms = (time.perf_counter() - started) * 1000

    got = _outcome(decision.action)
    ids = [f.control_id for f in decision.findings if f.action != Action.ALLOW]
    primary = decision.primary.control_id if decision.primary else None
    expected = case.get("control")
    control_ok = expected is None or any(_matches(i, expected) for i in ids)
    RESULTS[case["id"]] = {
        "expect": case["expect"],
        "got": got,
        "control": expected,
        "primary": primary,
        "findings": ids,
        "ok": got == case["expect"] and control_ok,
        "ms": round(elapsed_ms, 3),
    }

    assert got == case["expect"], (
        f"{case['id']} ({case.get('note')}): expected {case['expect']}, got "
        f"{decision.action.value}; primary={primary} findings={ids}"
    )
    if expected:
        assert control_ok, f"{case['id']}: expected control {expected}, findings={ids}"
    for value in case.get("must_not_contain") or []:
        assert value not in decision.text, f"{case['id']}: raw value still forwarded"


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    return round(statistics.quantiles(values, n=100, method="inclusive")[int(q) - 1], 3)


def _write_report() -> None:
    if not RESULTS:
        return
    benign = [r for r in RESULTS.values() if r["expect"] == "allow"]
    controls = sorted({r["control"] for r in RESULTS.values() if r["control"]})
    per_control = {}
    for ctl in controls:
        positives = [r for r in RESULTS.values() if r["control"] == ctl]
        tp = sum(r["ok"] for r in positives)
        fp = sum(any(_matches(i, ctl) for i in r["findings"]) and r["got"] != "allow" for r in benign)
        per_control[ctl] = {
            "positives": len(positives),
            "tp": tp,
            "tpr": round(tp / len(positives), 3) if positives else None,
            "fp": fp,
            "fpr": round(fp / len(benign), 3) if benign else None,
        }
    latencies = [r["ms"] for r in RESULTS.values()]
    report = {
        "ts": time.time(),
        "suite": "corpus",
        "cases": len(RESULTS),
        "passed": sum(r["ok"] for r in RESULTS.values()),
        "failed": [cid for cid, r in RESULTS.items() if not r["ok"]],
        "benign": len(benign),
        "false_positives": [cid for cid, r in RESULTS.items() if r["expect"] == "allow" and r["got"] != "allow"],
        "per_control": per_control,
        "latency_ms": {"p50": _pct(latencies, 50), "p99": _pct(latencies, 99), "max": round(max(latencies), 3)},
        "judge_backend": os.environ.get("CORPUS_JUDGE", "heuristic"),
        "results": RESULTS,
    }
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
