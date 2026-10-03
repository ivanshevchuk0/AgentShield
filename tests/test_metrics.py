from concurrent.futures import ThreadPoolExecutor

import pytest

from app.metrics import Metrics
from app.models import Action


def record(overhead, *, judge="skipped", action="allow", control=None, upstream=100):
    return {"kind": "chat", "action": action, "judge": judge,
            "primary": {"control_id": control} if control else None,
            "timings_ms": {"total": overhead + upstream, "upstream": upstream}}


def test_empty_snapshot_is_zero_and_has_all_actions():
    snapshot = Metrics().snapshot()
    assert snapshot["requests_total"] == 0 and snapshot["judge_rate"] == 0
    assert snapshot["counts"] == {action.value: 0 for action in Action}
    assert snapshot["controls"] == {}
    for key in ("p50_ms", "p99_ms", "p50_judge_ms", "p99_judge_ms", "p50_no_judge_ms", "p99_no_judge_ms"):
        assert snapshot[key] == 0


def test_single_sample_excludes_upstream_latency():
    metrics = Metrics()
    metrics.observe(record(7, upstream=10_000, action=Action.BLOCK, control="budget.usd"))
    snapshot = metrics.snapshot()
    assert snapshot["p50_ms"] == snapshot["p99_ms"] == 7
    assert snapshot["p50_no_judge_ms"] == snapshot["p99_no_judge_ms"] == 7
    assert snapshot["p50_judge_ms"] == 0
    assert snapshot["counts"]["block"] == 1 and snapshot["controls"] == {"budget.usd": 1}


def test_percentiles_overall_and_judge_split():
    metrics = Metrics()
    for latency, judge in [(1, "skipped"), (3, "disabled"), (10, "allow"), (30, {"status": "block"})]:
        metrics.observe(record(latency, judge=judge))
    snapshot = metrics.snapshot()
    assert snapshot["p50_ms"] == 6.5
    assert snapshot["p99_ms"] == 29.4
    assert snapshot["p50_judge_ms"] == 20 and snapshot["p99_judge_ms"] == 29.8
    assert snapshot["p50_no_judge_ms"] == 2 and snapshot["p99_no_judge_ms"] == 2.98
    assert snapshot["requests_total"] == 4 and snapshot["judge_rate"] == 0.5


def test_bounded_window_lifetime_counts_and_rate():
    metrics = Metrics(window=2)
    metrics.observe(record(1000, judge="block", action="block", control="injection.heuristic"))
    metrics.observe(record(1, action="allow"))
    metrics.observe(record(3, action="redact", control="pii.email"))
    snapshot = metrics.snapshot()
    assert snapshot["p50_ms"] == 2 and snapshot["p99_ms"] == 2.98
    assert snapshot["p50_judge_ms"] == 0
    assert snapshot["judge_rate"] == pytest.approx(1 / 3)
    assert snapshot["requests_total"] == 3
    assert snapshot["counts"]["block"] == snapshot["counts"]["allow"] == snapshot["counts"]["redact"] == 1
    assert snapshot["controls"] == {"injection.heuristic": 1, "pii.email": 1}


def test_only_primary_control_is_counted_once():
    metrics = Metrics()
    event = record(2, action="require_approval", control="tools.approval")
    event["findings"] = [{"control_id": "tools.approval"}, {"control_id": "flow.untrusted_before_irreversible"}]
    metrics.observe(event)
    metrics.observe(record(3, action="monitor", control="budget.usd"))
    assert metrics.snapshot()["controls"] == {"tools.approval": 1, "budget.usd": 1}
    assert metrics.snapshot()["counts"]["require_approval"] == 1


@pytest.mark.parametrize("judge,used", [
    ("skipped", False), ("disabled", False), (None, False), ("", False),
    ("allow", True), ("block", True), ("timeout", True), ("error", True),
    ("circuit_open", True), ("budget", True), ({"status": "allow"}, True),
    ({"status": "disabled"}, False), ({}, False),
])
def test_judge_status_counting(judge, used):
    metrics = Metrics()
    metrics.observe(record(4, judge=judge))
    snapshot = metrics.snapshot()
    assert snapshot["judge_rate"] == int(used)
    assert snapshot["p50_judge_ms" if used else "p50_no_judge_ms"] == 4


@pytest.mark.parametrize("kind", ["policy", "approval", "kill"])
def test_governance_events_do_not_inflate_request_metrics(kind):
    metrics = Metrics()
    event = record(999, judge="allow", action="block", control="tools.kill_switch")
    event["kind"] = kind
    metrics.observe(event)
    assert metrics.snapshot()["requests_total"] == 0
    assert metrics.snapshot()["controls"] == {}


@pytest.mark.parametrize("kind", ["chat", "tool", "try"])
def test_request_kinds_are_observed(kind):
    metrics = Metrics()
    event = record(1)
    event["kind"] = kind
    metrics.observe(event)
    assert metrics.snapshot()["requests_total"] == 1


def test_missing_timings_fallback_and_negative_overhead():
    metrics = Metrics()
    metrics.observe({"action": "allow", "timings_ms": {"detect": 2, "judge": 3, "upstream": 100}})
    metrics.observe({"action": "allow", "timings_ms": {"total": 10, "upstream": 20}})
    metrics.observe({})
    assert metrics.snapshot()["p50_ms"] == 0
    assert metrics.snapshot()["p99_ms"] == 4.9


@pytest.mark.parametrize("value", [None, "invalid", float("nan"), float("inf"), -10])
def test_invalid_timing_values_do_not_poison_percentiles(value):
    metrics = Metrics()
    metrics.observe({"timings_ms": {"total": value, "upstream": 0}})
    metrics.observe({"timings_ms": {"detect": value, "judge": 2}})
    assert metrics.snapshot()["p50_ms"] == 1
    assert metrics.snapshot()["p99_ms"] == 1.98


def test_observations_and_snapshots_are_detached():
    metrics = Metrics()
    event = record(2, control="pii.email")
    metrics.observe(event)
    event["timings_ms"]["total"] = 999
    event["primary"]["control_id"] = "changed"
    snapshot = metrics.snapshot()
    snapshot["counts"]["allow"] = 999
    snapshot["controls"].clear()
    assert metrics.snapshot()["counts"]["allow"] == 1
    assert metrics.snapshot()["controls"] == {"pii.email": 1}
    assert metrics.snapshot()["p50_ms"] == 2


def test_concurrent_observations_keep_all_counts():
    metrics = Metrics(window=10)
    with ThreadPoolExecutor(max_workers=20) as pool:
        list(pool.map(lambda i: metrics.observe(record(1, judge="allow" if i % 2 else "skipped",
                                                        action="block", control="budget.rpm")), range(500)))
    snapshot = metrics.snapshot()
    assert snapshot["requests_total"] == snapshot["counts"]["block"] == snapshot["controls"]["budget.rpm"] == 500
    assert snapshot["judge_rate"] == 0.5 and snapshot["p99_ms"] == 1


@pytest.mark.parametrize("window", [0, -1, True, 1.5])
def test_invalid_windows_rejected(window):
    with pytest.raises(ValueError):
        Metrics(window)
