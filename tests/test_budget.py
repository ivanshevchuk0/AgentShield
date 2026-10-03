from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from threading import Barrier

import pytest

from app.budget import Ledger, Reservation, estimate_tokens
from app.models import Action
from app.policy import Budget, ModelCfg


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def model():
    return ModelCfg(upstream="mock", input_per_1m=1_000, output_per_1m=2_000,
                    compute_usd_per_second=0.1)


@pytest.mark.parametrize("text,expected", [("", 0), ("a", 1), ("abcd", 1), ("abcde", 2), ("ą🙂中!", 1)])
def test_estimate_tokens(text, expected):
    assert estimate_tokens(text) == expected


def test_reserve_and_settle_actual_cost(clock, model):
    ledger, budget = Ledger(clock), Budget(usd_per_day=1, tokens_per_minute=200)
    res, findings = ledger.reserve("agent", budget, model, 100, 50)
    assert isinstance(res, Reservation) and not findings
    assert res.usd == pytest.approx(0.2)
    assert res.tokens == 150 and res.created == clock.now
    assert ledger.usage("agent", budget)["usd_used"] == pytest.approx(0.2)
    assert ledger.settle(res, 80, 10, 0.2, model) == pytest.approx(0.12)
    usage = ledger.usage("agent", budget)
    assert usage["usd_used"] == pytest.approx(0.12)
    assert usage["usd_spent"] == pytest.approx(0.12)
    assert usage["usd_reserved"] == 0
    assert usage["tokens_min"] == 90 and usage["requests_min"] == 1
    assert usage["compute_seconds_used"] == 0.2
    with pytest.raises(ValueError, match="already settled"):
        ledger.settle(res, 80, 10, 0.2, model)
    ledger.release(res)  # Explicit release is harmless after settlement.
    assert ledger.usage("agent", budget)["usd_used"] == pytest.approx(0.12)


def test_50_concurrent_reserve_threads_cannot_exceed_daily_budget(clock):
    ledger = Ledger(clock)
    model = ModelCfg(upstream="mock", input_per_1m=100_000)
    budget = Budget(usd_per_day=1)
    barrier = Barrier(50)

    def reserve(_):
        barrier.wait(timeout=10)
        return ledger.reserve("agent", budget, model, 1, 0)

    with ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(reserve, range(50)))
    admitted = [res for res, _ in results if res]
    assert len(admitted) == 10
    assert len({res.id for res in admitted}) == 10
    assert ledger.usage("agent", budget)["usd_used"] == 1
    assert sum(res.usd for res in admitted) <= 1
    for res, findings in results:
        if res is None:
            assert any(f.control_id == "budget.usd" and f.action == Action.BLOCK for f in findings)
    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda res: ledger.settle(res, 1, 0, 0, model), admitted))
    assert ledger.usage("agent", budget)["usd_spent"] == 1
    assert ledger.reserve("agent", budget, model, 1, 0)[0] is None


def test_reservation_kept_on_upstream_error(clock, model):
    ledger, budget = Ledger(clock), Budget(usd_per_day=0.2)
    res, _ = ledger.reserve("agent", budget, model, 100, 50)
    with pytest.raises(ConnectionError):
        raise ConnectionError("offline upstream failed")
    clock.now += 120
    assert ledger.reserve("agent", budget, model, 1, 0)[0] is None
    assert ledger.usage("agent", budget)["usd_reserved"] == 0.2
    ledger.release(res)
    ledger.release(res)
    assert ledger.usage("agent", budget)["usd_used"] == 0
    assert ledger.reserve("agent", budget, model, 1, 0)[0] is not None


@pytest.mark.parametrize("budget,control,counts", [
    (Budget(max_tokens_per_request=10), "budget.max_tokens", (6, 5)),
    (Budget(tokens_per_minute=10), "budget.tokens_per_minute", (6, 5)),
    (Budget(requests_per_minute=0), "budget.rpm", (0, 0)),
    (Budget(tokens_per_minute=0), "budget.tokens_per_minute", (0, 0)),
    (Budget(usd_per_day=0), "budget.usd", (0, 0)),
    (Budget(compute_seconds_per_day=0), "budget.compute", (0, 0)),
])
def test_limits_block_without_mutating_usage(clock, model, budget, control, counts):
    ledger = Ledger(clock)
    res, findings = ledger.reserve("agent", budget, model, *counts)
    assert res is None
    assert any(f.control_id == control and f.action == Action.BLOCK and f.owasp == "LLM10"
               for f in findings)
    usage = ledger.usage("agent", budget)
    assert usage["requests_min"] == usage["tokens_min"] == usage["usd_used"] == 0


@pytest.mark.parametrize("field,control", [
    ("requests_per_minute", "budget.rpm"), ("tokens_per_minute", "budget.tokens_per_minute"),
])
def test_rolling_minute_window_uses_injected_clock(clock, model, field, control):
    ledger, budget = Ledger(clock), Budget(**{field: 2})
    start = clock.now
    assert ledger.reserve("agent", budget, model, 1, 0)[0]
    clock.now += 10
    assert ledger.reserve("agent", budget, model, 1, 0)[0]
    clock.now = start + 59.999
    res, findings = ledger.reserve("agent", budget, model, 1, 0)
    assert res is None and any(f.control_id == control and f.action == Action.BLOCK for f in findings)
    clock.now = start + 60
    assert ledger.reserve("agent", budget, model, 1, 0)[0]
    assert ledger.usage("agent", budget)["requests_min"] == 2


def test_settlement_and_release_adjust_tpm_but_keep_rpm(clock, model):
    ledger, budget = Ledger(clock), Budget(tokens_per_minute=100, requests_per_minute=3)
    res, _ = ledger.reserve("agent", budget, model, 50, 50)
    assert ledger.reserve("agent", budget, model, 1, 0)[0] is None
    ledger.settle(res, 5, 5, 0, model)
    second, _ = ledger.reserve("agent", budget, model, 40, 50)
    ledger.release(second)
    usage = ledger.usage("agent", budget)
    assert usage["tokens_min"] == 10 and usage["requests_min"] == 2


@pytest.mark.parametrize("budget,counts,control", [
    (Budget(usd_per_day=0.1), (80, 0), "budget.usd"),
    (Budget(tokens_per_minute=100), (80, 0), "budget.tokens_per_minute"),
    (Budget(max_tokens_per_request=100), (80, 0), "budget.max_tokens"),
    (Budget(requests_per_minute=1), (1, 0), "budget.rpm"),
])
def test_warn_at_80_percent_is_monitor_not_block(clock, model, budget, counts, control):
    ledger = Ledger(clock)
    res, findings = ledger.reserve("agent", budget, model, *counts)
    assert res is not None
    warning = next(f for f in findings if f.control_id == control)
    assert warning.action == Action.MONITOR and warning.owasp == "LLM10"


def test_warn_threshold_configurable_and_below_threshold_silent(clock, model):
    ledger, budget = Ledger(clock), Budget(usd_per_day=1, warn_at=0.5)
    assert not ledger.reserve("a", budget, model, 499, 0)[1]
    res, findings = ledger.reserve("a", budget, model, 1, 0)
    assert res and findings[0].action == Action.MONITOR


def test_compute_limit_and_cost_are_settled(clock, model):
    ledger, budget = Ledger(clock), Budget(compute_seconds_per_day=10)
    res, _ = ledger.reserve("agent", budget, model, 0, 0)
    assert ledger.settle(res, 0, 0, 8, model) == pytest.approx(0.8)
    res, warnings = ledger.reserve("agent", budget, model, 0, 0)
    assert res and any(f.control_id == "budget.compute" and f.action == Action.MONITOR for f in warnings)
    ledger.settle(res, 0, 0, 2, model)
    res, findings = ledger.reserve("agent", budget, model, 0, 0)
    assert res is None and findings[0].control_id == "budget.compute"


def test_agents_have_independent_limits(clock, model):
    ledger, budget = Ledger(clock), Budget(usd_per_day=0.1, requests_per_minute=1)
    assert ledger.reserve("a", budget, model, 100, 0)[0]
    assert ledger.reserve("a", budget, model, 1, 0)[0] is None
    assert ledger.reserve("b", budget, model, 100, 0)[0]


def test_midnight_clears_settled_spend_not_outstanding_reservations(clock, model):
    ledger, budget = Ledger(clock), Budget(usd_per_day=1)
    settled, _ = ledger.reserve("a", budget, model, 200, 0)
    ledger.settle(settled, 200, 0, 1, model)
    pending, _ = ledger.reserve("a", budget, model, 400, 0)
    clock.now = (int(clock.now // 86400) + 1) * 86400
    usage = ledger.usage("a", budget)
    assert usage["usd_spent"] == usage["compute_seconds_used"] == 0
    assert usage["usd_reserved"] == 0.4
    ledger.settle(pending, 300, 0, 0, model)
    assert ledger.usage("a", budget)["usd_spent"] == 0.3


def test_restore_day_rebuilds_today_idempotently(clock, model):
    ledger, budget = Ledger(clock), Budget(usd_per_day=1)
    pending, _ = ledger.reserve("a", budget, model, 100, 0)
    today_iso = datetime.fromtimestamp(clock.now, timezone.utc).isoformat()
    records = [
        {"ts": clock.now, "agent_id": "a", "cost_usd": 0.2, "compute_s": 2},
        {"ts": today_iso, "agent_id": "a", "cost_usd": 0.3},
        {"ts": clock.now, "agent_id": "b", "cost_usd": 0.4},
        {"ts": clock.now - 86400, "agent_id": "a", "cost_usd": 999},
        {"ts": clock.now + 86400, "agent_id": "a", "cost_usd": 999},
        {"ts": clock.now, "agent_id": None, "cost_usd": 999},
        {"kind": "policy"},
    ]
    ledger.restore_day(iter(records))
    ledger.restore_day(records)
    usage = ledger.usage("a", budget)
    assert usage["usd_spent"] == 0.5 and usage["usd_used"] == 0.6
    assert usage["compute_seconds_used"] == 2 and usage["requests_min"] == 1
    assert ledger.usage("b", budget)["usd_spent"] == 0.4
    assert ledger.reserve("a", budget, model, 401, 0)[0] is None
    ledger.release(pending)
    ledger.restore_day([])
    assert ledger.usage("a", budget)["usd_used"] == 0


@pytest.mark.parametrize("value", [-1, 1.5, True])
def test_invalid_token_counts_rejected(clock, model, value):
    ledger = Ledger(clock)
    with pytest.raises(ValueError):
        ledger.reserve("a", Budget(), model, value, 1)
    with pytest.raises(ValueError):
        ledger.reserve("a", Budget(), model, 1, value)
    assert ledger.usage("a", Budget())["requests_min"] == 0


@pytest.mark.parametrize("compute", [-1, float("nan"), float("inf")])
def test_invalid_settlement_keeps_reservation(clock, model, compute):
    ledger, budget = Ledger(clock), Budget()
    res, _ = ledger.reserve("a", budget, model, 10, 10)
    with pytest.raises(ValueError):
        ledger.settle(res, 1, 1, compute, model)
    assert ledger.usage("a", budget)["usd_reserved"] == 0.03


def test_reservations_are_immutable_and_forgery_rejected(clock, model):
    ledger, budget = Ledger(clock), Budget()
    res, _ = ledger.reserve("a", budget, model, 10, 0)
    with pytest.raises(FrozenInstanceError):
        res.agent_id = "b"
    forged = replace(res, agent_id="b")
    with pytest.raises(ValueError):
        ledger.release(forged)
    with pytest.raises(ValueError):
        ledger.settle(forged, 1, 0, 0, model)
    assert ledger.usage("a", budget)["usd_reserved"] == 0.01


def test_actual_usage_over_estimate_is_not_silently_capped(clock, model):
    ledger, budget = Ledger(clock), Budget(usd_per_day=0.1)
    res, _ = ledger.reserve("a", budget, model, 1, 0)
    assert ledger.settle(res, 200, 0, 0, model) == 0.2
    assert ledger.reserve("a", budget, model, 1, 0)[0] is None


def test_restore_invalid_cost_is_atomic(clock, model):
    ledger, budget = Ledger(clock), Budget()
    res, _ = ledger.reserve("a", budget, model, 10, 0)
    ledger.settle(res, 10, 0, 0, model)
    with pytest.raises(ValueError):
        ledger.restore_day([{"ts": clock.now, "agent_id": "a", "cost_usd": -1}])
    assert ledger.usage("a", budget)["usd_spent"] == 0.01
