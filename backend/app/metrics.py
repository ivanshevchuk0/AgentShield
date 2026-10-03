"""Cumulative decision counts and bounded, upstream-excluded latency samples."""

from __future__ import annotations

import math
import threading
from collections import Counter, deque
from typing import Any

from .models import Action


def _milliseconds(value: Any) -> float:
    try:
        number = float(value)
    except (ValueError, TypeError):
        return 0.0
    return max(0.0, number) if math.isfinite(number) else 0.0


def _percentile(samples: list[float], fraction: float) -> float:
    if not samples:
        return 0.0
    values = sorted(samples)
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    return round(values[lower] + (values[upper] - values[lower]) * (position - lower), 3)


class Metrics:
    """Thread-safe counters for request decisions; policy/approval/kill events are excluded.

    Counts and judge_rate are lifetime totals; percentiles cover the latest `window`
    requests, using linear interpolation. Judge means a non-skipped judge decision.
    """

    def __init__(self, window: int = 500):
        if isinstance(window, bool) or not isinstance(window, int) or window < 1:
            raise ValueError("metrics window must be a positive integer")
        self._lock = threading.Lock()
        self._samples: deque[tuple[float, bool]] = deque(maxlen=window)
        self._actions: Counter[str] = Counter()
        self._controls: Counter[str] = Counter()
        self._total = 0
        self._judged = 0

    def observe(self, record: dict[str, Any]) -> None:
        if record.get("kind") in {"policy", "approval", "kill"}:
            return
        timings = record.get("timings_ms") or {}
        judge = record.get("judge", "skipped")
        if isinstance(judge, dict):
            judge = judge.get("status", "skipped")
        judged = judge not in (None, "", "skipped", "disabled", False)
        if "total" in timings:
            overhead = max(0.0, _milliseconds(timings["total"]) - _milliseconds(timings.get("upstream", 0)))
        else:
            overhead = _milliseconds(timings.get("detect", 0)) + _milliseconds(timings.get("judge", 0))
        action = record.get("action", "allow")
        if isinstance(action, Action):
            action = action.value
        primary = record.get("primary") or {}
        control = primary.get("control_id")
        with self._lock:
            self._samples.append((overhead, judged))
            self._actions[str(action)] += 1
            if control:
                self._controls[str(control)] += 1
            self._total += 1
            self._judged += int(judged)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            overall = [ms for ms, _ in self._samples]
            judged = [ms for ms, used in self._samples if used]
            unjudged = [ms for ms, used in self._samples if not used]
            return {
                "requests_total": self._total,
                "counts": {action.value: self._actions[action.value] for action in Action}
                          | {action: count for action, count in self._actions.items()},
                "controls": dict(self._controls),
                "judge_rate": self._judged / self._total if self._total else 0.0,
                "p50_ms": _percentile(overall, 0.5),
                "p99_ms": _percentile(overall, 0.99),
                "p50_judge_ms": _percentile(judged, 0.5),
                "p99_judge_ms": _percentile(judged, 0.99),
                "p50_no_judge_ms": _percentile(unjudged, 0.5),
                "p99_no_judge_ms": _percentile(unjudged, 0.99),
            }
