"""Atomic, conservative request reservations; UTC days and rolling minute limits."""

from __future__ import annotations

import math
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Iterable

from .models import Action, Finding
from .policy import Budget, ModelCfg


def estimate_tokens(text: str) -> int:
    return (len(text) + 3) // 4


@dataclass(frozen=True)
class Reservation:
    id: str
    agent_id: str
    usd: float
    tokens: int
    created: float


def _amount(value: float | int, name: str) -> Decimal:
    result = Decimal(str(value))
    if not result.is_finite() or result < 0:
        raise ValueError(f"{name} must be finite and nonnegative")
    return result


def _tokens(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("token counts must be nonnegative integers")
    return value


def _cost(prompt: int, completion: int, compute: float, model: ModelCfg) -> Decimal:
    return (
        _tokens(prompt) * _amount(model.input_per_1m, "input price") / 1_000_000
        + _tokens(completion) * _amount(model.output_per_1m, "output price") / 1_000_000
        + _amount(compute, "compute seconds")
        * _amount(model.compute_usd_per_second, "compute price")
    )


class Ledger:
    """One-process ledger. Failed upstream calls retain reservations until explicit release.

    Settlements are charged on completion day. Outstanding reservations survive midnight.
    Release refunds reserved tokens/USD, but an admitted request still counts toward RPM.
    """

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        # ponytail: one process-wide ledger lock; shard by agent if contention matters.
        self._lock = threading.Lock()
        self._day = int(clock() // 86400)
        self._spend: dict[str, Decimal] = defaultdict(Decimal)
        self._compute: dict[str, Decimal] = defaultdict(Decimal)
        self._pending: dict[str, tuple[Reservation, Decimal]] = {}
        self._minute: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)

    def _refresh(self, now: float) -> None:
        day = int(now // 86400)
        if day != self._day:
            self._spend.clear()
            self._compute.clear()
            self._day = day
        for agent, events in list(self._minute.items()):
            while events and events[0][0] <= now - 60:
                events.popleft()
            if not events:
                del self._minute[agent]

    def _usage(self, agent_id: str, budget: Budget) -> dict[str, Any]:
        reserved = sum((usd for res, usd in self._pending.values()
                        if res.agent_id == agent_id), Decimal(0))
        events = self._minute.get(agent_id, ())
        return {
            "agent_id": agent_id,
            "usd_used": float(self._spend[agent_id] + reserved),
            "usd_spent": float(self._spend[agent_id]),
            "usd_reserved": float(reserved),
            "usd_limit": budget.usd_per_day,
            "requests_min": len(events),
            "tokens_min": sum(event[2] for event in events),
            "compute_seconds_used": float(self._compute[agent_id]),
            "compute_seconds_limit": budget.compute_seconds_per_day,
        }

    def reserve(
        self, agent_id: str, budget: Budget, model: ModelCfg,
        est_input_tokens: int, max_output_tokens: int,
    ) -> tuple[Reservation | None, list[Finding]]:
        tokens = _tokens(est_input_tokens) + _tokens(max_output_tokens)
        usd = _cost(est_input_tokens, max_output_tokens, 0, model)
        with self._lock:
            now = self._clock()
            self._refresh(now)
            usage = self._usage(agent_id, budget)
            used_usd = self._spend[agent_id] + sum(
                (cost for res, cost in self._pending.values() if res.agent_id == agent_id),
                Decimal(0),
            )
            # No compute estimate is in the contract: check actual settled compute at admission.
            checks = [
                ("budget.max_tokens", Decimal(tokens), budget.max_tokens_per_request, False),
                ("budget.rpm", Decimal(usage["requests_min"] + 1), budget.requests_per_minute, False),
                ("budget.tokens_per_minute", Decimal(usage["tokens_min"] + tokens), budget.tokens_per_minute, False),
                ("budget.usd", used_usd + usd, budget.usd_per_day, False),
                ("budget.compute", self._compute[agent_id], budget.compute_seconds_per_day, True),
            ]
            findings: list[Finding] = []
            for control, value, raw_limit, exhausted in checks:
                if raw_limit is None:
                    continue
                limit = _amount(raw_limit, control)
                blocked = limit == 0 or value > limit or (exhausted and value >= limit)
                if blocked or value >= limit * _amount(budget.warn_at, "warn_at"):
                    findings.append(Finding(
                        control, Action.BLOCK if blocked else Action.MONITOR,
                        detail=f"{'Limit exceeded' if blocked else 'Budget warning'}: {value} / {limit}",
                        owasp="LLM10",
                    ))
            if any(f.action == Action.BLOCK for f in findings):
                return None, findings
            res = Reservation(uuid.uuid4().hex, agent_id, float(usd), tokens, now)
            self._pending[res.id] = (res, usd)
            self._minute[agent_id].append((now, res.id, tokens))
            return res, findings

    def _replace_tokens(self, res: Reservation, tokens: int) -> None:
        events = self._minute.get(res.agent_id)
        if events is not None:
            self._minute[res.agent_id] = deque(
                (ts, rid, tokens if rid == res.id else count) for ts, rid, count in events
            )

    def settle(
        self, res: Reservation, prompt_tokens: int, completion_tokens: int,
        compute_s: float, model: ModelCfg,
    ) -> float:
        cost = _cost(prompt_tokens, completion_tokens, compute_s, model)
        compute = _amount(compute_s, "compute seconds")
        with self._lock:
            entry = self._pending.get(res.id)
            if entry is None or entry[0] != res:
                raise ValueError("unknown or already settled reservation")
            self._refresh(self._clock())
            self._spend[res.agent_id] += cost
            self._compute[res.agent_id] += compute
            del self._pending[res.id]
            self._replace_tokens(res, prompt_tokens + completion_tokens)
        return float(cost)

    def release(self, res: Reservation) -> None:
        with self._lock:
            entry = self._pending.get(res.id)
            if entry is not None:
                if entry[0] != res:
                    raise ValueError("reservation does not match")
                del self._pending[res.id]
                self._replace_tokens(res, 0)

    def usage(self, agent_id: str, budget: Budget) -> dict[str, Any]:
        with self._lock:
            self._refresh(self._clock())
            return self._usage(agent_id, budget)

    def restore_day(self, records: Iterable[dict[str, Any]]) -> None:
        """Replace today's settled totals from verified audit records; repeatable, not additive."""
        with self._lock:
            now = self._clock()
            day = int(now // 86400)
            spend: dict[str, Decimal] = defaultdict(Decimal)
            compute: dict[str, Decimal] = defaultdict(Decimal)
            for record in records:
                ts = record.get("ts")
                if isinstance(ts, str):
                    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    ts = parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp()
                if ts is None or not math.isfinite(float(ts)) or int(float(ts) // 86400) != day:
                    continue
                agent = record.get("agent_id")
                if not agent:
                    continue
                spend[agent] += _amount(record.get("cost_usd", 0), "audit cost")
                compute[agent] += _amount(record.get("compute_s", 0), "audit compute")
            self._refresh(now)
            self._spend, self._compute = spend, compute
