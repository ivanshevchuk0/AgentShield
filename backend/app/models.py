"""Shared contracts. Every module imports these; change them only with the whole team."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    ALLOW = "allow"
    MONITOR = "monitor"            # finding recorded, nothing changed
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


SEVERITY = {
    Action.ALLOW: 0,
    Action.MONITOR: 1,
    Action.REDACT: 2,
    Action.REQUIRE_APPROVAL: 3,
    Action.BLOCK: 4,
}


def strongest(actions: list[Action]) -> Action:
    return max(actions, key=SEVERITY.__getitem__, default=Action.ALLOW)


@dataclass
class View:
    """One way of looking at a text (original, folded, decoded...)."""

    name: str              # original | folded | collapsed | base64 | hex | unicode_tags
    text: str
    maps_to_original: bool  # True if offsets in `text` equal offsets in the original string


@dataclass
class Finding:
    control_id: str        # e.g. pii.pesel, secrets.aws, injection.heuristic, signatures.<id>,
                           # canary, flow.taint, tools.allowlist, tools.approval, budget.usd,
                           # semantic.judge, semantic.unavailable, auth.missing, loop.repeat
    action: Action
    score: float = 1.0
    start: int | None = None   # offsets in the ORIGINAL text; None if found only in a decoded view
    end: int | None = None
    via: str = "original"      # which View matched
    evidence: str = ""         # masked snippet, never the raw secret / PII value
    detail: str = ""
    owasp: str = ""            # LLM01, LLM02, LLM05, LLM06, LLM07, LLM10 ...

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "action": self.action.value,
            "score": round(self.score, 3),
            "start": self.start,
            "end": self.end,
            "via": self.via,
            "evidence": self.evidence,
            "detail": self.detail,
            "owasp": self.owasp,
        }


@dataclass
class Decision:
    action: Action
    findings: list[Finding] = field(default_factory=list)
    text: str = ""                                   # text after redaction (what is forwarded)
    timings_ms: dict[str, float] = field(default_factory=dict)
    judge: str = "skipped"   # skipped | allow | block | timeout | circuit_open | error | budget

    @property
    def primary(self) -> Finding | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: (SEVERITY[f.action], f.score))


@dataclass
class Context:
    request_id: str
    agent_id: str | None
    session_id: str
    policy_hash: str
    policy_version: int
    direction: str = "input"   # input | output
    source: str = "user"       # user | tool | model
    tool_name: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def mask(value: str, keep: int = 2) -> str:
    """Masked evidence for logs and cards: first/last chars only."""
    v = value.strip()
    if len(v) <= keep * 2:
        return "*" * len(v)
    return f"{v[:keep]}{'*' * min(len(v) - keep * 2, 12)}{v[-keep:]}"
