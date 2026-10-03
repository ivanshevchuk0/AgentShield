"""Central policy engine: one YAML control catalog, strictly validated, versioned, hot reloaded.

Rules that matter on stage:
- an empty / truncated / invalid file is rejected and the last good policy keeps enforcing;
- a control section that is removed from the file means that control is DISABLED (not defaults);
- `flow` is not a detector: it stays on unless `flow.enabled: false`;
- an agent without `allowed_tools` may call no tools.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

Act = Literal["block", "redact", "monitor"]
Direction = Literal["input", "output", "both"]


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- controls (detectors)
class ControlCfg(_Cfg):
    enabled: bool = True
    action: Act = "block"
    direction: Direction = "both"


class InjectionCfg(ControlCfg):
    direction: Direction = "input"
    block_threshold: float = Field(0.8, ge=0, le=1)
    review_threshold: float = Field(0.3, ge=0, le=1)
    scan_tool_results: bool = True


class PiiCfg(ControlCfg):
    action: Act = "redact"
    entities: list[Literal["EMAIL", "PHONE", "PESEL", "NIP", "IBAN", "CREDIT_CARD"]] = [
        "EMAIL", "PHONE", "PESEL", "NIP", "IBAN", "CREDIT_CARD",
    ]


class SignaturesCfg(ControlCfg):
    feed_file: str = "feeds/signatures.yaml"


class CanaryCfg(ControlCfg):
    direction: Direction = "output"
    tokens: list[str] = ["WRDN-CANARY-7F3A"]


class LoopCfg(_Cfg):
    enabled: bool = True
    action: Act = "block"
    max_identical: int = Field(3, ge=1)
    window_seconds: int = Field(120, ge=1)
    max_requests_per_session: int = Field(60, ge=1)


class Controls(_Cfg):
    """Every field is optional: a missing section means the control is disabled."""

    prompt_injection: InjectionCfg | None = None
    pii: PiiCfg | None = None
    secrets: ControlCfg | None = None
    signatures: SignaturesCfg | None = None
    canary: CanaryCfg | None = None
    loop: LoopCfg | None = None

    def active(self, name: str):
        cfg = getattr(self, name, None)
        return cfg if cfg is not None and cfg.enabled else None


# ---------------------------------------------------------------- information flow
class FlowRules(_Cfg):
    secret_to_egress: Act = "block"                  # F1
    untrusted_value_as_target: Act = "block"         # F2
    untrusted_before_irreversible: Literal["approval", "block", "monitor"] = "approval"  # F4


class FlowCfg(_Cfg):
    enabled: bool = True
    min_chars: int = Field(12, ge=6)
    rules: FlowRules = FlowRules()


# ---------------------------------------------------------------- semantic judge
class SemanticCfg(_Cfg):
    enabled: bool = True
    backend: Literal["openrouter", "openai", "ollama", "heuristic", "stub"] = "heuristic"
    model: str = "google/gemini-2.5-flash-lite"
    fallback_model: str | None = "openai/gpt-4o-mini"
    base_url: str = "https://openrouter.ai/api/v1"
    api_key_env: str = "OPENROUTER_API_KEY"
    trigger: Literal["suspicious", "always"] = "suspicious"
    threshold: float = Field(0.7, ge=0, le=1)
    timeout_ms: int = Field(1200, ge=50, le=10000)
    breaker_failures: int = Field(3, ge=1)
    breaker_cooldown_s: int = Field(30, ge=1)
    usd_per_day: float = Field(1.0, ge=0)
    action: Act = "block"
    scan_output: bool = False
    denied_topics: list[str] = []


# ---------------------------------------------------------------- models, budgets, agents, tools
class ModelCfg(_Cfg):
    upstream: Literal["mock", "openrouter", "openai", "ollama"]
    upstream_model: str | None = None
    base_url: str | None = None
    input_per_1m: float = Field(0.0, ge=0)
    output_per_1m: float = Field(0.0, ge=0)
    compute_usd_per_second: float = Field(0.0, ge=0)


class Budget(_Cfg):
    usd_per_day: float | None = Field(None, ge=0)
    tokens_per_minute: int | None = Field(None, ge=0)
    requests_per_minute: int | None = Field(None, ge=0)
    max_tokens_per_request: int | None = Field(None, ge=1)
    compute_seconds_per_day: float | None = Field(None, ge=0)
    warn_at: float = Field(0.8, gt=0, le=1)


class AgentCfg(_Cfg):
    id: str
    api_key: str | None = None
    api_key_env: str | None = None
    description: str = ""
    allowed_models: list[str] | None = None   # None = every model in `models`
    allowed_tools: list[str] = []             # missing/empty = NO tools
    budget: Budget | None = None

    def key(self) -> str | None:
        if self.api_key_env and os.environ.get(self.api_key_env):
            return os.environ[self.api_key_env]
        return self.api_key


class ToolCfg(_Cfg):
    labels: list[Literal["secret", "untrusted", "internal"]] = []   # labels on the tool's RESULT
    egress: bool = False              # sends data outside the trust boundary
    irreversible: bool = False        # needs human approval
    target_args: list[str] = []       # args that name a destination (to, url, iban)
    arg_patterns: dict[str, str] = {}       # arg must match
    deny_arg_patterns: dict[str, str] = {}  # arg must not match
    max_values: dict[str, float] = {}

    @model_validator(mode="after")
    def _regexes_compile(self):
        for pat in [*self.arg_patterns.values(), *self.deny_arg_patterns.values()]:
            re.compile(pat)
        return self


class McpServerCfg(_Cfg):
    url: str | None = None
    command: list[str] | None = None


class Policy(_Cfg):
    version: str
    mode: Literal["enforce", "monitor"] = "enforce"
    profile: str = "standard"
    fail_mode: Literal["open", "closed"] = "closed"
    require_auth: bool = True
    block_response: Literal["error", "message"] = "error"
    max_input_chars: int = Field(40000, ge=100)
    approval_ttl_s: int = Field(120, ge=5)
    controls: Controls = Controls()
    flow: FlowCfg = FlowCfg()
    semantic: SemanticCfg = SemanticCfg()
    models: dict[str, ModelCfg]
    budgets: dict[str, Budget] = {"default": Budget()}
    agents: list[AgentCfg]
    tools: dict[str, ToolCfg] = {}
    mcp_servers: dict[str, McpServerCfg] = {}
    kill_switch: list[str] = []
    profiles: dict[str, dict[str, Any]] = {}

    @model_validator(mode="after")
    def _consistency(self):
        inj = self.controls.prompt_injection
        if inj and inj.review_threshold >= inj.block_threshold:
            raise ValueError("controls.prompt_injection.review_threshold must be < block_threshold")
        ids = [a.id for a in self.agents]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate agent id")
        keys = [a.key() for a in self.agents if a.key()]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate agent api key")
        for a in self.agents:
            for m in a.allowed_models or []:
                if m not in self.models:
                    raise ValueError(f"agent {a.id}: unknown model '{m}'")
            for t in a.allowed_tools:
                if t not in self.tools:
                    raise ValueError(f"agent {a.id}: unknown tool '{t}'")
        for k in self.kill_switch:
            if k not in ids:
                raise ValueError(f"kill_switch: unknown agent '{k}'")
        return self

    # helpers
    def agent_by_key(self, key: str | None) -> AgentCfg | None:
        if not key:
            return None
        import hmac

        for a in self.agents:
            ak = a.key()
            if ak and hmac.compare_digest(ak, key):
                return a
        return None

    def agent_by_id(self, agent_id: str | None) -> AgentCfg | None:
        return next((a for a in self.agents if a.id == agent_id), None)

    def budget_for(self, agent: AgentCfg | None) -> Budget:
        base = self.budgets.get("default", Budget()).model_dump()
        if agent and agent.budget:
            base.update(agent.budget.model_dump(exclude_unset=True))
        return Budget(**base)

    def model_allowed(self, agent: AgentCfg | None, model: str) -> bool:
        if model not in self.models:
            return False
        return agent is None or agent.allowed_models is None or model in agent.allowed_models


# ---------------------------------------------------------------- parsing
class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _no_dupes(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ValueError(f"duplicate key '{key}' (line {key_node.start_mark.line + 1})")
        seen.add(key)
    return loader.construct_mapping(node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dupes)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


REQUIRED_TOP_KEYS = ("version", "models", "agents")


def parse_policy(text: str) -> Policy:
    if len(text.strip()) < 50:
        raise ValueError("policy file is empty or truncated")
    raw = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    if not isinstance(raw, dict):
        raise ValueError("policy root must be a mapping")
    missing = [k for k in REQUIRED_TOP_KEYS if k not in raw]
    if missing:
        raise ValueError(f"policy is missing required keys: {missing}")
    profile = raw.get("profile", "standard")
    profiles = raw.get("profiles") or {}
    if profile != "standard" and profile not in profiles:
        raise ValueError(f"unknown profile '{profile}' (known: {sorted(profiles)})")
    return Policy(**deep_merge(raw, profiles.get(profile) or {}))


def _flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for k, v in data.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
        return out
    return {prefix: data}


def diff_policies(old: Policy | None, new: Policy) -> list[str]:
    if old is None:
        return []
    a, b = _flatten(old.model_dump()), _flatten(new.model_dump())
    return [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k) and not k.startswith("profiles")]


def short_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        parts = []
        for err in exc.errors()[:4]:
            loc = ".".join(str(p) for p in err["loc"])
            parts.append(f"{loc}: {err['msg']}" if loc else err["msg"])
        return "; ".join(parts)
    return str(exc).splitlines()[0][:300]


class PolicyStore:
    """Holds the live policy. Poll-based reload (works with editors that rename-on-save)."""

    def __init__(self, path: str | Path, on_event=None, history_limit: int = 50):
        self.path = Path(path)
        self.on_event = on_event or (lambda e: None)
        self._lock = threading.Lock()
        self.policy: Policy | None = None
        self.version = 0
        self.hash = ""
        self.loaded_at = 0.0
        self.history: list[dict[str, Any]] = []
        self.history_limit = history_limit
        self._sig: tuple[float, int] | None = None
        self._pending_since: float | None = None
        entry = self.reload(force=True)
        if self.policy is None:
            raise RuntimeError(f"initial policy {self.path} is invalid: {entry}")

    @property
    def base_dir(self) -> Path:
        return self.path.parent

    def snapshot(self) -> tuple[Policy, str, int]:
        with self._lock:
            assert self.policy is not None
            return self.policy, self.hash, self.version

    def text(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def _record(self, entry: dict[str, Any]) -> dict[str, Any]:
        self.history.append(entry)
        del self.history[: -self.history_limit]
        self.on_event({"kind": "policy", **entry})
        return entry

    def poll(self, debounce_s: float = 0.15) -> dict[str, Any] | None:
        """Call periodically. Applies a change once the file has been stable for `debounce_s`."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            if self._sig is not None:
                self._sig = None
                return self._record(self._rejected("", "policy file deleted"))
            return None
        sig = (st.st_mtime, st.st_size)
        if sig == self._sig:
            self._pending_since = None
            return None
        now = time.monotonic()
        if self._pending_since is None:
            self._pending_since = now
            return None
        if now - self._pending_since < debounce_s:
            return None
        self._pending_since = None
        self._sig = sig
        return self.reload()

    def reload(self, force: bool = False) -> dict[str, Any] | None:
        try:
            st = self.path.stat()
            text = self.text()
        except FileNotFoundError:
            return self._record(self._rejected("", "policy file not found"))
        self._sig = (st.st_mtime, st.st_size)
        digest = hashlib.sha256(text.encode()).hexdigest()[:12]
        if not force and digest == self.hash:
            return None
        return self._apply(text, digest)

    def _rejected(self, digest: str, error: str) -> dict[str, Any]:
        return {
            "status": "rejected",
            "hash": digest,
            "ts": time.time(),
            "error": error,
            "active_version": self.version,
            "active_hash": self.hash,
        }

    def _apply(self, text: str, digest: str) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            policy = parse_policy(text)
        except (ValidationError, ValueError, yaml.YAMLError, TypeError) as exc:
            return self._record(self._rejected(digest, short_error(exc)))
        with self._lock:
            changed = diff_policies(self.policy, policy)
            self.policy = policy
            self.version += 1
            self.hash = digest
            self.loaded_at = time.time()
        return self._record(
            {
                "status": "applied",
                "version": self.version,
                "hash": digest,
                "ts": self.loaded_at,
                "profile": policy.profile,
                "mode": policy.mode,
                "changed": changed[:50],
                "apply_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        )

    def apply_text(self, text: str) -> dict[str, Any]:
        """Validate first; only a valid policy is written (atomically) to disk."""
        digest = hashlib.sha256(text.encode()).hexdigest()[:12]
        try:
            parse_policy(text)
        except (ValidationError, ValueError, yaml.YAMLError, TypeError) as exc:
            return self._record(self._rejected(digest, short_error(exc)))
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, self.path)
        return self.reload(force=True) or {"status": "unchanged", "version": self.version}

    def set_profile(self, profile: str) -> dict[str, Any]:
        lines = self.text().splitlines()
        for i, line in enumerate(lines):
            if line.startswith("profile:"):
                comment = ("  #" + line.split("#", 1)[1]) if "#" in line else ""
                lines[i] = f"profile: {profile}{comment}"
                return self.apply_text("\n".join(lines) + "\n")
        return self.apply_text(f"profile: {profile}\n" + self.text())
