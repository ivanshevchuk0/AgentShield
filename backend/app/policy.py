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
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

Act = Literal["block", "redact", "monitor"]
Direction = Literal["input", "output", "both"]
SECRET_ENV = r"[A-Z][A-Z0-9_]*_(?:KEY|TOKEN)"


def _check_base_url(url: str) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    local = host in {"localhost", "127.0.0.1", "::1"}
    if (parts.scheme not in {"http", "https"} or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment
            or any(c.isspace() or ord(c) < 32 for c in url)
            or (not local and (host not in {"openrouter.ai", "api.openai.com"}
                               or parts.scheme != "https"))):
        raise ValueError("base_url must use an official HTTPS provider or a loopback HTTP(S) endpoint")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ValueError("base_url has an invalid port")


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

    @field_validator("feed_file")
    @classmethod
    def _relative_feed(cls, name: str) -> str:
        path = Path(name)
        if (path.is_absolute() or ".." in path.parts or "\\" in name
                or any(ord(c) < 32 for c in name) or path.suffix not in {".yaml", ".yml"}):
            raise ValueError("feed_file must be a relative YAML path without traversal")
        return name


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
    min_chars: int = Field(12, ge=6, le=128)
    rules: FlowRules = FlowRules()


# ---------------------------------------------------------------- semantic judge
class SemanticCfg(_Cfg):
    enabled: bool = True
    backend: Literal["openrouter", "openai", "ollama", "heuristic", "stub"] = "heuristic"
    model: str = "google/gemini-2.5-flash-lite"
    fallback_model: str | None = "openai/gpt-4o-mini"
    base_url: str = "https://openrouter.ai/api/v1"
    api_key_env: str = Field("OPENROUTER_API_KEY", pattern="^" + SECRET_ENV + "$", max_length=128)
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
    api_key: str | None = Field(None, min_length=8)
    api_key_env: str | None = Field(None, pattern="^" + SECRET_ENV + "$", max_length=128)
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
        # Reuse the feed's restricted regex grammar; import lazily to avoid a cycle.
        from app.guardrails.signatures import _safe_regex

        for pat in [*self.arg_patterns.values(), *self.deny_arg_patterns.values()]:
            try:
                _safe_regex(pat)
            except (re.error, OverflowError, RecursionError) as exc:
                raise ValueError(f"invalid tool regex: {exc}") from exc
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
    max_input_chars: int = Field(40000, ge=100, le=200000)
    approval_ttl_s: int = Field(120, ge=5, le=600)
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
        _check_base_url(self.semantic.base_url)
        for cfg in self.models.values():
            if cfg.base_url is not None:
                _check_base_url(cfg.base_url)
        if "redact" in self.flow.rules.model_dump().values():
            raise ValueError("flow rules cannot redact tool arguments; use block or monitor")
        inj = self.controls.prompt_injection
        if inj and inj.review_threshold >= inj.block_threshold:
            raise ValueError("controls.prompt_injection.review_threshold must be < block_threshold")
        ids = [a.id for a in self.agents]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate agent id")
        envs = [a.api_key_env for a in self.agents if a.api_key_env]
        if len(envs) != len(set(envs)):
            raise ValueError("duplicate agent api_key_env")
        keys = [a.key() for a in self.agents if a.key()]
        if any(len(key) < 8 for key in keys):
            raise ValueError("resolved agent api key must contain at least 8 characters")
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
        if not isinstance(key, str) or not key:
            return None
        import hmac

        wanted = hashlib.sha256(key.encode("utf-8", errors="surrogatepass")).digest()
        matches = []
        for a in self.agents:
            ak = a.key()
            if ak and len(ak) >= 8:
                digest = hashlib.sha256(ak.encode("utf-8", errors="surrogatepass")).digest()
                if hmac.compare_digest(digest, wanted):
                    matches.append(a)
        # Environment values may change after validation: ambiguous identities fail closed.
        return matches[0] if len(matches) == 1 else None

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
MAX_POLICY_BYTES = 256_000


class _PolicyLoader(_UniqueKeyLoader):
    """Bound construction before recursive YAML/profile processing can run."""

    def __init__(self, stream):
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("policy YAML aliases are forbidden")
        self._depth += 1
        self._nodes += 1
        try:
            if self._depth > 32 or self._nodes > 20_000:
                raise ValueError("policy YAML exceeds depth or node limit")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def parse_policy(text: str) -> Policy:
    if not isinstance(text, str) or len(text.strip()) < 50:
        raise ValueError("policy file is empty or truncated")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise ValueError("policy file exceeds 256 KB")
    raw = yaml.load(text, Loader=_PolicyLoader)  # noqa: S506 - SafeLoader subclass
    if not isinstance(raw, dict):
        raise ValueError("policy root must be a mapping")
    missing = [k for k in REQUIRED_TOP_KEYS if k not in raw]
    if missing:
        raise ValueError(f"policy is missing required keys: {missing}")
    profile = raw.get("profile", "standard")
    profiles = raw.get("profiles", {})
    if not isinstance(profile, str) or not isinstance(profiles, dict):
        raise ValueError("profile must be a string and profiles must be a mapping")
    if any(not isinstance(k, str) or not isinstance(v, dict) for k, v in profiles.items()):
        raise ValueError("profiles must map string names to mapping overlays")
    if profile != "standard" and profile not in profiles:
        raise ValueError(f"unknown profile '{profile}' (known: {sorted(profiles)})")
    return Policy(**deep_merge(raw, profiles.get(profile) or {}))


def _flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(data, (dict, list)) and data:
        out: dict[str, Any] = {}
        items = data.items() if isinstance(data, dict) else enumerate(data)
        for k, v in items:
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
        self._lock = threading.RLock()
        self.policy: Policy | None = None
        self.version = 0
        self.hash = ""
        self.loaded_at = 0.0
        self.history: list[dict[str, Any]] = []
        self.history_limit = history_limit
        self._sig: tuple[int, int, int] | None = None
        self._pending_since: float | None = None
        self._pending_sig: tuple[int, int, int] | None = None
        self._last_io_error: str | None = None
        entry = self.reload(force=True)
        if self.policy is None:
            raise RuntimeError(f"initial policy {self.path} is invalid: {entry}")

    @property
    def base_dir(self) -> Path:
        return self.path.parent

    def snapshot(self) -> tuple[Policy, str, int]:
        with self._lock:
            assert self.policy is not None
            return self.policy.model_copy(deep=True), self.hash, self.version

    def text(self) -> str:
        with self.path.open("rb") as file:
            data = file.read(MAX_POLICY_BYTES + 1)
        if len(data) > MAX_POLICY_BYTES:
            raise ValueError("policy file exceeds 256 KB")
        return data.decode("utf-8")

    def _record(self, entry: dict[str, Any]) -> dict[str, Any]:
        self.history.append(entry)
        del self.history[: -self.history_limit]
        self.on_event({"kind": "policy", **entry})
        return entry

    def poll(self, debounce_s: float = 0.15) -> dict[str, Any] | None:
        """Call periodically. Applies a change once the file has been stable for `debounce_s`."""
        with self._lock:
            try:
                st = self.path.stat()
            except OSError as exc:
                error = short_error(exc)
                self._sig = None
                self._pending_since = None
                if error == self._last_io_error:
                    return None
                self._last_io_error = error
                return self._record(self._rejected("", error))
            self._last_io_error = None
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
            if sig == self._sig:
                self._pending_since = None
                return None
            now = time.monotonic()
            if self._pending_since is None or sig != self._pending_sig:
                self._pending_sig = sig
                self._pending_since = now
                return None
            if now - self._pending_since < debounce_s:
                return None
            self._pending_since = None
            return self.reload()

    def reload(self, force: bool = False) -> dict[str, Any] | None:
        # One reload or apply at a time, so a poll never interleaves with a dashboard edit.
        with self._lock:
            try:
                st = self.path.stat()
                self._sig = (st.st_mtime_ns, st.st_size, st.st_ino)
                text = self.text()
            except (OSError, ValueError) as exc:
                return self._record(self._rejected("", short_error(exc)))
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

    def _apply(self, text: str, digest: str, policy: Policy | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        with self._lock:
            try:
                policy = policy if policy is not None else parse_policy(text)
            except (ValidationError, ValueError, yaml.YAMLError, TypeError) as exc:
                return self._record(self._rejected(digest, short_error(exc)))
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
                "changed": changed,
                "apply_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        )

    def apply_text(self, text: str) -> dict[str, Any]:
        """Validate first; atomically write and install exactly the validated bytes."""
        with self._lock:
            digest = ""
            try:
                digest = hashlib.sha256(text.encode()).hexdigest()[:12]
                policy = parse_policy(text)
            except (ValidationError, ValueError, yaml.YAMLError, TypeError) as exc:
                return self._record(self._rejected(digest, short_error(exc)))
            tmp = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent,
                                                 prefix=self.path.name + ".", delete=False) as file:
                    tmp = Path(file.name)
                    file.write(text)
                st = tmp.stat()
                os.replace(tmp, self.path)
                self._sig = (st.st_mtime_ns, st.st_size, st.st_ino)
                return self._apply(text, digest, policy)
            except (OSError, UnicodeError) as exc:
                return self._record(self._rejected(digest, short_error(exc)))
            finally:
                if tmp is not None:
                    tmp.unlink(missing_ok=True)

    def set_profile(self, profile: str) -> dict[str, Any]:
        with self._lock:
            if not isinstance(profile, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,32}", profile):
                return self._record(self._rejected("", "invalid profile name"))
            try:
                text = self.text()
            except (OSError, ValueError) as exc:
                return self._record(self._rejected("", short_error(exc)))
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if line.startswith("profile:"):
                    comment = ("  #" + line.split("#", 1)[1]) if "#" in line else ""
                    lines[i] = f"profile: {profile}{comment}"
                    return self.apply_text("\n".join(lines) + "\n")
            return self.apply_text(f"profile: {profile}\n" + text)
