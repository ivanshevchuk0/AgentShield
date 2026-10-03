"""Gateway: wires every guardrail into the chat and tool lifecycles (ARCHITECTURE §3).

Everything that decides is here; main.py only translates HTTP <-> GatewayResult.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import os
import re
import secrets as _secrets
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app import upstream
from app.audit import AuditLog
from app.budget import Ledger, estimate_tokens
from app.flow import TaintStore, sign_call_id, verify_call_id
from app.governance import ApprovalStore, LoopGuard, check_tool_call
from app.guardrails import injection, normalize, pii, secrets
from app.guardrails.semantic import Judge
from app.guardrails.signatures import SignatureFeed, scan_canary
from app.metrics import Metrics
from app.models import SEVERITY, Action, Context, Decision, Finding, mask, strongest
from app.policy import ControlCfg, PiiCfg, Policy, PolicyStore

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent

try:  # parallel module; minimal inline score until it exists
    from app.posture import coverage as _coverage_mod
    from app.posture import posture as _posture_mod
except Exception:  # noqa: BLE001
    _coverage_mod = _posture_mod = None

# controls that "disable all detectors" turns off; flow and loop are not detectors
DETECTORS = ("prompt_injection", "pii", "secrets", "signatures", "canary", "semantic")
TOGGLEABLE = (*DETECTORS, "loop", "flow")
CONTROL_NAMES = ("prompt_injection", "pii", "secrets", "signatures", "canary", "loop")

# never downgraded by monitor mode: identity, money, kill switch, hard limits
_NOT_DOWNGRADED = ("auth.", "budget.", "model.", "limits.", "tools.kill_switch")

_ACT = {
    "block": Action.BLOCK,
    "redact": Action.REDACT,
    "monitor": Action.MONITOR,
    "approval": Action.REQUIRE_APPROVAL,
    "require_approval": Action.REQUIRE_APPROVAL,
    "allow": Action.ALLOW,
}

# posture: score = 100 - sum(weights of open gaps), clamped to [0, 100]
POSTURE_WEIGHTS = {
    "mode.monitor": 25,
    "auth.disabled": 20,
    "flow.disabled": 20,
    "prompt_injection.disabled": 15,
    "pii.disabled": 10,
    "secrets.disabled": 10,
    "signatures.disabled": 5,
    "canary.disabled": 3,
    "loop.disabled": 2,
    "semantic.disabled": 5,
    "fail_mode.open": 5,
    "agent.unbudgeted": 3,
}
POSTURE_FORMULA = "score = 100 - sum(weight of each open gap), clamped to 0..100"


def owasp_for(control_id: str, direction: str = "input") -> str:
    c = control_id
    if c.startswith(("injection.", "semantic.")):
        return "LLM01"
    if c.startswith(("pii.", "secrets.")):
        return "LLM02"
    if c.startswith("signatures."):
        return "LLM05" if direction == "output" else "LLM03"
    if c == "canary":
        return "LLM07"
    if c.startswith(("tools.", "flow.", "auth.")):
        return "LLM06"
    if c.startswith(("budget.", "loop.", "limits.", "model.")):
        return "LLM10"
    return ""


def _act(value: Any) -> Action:
    if isinstance(value, Action):
        return value
    return _ACT.get(str(value), Action.BLOCK)


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _content_text(content: Any) -> str:
    """OpenAI message content may be a string or a list of parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict) and isinstance(p.get("text"), str):
                parts.append(p["text"])
            elif isinstance(p, str):
                parts.append(p)
        return "\n".join(parts)
    return str(content)


def status_for(control_id: str | None) -> int:
    if not control_id:
        return 403
    if control_id.startswith("budget."):
        return 429
    if control_id == "auth.impersonation":
        return 403
    if control_id.startswith("auth."):
        return 401
    return 403


@dataclass
class GatewayResult:
    status: int
    body: Any
    headers: dict[str, str] = field(default_factory=dict)
    record: dict | None = None
    stream: bool = False


class AuditUnavailable(RuntimeError):
    """No protected dispatch may proceed after audit persistence fails."""


def _blocked_body(record: dict) -> dict:
    primary = record.get("primary") or {}
    return {
        "error": {
            "type": "agentshield_blocked",
            "code": primary.get("control_id") or "blocked",
            "message": record.get("summary", "blocked"),
            "record": record,
            **({"approval_id": record["approval_id"]} if record.get("approval_id") else {}),
        }
    }


class Gateway:
    def __init__(
        self,
        policy_store: PolicyStore,
        data_dir: str | Path,
        transport=None,
        judge_transport=None,
    ):
        self.store = policy_store
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.transport = transport
        self.key = self._load_key()
        self.call_key = hmac.new(self.key, b"agentshield-tool-call-ids", hashlib.sha256).digest()
        self.audit = AuditLog(self.data_dir, self.key)
        self.audit_unavailable = False
        self.ledger = Ledger()
        try:
            self.ledger.restore_day(self.audit.all())
        except Exception:  # noqa: BLE001 - a bad history must not stop the gateway
            pass
        self.metrics = Metrics()
        self.counts = {a.value: 0 for a in Action}
        try:
            for r in self.audit.all():
                if r.get("kind") in ("chat", "tool", "try") and r.get("action") in self.counts:
                    self.counts[r["action"]] += 1
        except Exception:  # noqa: BLE001
            pass
        self.judge = Judge(transport=judge_transport)
        self.upstream_calls = 0   # model calls actually made since start (attempts, incl. failures)
        self.taint = TaintStore(self.audit.all(), lambda record: self.commit(record, observe=False),
                                hmac.new(self.key, b"agentshield-flow-fingerprints", hashlib.sha256).digest())
        self.approvals = ApprovalStore(self.data_dir / "approvals.jsonl")
        self.loop = LoopGuard(time.monotonic)
        self.feed = self._load_feed()
        self._lock = threading.Lock()
        self.overrides: dict[str, bool] = {}
        self.approval_args: dict[str, dict] = {}   # display copy (masked); the store keeps only a hash
        self.killed: set[str] = self._load_killed()
        self._eff_cache: tuple[Any, Any] | None = None
        self.started = time.time()
        self.tests_paths = [REPO_DIR / "reports" / "last-run.json", self.data_dir / "last-run.json"]
        self._chain_cache: tuple[float, bool] | None = None
        try:
            self.ensure_fixture()
        except Exception:  # noqa: BLE001
            pass
        # policy reload / rejection events become audit records
        self.store.on_event = self._on_policy_event
        self._log_admin("policy", "allow", f"gateway started with policy v{self.store.version} "
                        f"({self.store.hash})", extra={"status": "startup"})

    # ------------------------------------------------------------------ setup helpers
    def _load_key(self) -> bytes:
        env = os.environ.get("AGENTSHIELD_AUDIT_KEY")
        if env:
            return env.encode()
        path = self.data_dir / "audit.key"
        if path.exists():
            return path.read_text().strip().encode()
        key = _secrets.token_hex(32)
        path.write_text(key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key.encode()

    def feed_path(self) -> Path:
        policy, _, _ = self.store.snapshot()
        rel = policy.controls.signatures.feed_file if policy.controls.signatures else "feeds/signatures.yaml"
        p = Path(rel)
        if p.is_absolute():
            return p
        cand = self.store.base_dir / rel
        return cand if cand.exists() else BACKEND_DIR / rel

    def _load_feed(self):
        try:
            return SignatureFeed(self.feed_path())
        except Exception:  # noqa: BLE001
            return None

    def _kill_file(self) -> Path:
        return self.data_dir / "kill_switch.json"

    def _load_killed(self) -> set[str]:
        try:
            return set(json.loads(self._kill_file().read_text()))
        except Exception:  # noqa: BLE001
            return set()

    def _save_killed(self) -> None:
        self._kill_file().write_text(json.dumps(sorted(self.killed)))

    # ------------------------------------------------------------------ effective policy
    def effective(self) -> tuple[Policy, str, int, list[str]]:
        """Live policy + dashboard overrides (detector toggles, runtime kill switch)."""
        policy, h, v = self.store.snapshot()
        with self._lock:
            key = (h, v, tuple(sorted(self.overrides.items())), tuple(sorted(self.killed)))
            if self._eff_cache and self._eff_cache[0] == key:
                return self._eff_cache[1]
            p = policy
            if self.overrides or self.killed:
                p = policy.model_copy(deep=True)
                for name, enabled in self.overrides.items():
                    if name == "flow":
                        p.flow.enabled = enabled
                        continue
                    cfg = p.semantic if name == "semantic" else getattr(p.controls, name, None)
                    if cfg is not None:
                        cfg.enabled = enabled
                known = {a.id for a in p.agents}
                p.kill_switch = sorted(set(p.kill_switch) | (self.killed & known))
            disabled = [n for n in DETECTORS if not self._detector_on(p, n)]
            out = (p, h, v, disabled)
            self._eff_cache = (key, out)
            return out

    @staticmethod
    def _detector_on(p: Policy, name: str) -> bool:
        if name == "semantic":
            return bool(p.semantic.enabled)
        return p.controls.active(name) is not None

    # ------------------------------------------------------------------ inspect
    @staticmethod
    def _applies(cfg_direction: str, direction: str) -> bool:
        return cfg_direction == "both" or cfg_direction == direction

    def _finish_finding(self, f: Finding, direction: str) -> Finding:
        if not f.owasp:
            f.owasp = owasp_for(f.control_id, direction)
        if not isinstance(f.action, Action):
            f.action = _act(f.action)
        return f

    async def inspect(self, text: str, ctx: Context, policy: Policy) -> Decision:
        t0 = time.perf_counter()
        direction = ctx.direction
        findings: list[Finding] = []
        text = text or ""
        views = normalize.views(text)
        c = policy.controls

        pii_cfg = c.active("pii")
        if pii_cfg and self._applies(pii_cfg.direction, direction):
            for f in pii.scan(text, views, pii_cfg):
                f.action = _act(pii_cfg.action)
                findings.append(f)

        sec_cfg = c.active("secrets")
        if sec_cfg and self._applies(sec_cfg.direction, direction):
            for f in secrets.scan(text, views, sec_cfg):
                f.action = _act(sec_cfg.action)
                findings.append(f)

        grey = False
        inj_score = 0.0
        inj_cfg = c.active("prompt_injection")
        if (
            inj_cfg
            and self._applies(inj_cfg.direction, direction)
            and (ctx.source != "tool" or inj_cfg.scan_tool_results)
        ):
            inj_score, inj_findings = injection.score(views)
            if inj_score >= inj_cfg.block_threshold:
                act = _act(inj_cfg.action)
                if act == Action.REDACT:
                    act = Action.BLOCK
                for f in inj_findings:
                    f.action = act
                    if ctx.source == "tool":
                        f.detail = (f.detail + " " if f.detail else "") + "(indirect, from tool result)"
                    findings.append(f)
            elif inj_score >= inj_cfg.review_threshold:
                grey = True
                for f in inj_findings:
                    f.action = Action.MONITOR
                    f.detail = (f.detail + " " if f.detail else "") + f"(grey zone {inj_score:.2f})"
                    findings.append(f)

        sig_cfg = c.active("signatures")
        if sig_cfg and self.feed is not None and self._applies(sig_cfg.direction, direction):
            findings.extend(self.feed.scan(views, direction, _act(sig_cfg.action)))

        can_cfg = c.active("canary")
        if can_cfg and self._applies(can_cfg.direction, direction):
            findings.extend(scan_canary(views, can_cfg.tokens, _act(can_cfg.action)))

        if pii_cfg and self._applies(pii_cfg.direction, direction) and pii_cfg.action == "redact":
            # An encoded copy of an original value may be deduplicated by scan().
            # Check the remainder after removing every mapped PII occurrence.
            remainder = pii.redact(text, [f for f in findings if f.control_id.startswith("pii.")])
            if remainder != text:
                for f in pii.scan(remainder, normalize.views(remainder), pii_cfg):
                    f.start = f.end = None  # remainder offsets are not original offsets
                    findings.append(f)

        for f in findings:
            self._finish_finding(f, direction)
            # Only original PII spans have a supported, reliable redaction path.
            # Never label text redacted while forwarding its sensitive source intact.
            if f.action == Action.REDACT and (
                not f.control_id.startswith("pii.")
                or f.start is None or f.end is None
                or not 0 <= f.start < f.end <= len(text)
            ):
                f.action = Action.BLOCK
                f.detail += "; cannot safely redact original text"
        t_detect = (time.perf_counter() - t0) * 1000

        # ---- semantic judge: grey zone only (or trigger=always), never on clear blocks
        judge_status = "skipped"
        judge_detail = None
        t_judge = 0.0
        sem = policy.semantic
        already_blocked = any(f.action == Action.BLOCK for f in findings)
        wants_judge = sem.enabled and not already_blocked and (
            grey or sem.trigger == "always"
        ) and (direction == "input" or sem.scan_output)
        if wants_judge:
            # Classifier privacy is independent of enabled controls/entity subsets.
            privacy = pii.scan(text, views, PiiCfg())
            safe_text = pii.redact(text, privacy)
            residual = pii.scan(safe_text, normalize.views(safe_text), PiiCfg())
            unsafe = [f for f in privacy if f.start is None or f.end is None] + residual
            if unsafe:
                # Replacing the whole request with a placeholder would discard its
                # attack intent. Refuse dispatch when privacy-safe classification
                # cannot preserve the request, even with PII enforcement disabled.
                for f in unsafe:
                    f.action = Action.BLOCK
                    f.start = f.end = None
                    f.detail += "; cannot safely sanitize classifier input"
                    findings.append(self._finish_finding(f, direction))
                wants_judge = False
        if wants_judge:
            self.admit_dispatch(ctx.agent_id or "anonymous", ctx.session_id,
                                ctx.policy_hash, ctx.policy_version, "judge")
            j0 = time.perf_counter()
            try:
                verdict = await self.judge.classify(safe_text, sem)
                status, risk = verdict.status, float(verdict.risk or 0.0)
                reason = f"{verdict.category}: {verdict.reason}"[:200]
                judge_detail = {
                    "risk": round(risk, 3), "category": verdict.category, "model": verdict.model,
                    "latency_ms": float(verdict.latency_ms), "cost_usd": float(verdict.cost_usd),
                    "reason": verdict.reason[:200],
                }
            except Exception as exc:  # noqa: BLE001 - judge failure is an availability event
                status, risk, reason = "error", 1.0, f"judge crashed: {type(exc).__name__}"
            t_judge = (time.perf_counter() - j0) * 1000
            if judge_detail is None:
                judge_detail = {
                    "risk": round(risk, 3), "category": "prompt_injection", "model": sem.model,
                    "latency_ms": t_judge, "cost_usd": 0.0, "reason": reason[:200],
                }
            judge_status = status
            if status in ("allow", "block"):
                if status == "block" or risk >= sem.threshold:
                    findings.append(Finding(
                        control_id="semantic.judge", action=_act(sem.action), score=risk,
                        via="judge", detail=reason, owasp="LLM01",
                    ))
            elif status != "disabled":
                cid = "semantic.budget" if status == "budget" else "semantic.unavailable"
                if grey and policy.fail_mode == "closed":
                    act, detail = Action.BLOCK, f"judge {status} on grey-zone input; fail_mode=closed"
                else:
                    act = Action.MONITOR
                    detail = (f"judge {status}; fail_mode=open" if grey
                              else f"judge {status} on non-grey traffic; deterministic decision kept")
                if reason:
                    detail += f" ({reason})"
                findings.append(Finding(control_id=cid, action=act, score=risk if grey else 0.0,
                                        via="judge", detail=detail, owasp="LLM01"))

        findings = self.downgrade(findings, policy)
        action = strongest([f.action for f in findings])
        out_text = text
        if action == Action.REDACT:
            out_text = pii.redact(text, [f for f in findings if f.action == Action.REDACT])
        return Decision(
            action=action,
            findings=findings,
            text=out_text,
            timings_ms={"detect": round(t_detect, 2), "judge": round(t_judge, 2)},
            judge=judge_status,
            judge_detail=judge_detail,
        )

    @staticmethod
    def downgrade(findings: list[Finding], policy: Policy) -> list[Finding]:
        """Monitor mode: record what WOULD have happened, change nothing."""
        if policy.mode != "monitor":
            return findings
        for f in findings:
            if f.action in (Action.BLOCK, Action.REDACT, Action.REQUIRE_APPROVAL) and not f.control_id.startswith(
                _NOT_DOWNGRADED
            ):
                f.detail = f"would_{f.action.value}" + (f"; {f.detail}" if f.detail else "")
                f.action = Action.MONITOR
        return findings

    # ------------------------------------------------------------------ records
    @staticmethod
    def _primary(findings: list[Finding]) -> Finding | None:
        if not findings:
            return None
        # ties: first finding wins (callers put the most explanatory control first)
        best = findings[0]
        for f in findings[1:]:
            if (SEVERITY[f.action], f.score) > (SEVERITY[best.action], best.score):
                best = f
        return best

    @staticmethod
    def _summary(action: Action, primary: Finding | None, prefix: str = "") -> str:
        if primary is None or action in (Action.ALLOW,):
            base = "allowed, no findings" if primary is None else f"allowed ({primary.control_id} noted)"
            return f"{prefix}{base}"
        verb = {
            Action.BLOCK: "blocked",
            Action.REDACT: "redacted",
            Action.REQUIRE_APPROVAL: "approval required",
            Action.MONITOR: "monitored",
        }[action]
        where = ""
        if primary.start is not None:
            where = f" at {primary.start}-{primary.end}"
        elif primary.via and primary.via != "original":
            where = f" via {primary.via}"
        why = primary.detail or primary.evidence
        return f"{prefix}{verb} by {primary.control_id}{where}" + (f": {why}" if why else "")

    def build_record(
        self,
        *,
        kind: str,
        request_id: str,
        agent_id: str | None,
        session_id: str | None,
        direction: str,
        findings: list[Finding],
        policy_hash: str,
        policy_version: int,
        detectors_disabled: list[str],
        judge: str = "skipped",
        judge_detail: dict[str, Any] | None = None,
        timings: dict[str, float] | None = None,
        model: str | None = None,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cost_usd: float = 0.0,
        approval_id: str | None = None,
        action: Action | None = None,
        summary: str | None = None,
        extra: dict | None = None,
        segments: list[tuple[str, list[Finding]]] | None = None,
    ) -> dict:
        action = action or strongest([f.action for f in findings])
        primary = self._primary(findings)
        excerpt, excerpt_offset = self._excerpt_for(primary, segments or [])
        rec = {
            "request_id": request_id,
            "kind": kind,
            "agent_id": agent_id,
            "session_id": session_id,
            "direction": direction,
            "action": action.value,
            "summary": summary or self._summary(action, primary),
            "primary": None if primary is None else {
                "control_id": primary.control_id,
                "evidence": primary.evidence,
                "start": primary.start,
                "end": primary.end,
                "via": primary.via,
                "owasp": primary.owasp,
                "detail": primary.detail,
                "action": primary.action.value,
                "score": round(primary.score, 3),
            },
            "findings": [f.to_dict() for f in findings],
            "policy_hash": policy_hash,
            "policy_version": policy_version,
            "judge": judge,
            "timings_ms": timings or {},
            "model": model,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "cost_usd": round(cost_usd, 8),
            "detectors_disabled": detectors_disabled,
            "excerpt": excerpt,
            "excerpt_offset": excerpt_offset,
        }
        if judge_detail is not None:
            rec["judge_detail"] = judge_detail
        if approval_id:
            rec["approval_id"] = approval_id
        if extra:
            rec.update(extra)
        return rec

    def _excerpt_for(self, primary: Finding | None, segments: list[tuple[str, list[Finding]]]) -> tuple[str, int]:
        """Offset-preserving masked excerpt (<= 400 chars): PII/secret spans are masked in place,
        so primary.start/end still index into it (minus excerpt_offset)."""
        if not segments:
            return "", 0
        seg = None
        if primary is not None:
            seg = next((sg for sg in segments if any(f is primary for f in sg[1])), None)
        text, fs = seg or segments[-1]
        if not text:
            return "", 0
        privacy = [f for f in fs if f.control_id.startswith(("pii.", "secrets.", "canary"))]
        try:
            # Policy findings may cover only selected entities or directions.
            views = normalize.views(text)
            privacy += pii.scan(text, views, PiiCfg())
            privacy += secrets.scan(text, views, ControlCfg())
        except Exception:  # noqa: BLE001 - omit evidence rather than risk disclosure
            return "", 0
        if any(f.start is None or f.end is None for f in privacy):
            # Decoded/normalized credentials cannot be safely masked by offsets.
            return "", 0
        spans = [(f.start, f.end) for f in privacy]
        remainder = list(text)
        for a, b in spans:
            if 0 <= a < b <= len(remainder):
                remainder[a:b] = " " * (b - a)
        remainder_text = "".join(remainder)
        try:
            remainder_views = normalize.views(remainder_text)
            if (pii.scan(remainder_text, remainder_views, PiiCfg())
                    or secrets.scan(remainder_text, remainder_views, ControlCfg())):
                return "", 0
        except Exception:  # noqa: BLE001
            return "", 0
        chars = list(text)
        for a, b in spans:
            a, b = max(0, a), min(len(chars), b or 0)
            n = b - a
            if n <= 0:
                continue
            keep = 2 if n > 6 else 0
            for i in range(a + keep, b - keep):
                if not chars[i].isspace():
                    chars[i] = "\u2022"
        out = "".join(chars)
        off = 0
        if len(out) > 400:
            anchor = primary.start if primary is not None and primary.start is not None and seg else 0
            off = max(0, min(anchor - 100, len(out) - 400))
            out = out[off:off + 400]
        return out, off

    def commit(self, rec: dict, observe: bool = True) -> dict:
        self.require_audit()
        try:
            out = self.audit.append(rec)
        except Exception as exc:
            self.audit_unavailable = True
            self._chain_cache = None
            raise AuditUnavailable("audit persistence failed") from exc
        if observe:
            if out.get("action") in self.counts:
                self.counts[out["action"]] += 1
            try:
                self.metrics.observe(out)
            except Exception:  # noqa: BLE001
                pass
        return out

    def require_audit(self) -> None:
        if self.audit_unavailable:
            raise AuditUnavailable("audit persistence unavailable")

    def admit_dispatch(self, agent_id: str, session_id: str, policy_hash: str,
                       policy_version: int, operation: str) -> None:
        """Persist admission before any paid upstream or tool side effect."""
        self.commit({"kind": "dispatch", "action": "allow", "summary": "Dispatch admitted",
                     "request_id": uuid.uuid4().hex[:16], "agent_id": agent_id,
                     "session_id": session_id, "policy_hash": policy_hash,
                     "policy_version": policy_version, "operation": operation,
                     "cost_usd": 0}, observe=False)

    @staticmethod
    def flow_key(agent_id: str | None) -> str:
        # A caller-controlled session must never erase a principal's exposure.
        return "agent:" + (agent_id or "anonymous")

    def _log_admin(self, kind: str, action: str, summary: str, extra: dict | None = None,
                   primary: dict | None = None) -> dict:
        try:
            _, h, v, disabled = self.effective()
        except Exception:  # noqa: BLE001
            h, v, disabled = self.store.hash, self.store.version, []
        rec = {
            "request_id": uuid.uuid4().hex[:16], "kind": kind, "agent_id": None, "session_id": None,
            "direction": "admin", "action": action, "summary": summary, "primary": primary,
            "findings": [], "policy_hash": h, "policy_version": v, "judge": "skipped",
            "timings_ms": {}, "model": None, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0,
            "detectors_disabled": disabled, **(extra or {}),
        }
        return self.commit(rec, observe=False)

    def _on_policy_event(self, e: dict) -> None:
        status = e.get("status")
        if status == "applied":
            summary = f"policy v{e.get('version')} applied ({e.get('hash')}); changed: " + (
                ", ".join(e.get("changed") or []) or "-")
            self._log_admin("policy", "allow", summary[:500], extra={"status": "applied", "event": e})
        else:
            summary = (f"policy edit rejected ({e.get('error')}); still enforcing "
                       f"v{e.get('active_version')} ({e.get('active_hash')})")
            self._log_admin("policy", "block", summary[:500], extra={"status": "rejected", "event": e},
                            primary={"control_id": "policy.rejected", "evidence": "", "start": None,
                                     "end": None, "via": "policy", "owasp": "",
                                     "detail": str(e.get("error"))[:300]})

    def _headers(self, rec: dict, total_ms: float, upstream_ms: float = 0.0) -> dict[str, str]:
        return {
            "X-AgentShield-Decision": str(rec.get("action")),
            "X-AgentShield-Overhead-Ms": f"{max(total_ms - upstream_ms, 0):.2f}",
            "X-AgentShield-Policy": f"{rec.get('policy_version')}:{rec.get('policy_hash')}",
            "X-AgentShield-Record": str(rec.get("seq", "")),
        }

    def _deny(self, rec: dict, t0: float, upstream_ms: float = 0.0) -> GatewayResult:
        total = (time.perf_counter() - t0) * 1000
        rec.setdefault("timings_ms", {})["total"] = round(total, 2)
        rec = self.commit(rec)
        code = (rec.get("primary") or {}).get("control_id")
        return GatewayResult(status_for(code), _blocked_body(rec), self._headers(rec, total, upstream_ms), rec)

    # ------------------------------------------------------------------ auth
    def authenticate(self, policy: Policy, authorization: str | None, agent_header: str | None):
        """Returns (agent, finding_or_None)."""
        key = None
        if authorization:
            parts = authorization.split(None, 1)
            key = parts[1].strip() if len(parts) == 2 and parts[0].lower() == "bearer" else authorization.strip()
        agent = policy.agent_by_key(key) if key else None
        if key and agent is None:
            return None, Finding("auth.invalid", Action.BLOCK, detail="unknown API key", owasp="LLM06")
        if agent is None and policy.require_auth:
            return None, Finding("auth.missing", Action.BLOCK, detail="Authorization: Bearer <agent key> required",
                                 owasp="LLM06")
        if agent is not None and agent_header and not hmac.compare_digest(agent_header, agent.id):
            return agent, Finding("auth.impersonation", Action.BLOCK,
                                  detail=f"X-Agent-Id '{agent_header[:40]}' does not match key owner",
                                  owasp="LLM06")
        return agent, None

    # ------------------------------------------------------------------ tool governance
    def _approval_id_from(self, findings: list[Finding], agent_id: str, tool: str) -> str | None:
        for f in findings:
            if f.control_id != "tools.approval":
                continue
            m = re.search(r"(?:approval[_ ]?id)\s*[=:]\s*([A-Za-z0-9_.:-]+)", f.detail or "")
            if m:
                return m.group(1)
            token = (f.detail or "").strip()
            if token and " " not in token:
                return token
        try:
            pend = [a for a in self.approvals.list("pending")
                    if a.get("agent_id") == agent_id and a.get("tool") == tool]
            if pend:
                return pend[-1].get("id")
        except Exception:  # noqa: BLE001
            pass
        return None

    def govern_tool(
        self, policy: Policy, policy_hash: str, agent, tool: str, raw_args: Any,
        session_id: str, approval_id: str | None,
    ) -> tuple[dict | None, list[Finding], str | None]:
        """allow-list -> args -> flow -> approval. Returns (args, findings, approval_id)."""
        args, gov = check_tool_call(policy, agent, tool, raw_args, self.approvals, approval_id, policy_hash)
        gov = [self._finish_finding(f, "output") for f in gov]
        flow_f: list[Finding] = []
        tool_cfg = policy.tools.get(tool)
        if args is not None and policy.flow.enabled and tool_cfg is not None:
            flow_f = [self._finish_finding(f, "output")
                      for f in self.taint.check_egress(self.flow_key(agent.id if agent else None),
                                                     tool, tool_cfg, args, policy.flow)]
        gov_wants_approval = any(f.control_id == "tools.approval" and f.action == Action.REQUIRE_APPROVAL
                                 for f in gov)
        approved = (approval_id is not None and not gov_wants_approval
                    and not any(f.action == Action.BLOCK for f in gov))
        if approved:
            # a human already approved this exact call: F4 (approval) is satisfied, blocks are not
            flow_f = [f for f in flow_f if f.action != Action.REQUIRE_APPROVAL]
        findings = [*flow_f, *gov]   # flow first: it explains the more specific attack
        new_approval = None
        if any(f.action == Action.REQUIRE_APPROVAL for f in findings):
            new_approval = self._approval_id_from(gov, agent.id if agent else "", tool)
            if new_approval is None and not any(f.action == Action.BLOCK for f in findings):
                try:
                    a = self.approvals.create(agent.id if agent else "", tool, args or {}, policy_hash,
                                              policy.approval_ttl_s)
                    new_approval = a.get("id")
                except Exception:  # noqa: BLE001
                    pass
        if new_approval and any(f.action == Action.BLOCK for f in findings):
            # a block always wins; do not leave an approvable request behind
            try:
                self.approvals.decide(new_approval, False, who="flow")
            except Exception:  # noqa: BLE001
                pass
            new_approval = None
        if new_approval and args is not None:
            self.approval_args[new_approval] = _display_args(args)
        findings = self.downgrade(findings, policy)
        for f in findings:
            if f.action == Action.REQUIRE_APPROVAL and new_approval and "approval" not in (f.detail or ""):
                f.detail = (f.detail + "; " if f.detail else "") + f"approval_id={new_approval}"
        return args, findings, new_approval

    # ------------------------------------------------------------------ chat lifecycle
    async def chat(self, body: dict, headers: dict[str, str]) -> GatewayResult:
        self.require_audit()
        t0 = time.perf_counter()
        policy, phash, pver, disabled = self.effective()
        rid = uuid.uuid4().hex[:16]
        h = {k.lower(): v for k, v in headers.items()}
        model_name = str(body.get("model") or "")
        segments: list[tuple[str, list[Finding]]] = []
        base = dict(kind="chat", request_id=rid, policy_hash=phash, policy_version=pver,
                    detectors_disabled=disabled, model=model_name or None, segments=segments)

        # 1. auth -> kill switch -> size -> model allow-list
        agent, auth_f = self.authenticate(policy, h.get("authorization"), h.get("x-agent-id"))
        agent_id = agent.id if agent else ("anonymous" if not auth_f else None)
        if auth_f:
            return self._deny(self.build_record(agent_id=agent_id, session_id=None, direction="input",
                                                findings=[auth_f], **base), t0)
        # Strict validation before conversion/reservation. Multiple choices are
        # unsupported because their output budget would require a separate bound.
        invalid = None
        if "n" in body and (type(body["n"]) is not int or body["n"] != 1):
            invalid = "n must be 1"
        limits = [key for key in ("max_tokens", "max_completion_tokens") if key in body]
        if len(limits) > 1:
            invalid = "specify only one output token limit"
        if any(type(body[key]) is not int or body[key] <= 0 for key in limits):
            invalid = "output token limit must be a positive integer"
        if invalid:
            return GatewayResult(400, {"error": {"type": "invalid_request", "message": invalid}})
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            f = Finding("limits.input_size", Action.BLOCK, detail="messages must be a non-empty list",
                        owasp="LLM10")
            return self._deny(self.build_record(agent_id=agent_id, session_id=None, direction="input",
                                                findings=[f], **base), t0)
        if agent and agent.id in policy.kill_switch:
            f = Finding("tools.kill_switch", Action.BLOCK, detail=f"agent {agent.id} is kill-switched",
                        owasp="LLM06")
            return self._deny(self.build_record(agent_id=agent_id, session_id=None, direction="input",
                                                findings=[f], **base), t0)
        total_chars = sum(len(_content_text(m.get("content"))) for m in messages if isinstance(m, dict))
        if total_chars > policy.max_input_chars:
            f = Finding("limits.input_size", Action.BLOCK,
                        detail=f"{total_chars} chars > max_input_chars {policy.max_input_chars}", owasp="LLM10")
            return self._deny(self.build_record(agent_id=agent_id, session_id=None, direction="input",
                                                findings=[f], **base), t0)
        if not policy.model_allowed(agent, model_name):
            f = Finding("model.not_allowed", Action.BLOCK, evidence=model_name[:60],
                        detail=f"model '{model_name[:60]}' is not allowed for {agent_id}", owasp="LLM10")
            return self._deny(self.build_record(agent_id=agent_id, session_id=None, direction="input",
                                                findings=[f], **base), t0)

        # 2. session + loop guard
        first_user = next((_content_text(m.get("content")) for m in messages
                           if isinstance(m, dict) and m.get("role") == "user"), "")
        session_id = h.get("x-session") or "s_" + hashlib.sha256(
            f"{agent_id}|{first_user}".encode()).hexdigest()[:16]
        base["session_id"] = session_id
        findings: list[Finding] = []
        loop_cfg = policy.controls.active("loop")
        if loop_cfg:
            last = messages[-1] if isinstance(messages[-1], dict) else {}
            fp = hashlib.sha256(_canonical([last.get("role"), _content_text(last.get("content"))]).encode()).hexdigest()
            lf = self.loop.check(agent_id or "", session_id, fp, loop_cfg)
            if lf is not None:
                lf.action = _act(loop_cfg.action) if lf.action != Action.MONITOR else lf.action
                findings.extend(self.downgrade([self._finish_finding(lf, "input")], policy))

        # 3+4. label tool messages, inspect every client message, redact forwarded copy
        fwd = copy.deepcopy(body)
        fwd.pop("stream", None)
        fwd.pop("stream_options", None)
        t_detect = 0.0
        t_judge = 0.0
        judge_status = "skipped"
        for i, m in enumerate(fwd["messages"]):
            if not isinstance(m, dict):
                continue
            role = m.get("role")
            text = _content_text(m.get("content"))
            if not text:
                continue
            source = "user"
            tool_name = None
            if role == "tool":
                source = "tool"
                tool_name = verify_call_id(str(m.get("tool_call_id") or ""), self.call_key)
                tcfg = policy.tools.get(tool_name) if tool_name else None
                labels = list(tcfg.labels) if tcfg else ["untrusted"]
                if not tool_name:
                    labels = ["untrusted"]   # unknown / forged id: provenance cannot be trusted
                self.taint.add(self.flow_key(agent_id), tool_name or "unverified", labels, text)
            elif role == "assistant":
                source = "model"
            ctx = Context(request_id=rid, agent_id=agent_id, session_id=session_id, policy_hash=phash,
                          policy_version=pver, direction="input", source=source, tool_name=tool_name)
            d = await self.inspect(text, ctx, policy)
            t_detect += d.timings_ms.get("detect", 0)
            t_judge += d.timings_ms.get("judge", 0)
            if d.judge != "skipped":
                judge_status = d.judge
                base["judge_detail"] = d.judge_detail
            findings.extend(d.findings)
            segments.append((text, d.findings))
            if d.action == Action.REDACT:
                m["content"] = d.text

        if any(f.action == Action.BLOCK for f in findings):
            rec = self.build_record(agent_id=agent_id, direction="input", findings=findings, judge=judge_status,
                                    timings={"detect": round(t_detect, 2), "judge": round(t_judge, 2)}, **base)
            return self._maybe_message_block(rec, t0, policy, body)

        # 5. budget reserve -> upstream -> settle
        model_cfg = policy.models[model_name]
        budget = policy.budget_for(agent)
        # Include tool schemas and other provider input in the reservation estimate.
        est_in = estimate_tokens(_canonical(fwd))
        limit_field = limits[0] if limits else "max_tokens"
        max_out = body[limit_field] if limits else min(budget.max_tokens_per_request or 1024, 1024)
        fwd[limit_field] = max_out  # The provider must receive the same bound we reserve.
        res, bud_f = self.ledger.reserve(agent_id or "anonymous", budget, model_cfg, est_in, max_out)
        bud_f = [self._finish_finding(f, "input") for f in bud_f]
        findings.extend(bud_f)
        if res is None:
            if not any(f.action == Action.BLOCK for f in bud_f):
                findings.append(Finding("budget.usd", Action.BLOCK, detail="budget reservation refused",
                                        owasp="LLM10"))
            rec = self.build_record(agent_id=agent_id, direction="input", findings=findings, judge=judge_status,
                                    timings={"detect": round(t_detect, 2), "judge": round(t_judge, 2)}, **base)
            return self._deny(rec, t0)

        try:
            self.admit_dispatch(agent_id or "anonymous", session_id, phash, pver, "chat")
        except AuditUnavailable:
            self.ledger.release(res)
            raise
        u0 = time.perf_counter()
        self.upstream_calls += 1
        try:
            result = await upstream.complete(model_name, model_cfg, fwd, transport=self.transport)
        except Exception as exc:  # noqa: BLE001
            upstream_ms = (time.perf_counter() - u0) * 1000
            # keep the reservation: charge what we reserved
            try:
                self.ledger.settle(res, est_in, max_out, 0.0, model_cfg)
            except Exception:  # noqa: BLE001
                pass
            rec = self.build_record(agent_id=agent_id, direction="input", findings=findings, judge=judge_status,
                                    timings={"detect": round(t_detect, 2), "judge": round(t_judge, 2),
                                             "upstream": round(upstream_ms, 2)},
                                    action=Action.BLOCK, summary=f"upstream error: {type(exc).__name__}: {exc}"[:300],
                                    extra={"status": "upstream_error"}, **base)
            total = (time.perf_counter() - t0) * 1000
            rec["timings_ms"]["total"] = round(total, 2)
            rec = self.commit(rec)
            return GatewayResult(502, {"error": {"type": "upstream_error", "message": rec["summary"],
                                                 "record": rec}}, self._headers(rec, total, upstream_ms), rec)
        upstream_ms = (time.perf_counter() - u0) * 1000
        cost = self.ledger.settle(res, result.prompt_tokens, result.completion_tokens, result.compute_s, model_cfg)

        # 6. output inspection + proposed tool calls
        response = copy.deepcopy(result.response)
        choices = response.get("choices") or []
        approval_id = None
        out_findings: list[Finding] = []
        for ch in choices:
            msg = ch.get("message") or {}
            # Refusals are user-visible text in JSON, SSE and Anthropic output.
            for field in ("content", "refusal"):
                text = _content_text(msg.get(field))
                if text:
                    ctx = Context(request_id=rid, agent_id=agent_id, session_id=session_id, policy_hash=phash,
                                  policy_version=pver, direction="output", source="model")
                    d = await self.inspect(text, ctx, policy)
                    t_detect += d.timings_ms.get("detect", 0)
                    t_judge += d.timings_ms.get("judge", 0)
                    if d.judge != "skipped":
                        judge_status = d.judge
                        base["judge_detail"] = d.judge_detail
                    out_findings.extend(d.findings)
                    segments.append((text, d.findings))
                    if d.action == Action.REDACT:
                        msg[field] = d.text
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                name = str(fn.get("name") or "")
                args, tf, appr = self.govern_tool(policy, phash, agent, name, fn.get("arguments") or "{}",
                                                  session_id, h.get("x-approval"))
                out_findings.extend(tf)
                raw = fn.get("arguments")
                segments.append((raw if isinstance(raw, str) else _canonical(raw), tf))
                approval_id = approval_id or appr
                if not any(f.action in (Action.BLOCK, Action.REQUIRE_APPROVAL) for f in tf):
                    tc["id"] = sign_call_id(str(tc.get("id") or uuid.uuid4().hex[:12]), name, session_id,
                                            self.call_key)
        findings.extend(out_findings)
        direction = "output" if out_findings else "input"
        timings = {"detect": round(t_detect, 2), "judge": round(t_judge, 2), "upstream": round(upstream_ms, 2)}
        base["extra"] = {"compute_s": result.compute_s}
        common = dict(agent_id=agent_id, direction=direction, findings=findings, judge=judge_status,
                      timings=timings, tokens_in=result.prompt_tokens, tokens_out=result.completion_tokens,
                      cost_usd=cost, **base)
        final = strongest([f.action for f in findings])
        if final in (Action.BLOCK, Action.REQUIRE_APPROVAL):
            rec = self.build_record(approval_id=approval_id if final == Action.REQUIRE_APPROVAL else None, **common)
            if final == Action.BLOCK:
                return self._maybe_message_block(rec, t0, policy, body, upstream_ms)
            return self._deny(rec, t0, upstream_ms)

        # 7. audit -> metrics -> response
        rec = self.build_record(**common)
        total = (time.perf_counter() - t0) * 1000
        rec["timings_ms"]["total"] = round(total, 2)
        rec = self.commit(rec)
        response.setdefault("agentshield", {})
        response["agentshield"] = {"action": rec["action"], "seq": rec.get("seq"), "summary": rec["summary"]}
        return GatewayResult(200, response, self._headers(rec, total, upstream_ms), rec,
                             stream=bool(body.get("stream")))

    def _maybe_message_block(self, rec: dict, t0: float, policy: Policy, body: dict,
                             upstream_ms: float = 0.0) -> GatewayResult:
        if policy.block_response != "message":
            return self._deny(rec, t0, upstream_ms)
        total = (time.perf_counter() - t0) * 1000
        rec.setdefault("timings_ms", {})["total"] = round(total, 2)
        rec = self.commit(rec)
        resp = {
            "id": "chatcmpl-" + rec["request_id"], "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model"),
            "choices": [{"index": 0, "finish_reason": "content_filter",
                         "message": {"role": "assistant",
                                     "content": f"Request blocked by AgentShield: {rec['summary']}"}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "agentshield": {"action": rec["action"], "seq": rec.get("seq"), "summary": rec["summary"]},
        }
        return GatewayResult(200, resp, self._headers(rec, total, upstream_ms), rec, stream=bool(body.get("stream")))

    # ------------------------------------------------------------------ tool lifecycle
    async def tool_call(self, body: dict, headers: dict[str, str]) -> GatewayResult:
        self.require_audit()
        t0 = time.perf_counter()
        policy, phash, pver, disabled = self.effective()
        rid = uuid.uuid4().hex[:16]
        h = {k.lower(): v for k, v in headers.items()}
        tool = str(body.get("tool") or body.get("name") or "")
        segments: list[tuple[str, list[Finding]]] = []
        base = dict(kind="tool", request_id=rid, policy_hash=phash, policy_version=pver,
                    detectors_disabled=disabled, model=None, extra={"tool": tool}, segments=segments)
        agent, auth_f = self.authenticate(policy, h.get("authorization"), h.get("x-agent-id"))
        agent_id = agent.id if agent else ("anonymous" if not auth_f else None)
        if auth_f:
            return self._deny(self.build_record(agent_id=agent_id, session_id=None, direction="input",
                                                findings=[auth_f], **base), t0)
        session_id = h.get("x-session") or str(body.get("session_id") or f"default:{agent_id}")
        base["session_id"] = session_id
        approval_id = h.get("x-approval") or body.get("approval_id")
        raw_args = body.get("arguments", {})
        if raw_args is None:
            raw_args = {}

        findings: list[Finding] = []
        loop_cfg = policy.controls.active("loop")
        if loop_cfg:
            fp = hashlib.sha256(f"tool:{tool}:{raw_args if isinstance(raw_args, str) else _canonical(raw_args)}"
                                .encode()).hexdigest()
            lf = self.loop.check(agent_id or "", session_id, fp, loop_cfg)
            if lf is not None:
                findings.extend(self.downgrade([self._finish_finding(lf, "input")], policy))

        g0 = time.perf_counter()
        args, tf, appr = self.govern_tool(policy, phash, agent, tool, raw_args, session_id, approval_id)
        findings.extend(tf)
        segments.append((raw_args if isinstance(raw_args, str) else _canonical(raw_args), tf))
        t_gov = (time.perf_counter() - g0) * 1000
        final = strongest([f.action for f in findings])
        if final in (Action.BLOCK, Action.REQUIRE_APPROVAL) or args is None:
            if args is None and final not in (Action.BLOCK, Action.REQUIRE_APPROVAL):
                findings.append(Finding("tools.args", Action.BLOCK, detail="arguments could not be parsed",
                                        owasp="LLM06"))
            rec = self.build_record(agent_id=agent_id, direction="input", findings=findings,
                                    timings={"detect": round(t_gov, 2)},
                                    approval_id=appr if final == Action.REQUIRE_APPROVAL else None, **base)
            return self._deny(rec, t0)

        # execute (demo tools), then label + scan the result
        from app import tools as tools_mod

        self.admit_dispatch(agent_id or "anonymous", session_id, phash, pver, "tool")
        u0 = time.perf_counter()
        try:
            out = tools_mod.run_tool(tool, args)
            output = out if isinstance(out, str) else _canonical(out)
        except Exception as exc:  # noqa: BLE001
            output = f"tool error: {type(exc).__name__}: {exc}"
        exec_ms = (time.perf_counter() - u0) * 1000
        tcfg = policy.tools.get(tool)
        labels = list(tcfg.labels) if tcfg else ["untrusted"]
        self.taint.add(self.flow_key(agent_id), tool, labels, output)

        ctx = Context(request_id=rid, agent_id=agent_id, session_id=session_id, policy_hash=phash,
                      policy_version=pver, direction="input", source="tool", tool_name=tool)
        d = await self.inspect(output, ctx, policy)
        findings.extend(d.findings)
        segments.append((output, d.findings))
        timings = {"detect": round(t_gov + d.timings_ms.get("detect", 0), 2),
                   "judge": d.timings_ms.get("judge", 0), "upstream": round(exec_ms, 2)}
        call_id = sign_call_id(str(body.get("call_id") or uuid.uuid4().hex[:12]), tool, session_id, self.call_key)
        base["extra"] = {"tool": tool, "labels": labels, "call_id": call_id}
        base["judge_detail"] = d.judge_detail
        if d.action == Action.BLOCK:
            rec = self.build_record(agent_id=agent_id, direction="input", findings=findings, judge=d.judge,
                                    timings=timings, summary=None, **base)
            rec["summary"] = "tool result withheld: " + rec["summary"]
            return self._deny(rec, t0, exec_ms)
        rec = self.build_record(agent_id=agent_id, direction="input", findings=findings, judge=d.judge,
                                timings=timings, **base)
        total = (time.perf_counter() - t0) * 1000
        rec["timings_ms"]["total"] = round(total, 2)
        rec = self.commit(rec)
        resp = {"tool": tool, "call_id": call_id, "result": d.text, "labels": labels,
                "action": rec["action"], "record": rec}
        return GatewayResult(200, resp, self._headers(rec, total, exec_ms), rec)

    # ------------------------------------------------------------------ try-it
    async def try_text(self, agent_key: str | None, text: str, direction: str = "input") -> dict:
        self.require_audit()
        t0 = time.perf_counter()
        policy, phash, pver, disabled = self.effective()
        agent = policy.agent_by_key(agent_key) if agent_key else None
        direction = direction if direction in ("input", "output") else "input"
        rid = uuid.uuid4().hex[:16]
        ctx = Context(request_id=rid, agent_id=agent.id if agent else None, session_id="try",
                      policy_hash=phash, policy_version=pver, direction=direction,
                      source="user" if direction == "input" else "model")
        d = await self.inspect(text or "", ctx, policy)
        rec = self.build_record(kind="try", request_id=rid, agent_id=ctx.agent_id, session_id="try",
                                direction=direction, findings=d.findings, policy_hash=phash, policy_version=pver,
                                detectors_disabled=disabled, judge=d.judge, judge_detail=d.judge_detail,
                                timings=dict(d.timings_ms),
                                segments=[(text or "", d.findings)])
        rec["timings_ms"]["total"] = round((time.perf_counter() - t0) * 1000, 2)
        rec = self.commit(rec)
        out = dict(rec)
        out["redacted_text"] = d.text if d.action != Action.BLOCK else None
        return out

    # ------------------------------------------------------------------ admin actions
    def set_override(self, control: str, enabled: bool) -> dict:
        if control not in TOGGLEABLE:
            raise ValueError(f"unknown control '{control}' (toggleable: {', '.join(TOGGLEABLE)})")
        with self._lock:
            self.overrides[control] = bool(enabled)
        self._log_admin("policy", "allow" if enabled else "monitor",
                        f"dashboard toggle: {control} {'enabled' if enabled else 'DISABLED'}",
                        extra={"status": "override", "control": control, "enabled": bool(enabled)})
        return self.overrides_view()

    def detectors_off(self) -> dict:
        with self._lock:
            for n in DETECTORS:
                self.overrides[n] = False
        self._log_admin("policy", "monitor", "dashboard: ALL detectors disabled (flow guard stays on)",
                        extra={"status": "override", "detectors_off": list(DETECTORS)})
        return self.overrides_view()

    def detectors_on(self) -> dict:
        with self._lock:
            for n in (*DETECTORS, "loop"):
                self.overrides.pop(n, None)
        self._log_admin("policy", "allow", "dashboard: detector overrides cleared (policy file rules)",
                        extra={"status": "override"})
        return self.overrides_view()

    def overrides_view(self) -> dict:
        _, _, _, disabled = self.effective()
        return {"overrides": dict(self.overrides), "detectors_disabled": disabled}

    def kill(self, agent_id: str) -> dict:
        policy, _, _ = self.store.snapshot()
        if policy.agent_by_id(agent_id) is None:
            raise KeyError(agent_id)
        with self._lock:
            self.killed.add(agent_id)
            self._save_killed()
        self._log_admin("kill", "block", f"kill switch ON for {agent_id}", extra={"target_agent": agent_id},
                        primary={"control_id": "tools.kill_switch", "evidence": agent_id, "start": None,
                                 "end": None, "via": "dashboard", "owasp": "LLM06", "detail": "manual kill"})
        return {"killed": sorted(self.effective()[0].kill_switch)}

    def unkill(self, agent_id: str) -> dict:
        with self._lock:
            self.killed.discard(agent_id)
            self._save_killed()
        policy, _, _ = self.store.snapshot()
        note = " (still listed in policy.yaml kill_switch)" if agent_id in policy.kill_switch else ""
        self._log_admin("kill", "allow", f"kill switch OFF for {agent_id}{note}", extra={"target_agent": agent_id})
        return {"killed": sorted(self.effective()[0].kill_switch)}

    def approvals_view(self, status: str | None = None) -> list[dict]:
        out = []
        for a in self.approvals.list(status):
            out.append({
                **a,
                "id": a.get("id"), "status": a.get("status"), "agent_id": a.get("agent_id"),
                "tool": a.get("tool"), "args": self.approval_args.get(a.get("id"), {}),
                "created": a.get("created_at"), "expires": a.get("expires_at"),
            })
        out.sort(key=lambda r: r.get("created") or 0, reverse=True)
        return out

    def decide_approval(self, approval_id: str, approve: bool) -> dict:
        res = self.approvals.decide(approval_id, bool(approve), who="dashboard")
        self._log_admin("approval", "allow" if approve else "block",
                        f"approval {approval_id} {'APPROVED' if approve else 'rejected'} on dashboard",
                        extra={"approval_id": approval_id, "approval": res})
        return res

    def poll_feed(self) -> dict | None:
        if self.feed is None:
            self.feed = self._load_feed()
            return None
        try:
            ev = self.feed.reload_if_changed()
        except Exception as exc:  # noqa: BLE001
            ev = {"status": "rejected", "error": str(exc)}
        if ev:
            ok = ev.get("status") != "rejected"
            self._log_admin("policy", "allow" if ok else "block",
                            f"signature feed {'reloaded' if ok else 'rejected'}: "
                            f"{ev.get('error') or ev.get('count', '')}"[:300],
                            extra={"status": "feed_" + str(ev.get("status", "applied")), "event": ev})
        return ev

    # ------------------------------------------------------------------ tamper fixture
    def fixture_dir(self) -> Path:
        return self.data_dir / "fixtures" / "tampered"

    def ensure_fixture(self, force: bool = False) -> Path:
        """fixtures/tampered.jsonl: a chain signed with OUR key whose record #2 was edited afterwards."""
        d = self.fixture_dir()
        flat = self.data_dir / "fixtures" / "tampered.jsonl"
        if flat.exists() and not force:
            return flat
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)
        log = AuditLog(d, self.key)
        log.append({"kind": "try", "action": "block", "summary": "fixture: injection blocked"})
        log.append({"kind": "try", "action": "block", "summary": "fixture: PESEL exfiltration blocked"})
        log.append({"kind": "try", "action": "allow", "summary": "fixture: benign request"})
        path = d / "audit.jsonl"
        lines = path.read_text().splitlines()
        rec = json.loads(lines[1])
        rec["action"] = "allow"   # attacker rewrites a block into an allow, keeps the old hash
        rec["summary"] = "fixture: benign request"
        lines[1] = json.dumps(rec, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")
        shutil.copyfile(path, flat)
        shutil.rmtree(d, ignore_errors=True)
        return flat

    def verify_fixture(self) -> dict:
        flat = self.ensure_fixture()
        try:
            result = self.audit.verify(flat)
        except Exception as exc:  # noqa: BLE001
            result = {"ok": False, "reason": f"verify crashed: {exc}"}
        return {"fixture": str(flat), "tampered": "record 2 rewritten block -> allow after signing", **result}

    # ------------------------------------------------------------------ posture + snapshot
    def chain_ok(self, ttl_s: float = 5.0) -> bool:
        if self.audit_unavailable:
            return False
        now = time.monotonic()
        if self._chain_cache and now - self._chain_cache[0] < ttl_s:
            return self._chain_cache[1]
        try:
            ok = bool(self.audit.verify().get("ok"))
        except Exception:  # noqa: BLE001
            ok = False
        self._chain_cache = (now, ok)
        return ok

    def tests_report(self) -> dict:
        return load_tests_report(self.tests_paths)

    def posture(self, policy: Policy | None = None) -> dict:
        policy = policy or self.effective()[0]
        if _posture_mod is not None:
            try:
                try:
                    js = self.judge.state()
                except Exception:  # noqa: BLE001
                    js = {}
                out = dict(_posture_mod(policy, js, self.chain_ok(), self.tests_report().get("summary")))
                out["gaps"] = [g if isinstance(g, str) else str(g.get("detail") or g.get("id") or g)
                               for g in out.get("gaps", [])]
                out.setdefault("formula", POSTURE_FORMULA)
                return out
            except Exception:  # noqa: BLE001 - fall back to the inline score
                pass
        return self._posture_inline(policy)

    def _posture_inline(self, policy: Policy) -> dict:
        gaps = []

        def gap(gid: str, detail: str):
            gaps.append({"id": gid, "weight": POSTURE_WEIGHTS[gid], "detail": detail})

        if policy.mode == "monitor":
            gap("mode.monitor", "monitor mode: nothing is blocked, only logged")
        if not policy.require_auth:
            gap("auth.disabled", "require_auth is false: anonymous agents accepted")
        if not policy.flow.enabled:
            gap("flow.disabled", "information-flow guard is off")
        for name in ("prompt_injection", "pii", "secrets", "signatures", "canary", "loop"):
            cfg = policy.controls.active(name)
            if cfg is None:
                gap(f"{name}.disabled", f"control '{name}' is disabled or missing from the policy")
        if not policy.semantic.enabled:
            gap("semantic.disabled", "semantic judge is off (grey zone decided deterministically)")
        if policy.fail_mode == "open":
            gap("fail_mode.open", "grey-zone traffic is allowed when the judge is down")
        for a in policy.agents:
            b = policy.budget_for(a)
            if b.usd_per_day is None:
                gap("agent.unbudgeted", f"agent {a.id} has no daily USD budget")
        score = max(0, min(100, 100 - sum(g["weight"] for g in gaps)))
        return {
            "score": score,
            "formula": POSTURE_FORMULA,
            "gaps": [f"-{g['weight']} {g['detail']}" for g in gaps],
            "gap_details": gaps,
            "weights": POSTURE_WEIGHTS,
        }

    def coverage(self, policy: Policy) -> list[dict]:
        """OWASP LLM 2025 grid from posture.coverage(); [] if the module is unavailable."""
        if _coverage_mod is None:
            return []
        try:
            return list(_coverage_mod(policy))
        except Exception:  # noqa: BLE001
            return []

    def judge_breaker(self, policy: Policy, state: dict) -> tuple[bool, float | None]:
        """(breaker_open, open_until epoch seconds); open_until is None unless the breaker is open."""
        if state.get("breaker") != "open":
            return False, None
        opened_at = getattr(self.judge, "_opened_at", None)
        clock = getattr(self.judge, "_clock", None)
        if not isinstance(opened_at, (int, float)) or not callable(clock):
            return True, None
        remaining = opened_at + policy.semantic.breaker_cooldown_s - clock()   # judge clock is monotonic
        return True, round(time.time() + max(remaining, 0.0), 3)

    def snapshot(self) -> dict:
        policy, phash, pver, disabled = self.effective()
        controls = {}
        for name in CONTROL_NAMES:
            cfg = getattr(policy.controls, name)
            controls[name] = {
                "enabled": bool(cfg is not None and cfg.enabled),
                "action": getattr(cfg, "action", None) if cfg is not None else None,
                "present": cfg is not None,
                "overridden": name in self.overrides,
            }
        controls["semantic"] = {"enabled": policy.semantic.enabled, "action": policy.semantic.action,
                                "present": True, "overridden": "semantic" in self.overrides}
        last = self.store.history[-1] if self.store.history else {}
        last_applied = next((e for e in reversed(self.store.history) if e.get("status") == "applied"), {})
        try:
            m = self.metrics.snapshot()
        except Exception:  # noqa: BLE001
            m = {}
        try:
            js = self.judge.state()
        except Exception:  # noqa: BLE001
            js = {}
        budgets = []
        for a in policy.agents:
            b = policy.budget_for(a)
            try:
                u = self.ledger.usage(a.id, b) or {}
            except Exception:  # noqa: BLE001
                u = {}
            budgets.append({
                "agent_id": a.id,
                "usd_used": _first(u, "usd_used", "usd_today", "usd", "spend_usd", default=0.0),
                "usd_limit": _first(u, "usd_limit", default=b.usd_per_day),
                "requests_min": _first(u, "requests_min", "requests_per_minute", "rpm", default=0),
                "tokens_min": _first(u, "tokens_min", "tokens_per_minute", "tpm", default=0),
                "killed": a.id in policy.kill_switch,
                "usage": u,
            })
        try:
            pending = len(self.approvals.list("pending"))
        except Exception:  # noqa: BLE001
            pending = 0
        try:
            feed = self.feed.info() if self.feed else {"count": 0, "hash": None, "last_error": "feed not loaded"}
        except Exception as exc:  # noqa: BLE001
            feed = {"count": 0, "hash": None, "last_error": str(exc)}
        try:
            recent = self.audit.tail(30)
        except Exception:  # noqa: BLE001
            recent = []
        lat = m.get("latency") if isinstance(m.get("latency"), dict) else m
        breaker_open, open_until = self.judge_breaker(policy, js)
        return {
            "policy": {
                "version": pver,
                "name": policy.version,
                "hash": phash,
                "profile": policy.profile,
                "mode": policy.mode,
                "fail_mode": policy.fail_mode,
                "last_reload": {
                    "status": last.get("status", "applied"),
                    "error": last.get("error"),
                    "ts": last.get("ts", self.store.loaded_at),
                    "applied_ts": last_applied.get("ts", self.store.loaded_at),
                    "changed": last.get("changed", []),
                },
                "controls": controls,
                "flow_enabled": policy.flow.enabled,
                "kill_switch": list(policy.kill_switch),
                "detectors_disabled": disabled,
                "overrides": dict(self.overrides),
            },
            "posture": self.posture(policy),
            "coverage": self.coverage(policy),
            "upstream_calls": self.upstream_calls,
            "server_time": time.time(),
            "counts": dict(self.counts),
            "agents": [a.id for a in policy.agents],
            "latency": {
                "p50_ms": _first(lat, "p50_ms", "p50", default=0.0),
                "p99_ms": _first(lat, "p99_ms", "p99", default=0.0),
                "p50_judge_ms": _first(lat, "p50_judge_ms", "judge_p50_ms", "p50_judge", default=0.0),
                "p99_judge_ms": _first(lat, "p99_judge_ms", "judge_p99_ms", "p99_judge", default=0.0),
                "judge_rate": _first(m, "judge_rate", default=0.0),
            },
            "metrics": m,
            "judge": {
                "breaker": js.get("breaker", "closed"),
                "backend": policy.semantic.backend,
                "model": policy.semantic.model,
                "enabled": policy.semantic.enabled,
                "spend_today_usd": js.get("spend_today_usd", 0.0),
                "breaker_open": breaker_open,
                "open_until": open_until,
                "calls": int(js.get("calls") or 0),
                "failures": int(js.get("failures") or 0),
                "state": js,
            },
            "budgets": budgets,
            "approvals_pending": pending,
            "feed": {"count": feed.get("count", 0), "hash": feed.get("hash"),
                     "last_error": feed.get("last_error"), "version": feed.get("version")},
            "recent": recent,
        }


def load_tests_report(paths: list[Path]) -> dict:
    """reports/last-run.json (written by the test reporter) normalised for the dashboard."""
    data: dict[str, Any] = {}
    for p in paths:
        try:
            loaded = json.loads(Path(p).read_text())
        except (OSError, ValueError):
            continue
        if isinstance(loaded, dict):
            data = {**loaded, **data} if data else dict(loaded)
            data.setdefault("source", str(p))
    if not data:
        return {"status": "not_run", "summary": {"passed": 0, "failed": 0, "skipped": 0, "total": 0,
                                                 "duration_s": 0.0}, "groups": []}
    raw = data.get("summary") if isinstance(data.get("summary"), dict) else data

    def num(k, cast=int):
        try:
            return cast(raw.get(k, 0) or 0)
        except (TypeError, ValueError):
            return cast(0)

    summary = {"passed": num("passed"), "failed": num("failed"), "skipped": num("skipped"),
               "total": num("total"), "duration_s": num("duration_s", float)}
    if not summary["total"]:
        summary["total"] = summary["passed"] + summary["failed"] + summary["skipped"]
    groups = data.get("groups")
    if isinstance(groups, dict):
        groups = [{"name": k, **(v if isinstance(v, dict) else {})} for k, v in groups.items()]
    if not isinstance(groups, list):
        groups = []
    norm = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        norm.append({**g, "name": str(g.get("name", "?")), "passed": int(g.get("passed", 0) or 0),
                     "failed": int(g.get("failed", 0) or 0)})
    return {**data, "summary": summary, "groups": norm}


def _display_args(args: dict) -> dict:
    """What the human approver sees: amounts and short values in clear, long identifiers masked."""
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 12 and not re.search(r"\s", v):
            out[k] = mask(v, keep=4)
        elif isinstance(v, str) and len(v) > 120:
            out[k] = v[:117] + "..."
        else:
            out[k] = v
    return out


def _first(d: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


__all__ = ["Gateway", "GatewayResult", "status_for", "owasp_for", "mask", "asyncio"]
