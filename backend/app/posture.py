"""Policy posture, not a security guarantee; OWASP coverage is scoped to runtime controls."""

from __future__ import annotations

from .policy import Policy

WEIGHTS = {
    "prompt_injection": 18, "pii": 14, "secrets": 14, "signatures": 8,
    "canary": 4, "loop": 4, "flow": 14, "semantic": 8,
    "auth": 6, "budgets": 6, "approvals": 4,
}
DETECTORS = {"prompt_injection", "pii", "secrets", "signatures", "canary", "loop", "semantic"}
TAGS = {
    "prompt_injection": ["LLM01"], "pii": ["LLM02"], "secrets": ["LLM02"],
    "signatures": ["LLM03", "LLM05"], "canary": ["LLM07"], "loop": ["LLM10"],
    "flow": ["LLM06"], "semantic": ["LLM01"], "auth": ["LLM06"],
    "budgets": ["LLM10"], "approvals": ["LLM06"],
}
FORMULA = (
    "Weighted sum (100 max): "
    + ", ".join(f"{name} {weight}" for name, weight in WEIGHTS.items())
    + "; enabled block/redact/approval = 100%, monitor = 30%, disabled = 0%. "
    "Flow averages its three rule factors. Global monitor multiplies detector contributions "
    "(including loop and semantic) by 0.3. Budgets require a daily USD limit for every agent; "
    "approvals require an irreversible tool. Penalties: semantic fail-open -2, breaker open -3, "
    "bad audit chain -10, failing tests -5. Clamp to 0–100, round to nearest integer "
    "(halves up). Grades: A >=90, B >=80, C >=70, D >=60, F <60."
)


def _factor(action: str) -> float:
    return 0.3 if action == "monitor" else 1.0


def posture(
    policy: Policy,
    judge_state: dict | None = None,
    chain_ok: bool | None = None,
    test_summary: dict | None = None,
) -> dict:
    """Report configured protection; omitted health inputs incur no assumed penalty.

    test_summary accepts pytest-style ``failed``/``errors`` counts or ``ok=False``.
    No network calls, environment-key checks, or policy mutations are performed.
    """
    controls = []
    gaps = []
    for name, weight in WEIGHTS.items():
        factor = 1.0
        if name in type(policy.controls).model_fields:
            cfg = getattr(policy.controls, name)
            enabled = cfg is not None and cfg.enabled
            action = cfg.action if cfg is not None else "disabled"
            # Empty entity/token lists perform no detection.
            if name == "pii" and cfg is not None:
                enabled = enabled and bool(cfg.entities)
            if name == "canary" and cfg is not None:
                enabled = enabled and any(cfg.tokens)
            factor = _factor(action)
        elif name == "semantic":
            enabled, action = policy.semantic.enabled, policy.semantic.action
            factor = _factor(action)
        elif name == "flow":
            enabled = policy.flow.enabled
            rules = policy.flow.rules.model_dump()
            action = ", ".join(f"{rule}={value}" for rule, value in rules.items())
            factor = sum(_factor(value) for value in rules.values()) / len(rules)
        elif name == "auth":
            enabled, action = policy.require_auth, "block"
        elif name == "budgets":
            enabled = bool(policy.agents) and all(
                policy.budget_for(agent).usd_per_day is not None for agent in policy.agents
            )
            action = "block"
        else:  # Approval enforcement is intrinsic to ToolCfg.irreversible.
            enabled = any(tool.irreversible for tool in policy.tools.values())
            action = "require_approval"
        contribution = weight * factor if enabled else 0.0
        if policy.mode == "monitor" and name in DETECTORS:
            contribution *= 0.3
        controls.append({
            "id": name, "enabled": enabled, "action": action, "weight": weight,
            "contribution": round(contribution, 4), "owasp": TAGS[name],
        })
        if not enabled:
            gaps.append(f"{name}: disabled, missing, or no applicable configuration")
        elif factor < 1:
            gaps.append(f"{name}: monitor-only rules reduce protection")
    if policy.mode == "monitor":
        gaps.append("Global monitor mode: detector contributions multiplied by 0.3")
    penalty = 0
    if policy.semantic.enabled and policy.fail_mode == "open":
        penalty += 2
        gaps.append("Semantic judge fail-open: -2")
    if (judge_state or {}).get("breaker") == "open":
        penalty += 3
        gaps.append("Semantic judge breaker open: -3")
    if chain_ok is False:
        penalty += 10
        gaps.append("Audit chain verification failed: -10")
    summary = test_summary or {}
    if summary.get("failed", 0) or summary.get("errors", 0) or summary.get("ok") is False:
        penalty += 5
        gaps.append("Failing tests: -5")
    score = int(max(0, min(100, sum(c["contribution"] for c in controls) - penalty)) + 0.5)
    grade = next((grade for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D"))
                  if score >= threshold), "F")
    return {"score": score, "grade": grade, "formula": FORMULA, "gaps": gaps, "controls": controls}


# A configured runtime control is not training-data integrity or full supply-chain security.
OWASP = (
    ("LLM01", "Prompt Injection", ("prompt_injection", "semantic"), False),
    ("LLM02", "Sensitive Information Disclosure", ("pii", "secrets"), False),
    ("LLM03", "Supply Chain", ("signatures",), True),
    ("LLM04", "Data and Model Poisoning", (), True),
    ("LLM05", "Improper Output Handling", ("signatures",), True),
    ("LLM06", "Excessive Agency", ("flow", "auth", "approvals"), False),
    ("LLM07", "System Prompt Leakage", ("canary",), True),
    ("LLM08", "Vector and Embedding Weaknesses", (), True),
    ("LLM09", "Misinformation", (), True),
    ("LLM10", "Unbounded Consumption", ("loop", "budgets"), False),
)


def coverage(policy: Policy) -> list[dict]:
    """OWASP LLM 2025 runtime mapping; covered means mapped controls fully enforce.

    Supply chain, output handling, and canary leakage detection remain partial even
    at full weight: regex feeds and canaries cannot cover these entire categories.
    Unimplemented training, retrieval, and factuality controls are explicit gaps.
    """
    controls = {c["id"]: c for c in posture(policy)["controls"]}
    result = []
    for oid, title, names, partial_only in OWASP:
        contributions = [controls[name]["contribution"] for name in names]
        if not any(contributions):
            status = "gap"
        elif not partial_only and all(controls[name]["contribution"] == controls[name]["weight"]
                                      for name in names):
            status = "covered"
        else:
            status = "partial"
        result.append({"framework": "OWASP LLM 2025", "id": oid, "title": title,
                       "controls": list(names), "status": status})
    return result
