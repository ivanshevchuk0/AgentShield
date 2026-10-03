from pathlib import Path

import pytest

from app.policy import Budget, parse_policy
from app.posture import WEIGHTS, coverage, posture


@pytest.fixture
def policy():
    return parse_policy((Path(__file__).resolve().parents[1] / "backend/policy.yaml").read_text())


def control(result, name):
    return next(c for c in result["controls"] if c["id"] == name)


def test_full_policy_schema_and_weights(policy):
    result = posture(policy)
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["gaps"] == []
    assert sum(WEIGHTS.values()) == 100
    assert {c["id"]: c["weight"] for c in result["controls"]} == WEIGHTS
    for c in result["controls"]:
        assert set(c) == {"id", "enabled", "action", "weight", "contribution", "owasp"}
        assert c["enabled"] and c["contribution"] == c["weight"]
        assert c["owasp"]
        assert f"{c['id']} {c['weight']}" in result["formula"]


@pytest.mark.parametrize("name", ["prompt_injection", "pii", "secrets", "signatures", "canary", "loop", "semantic"])
@pytest.mark.parametrize("action,factor", [("block", 1), ("redact", 1), ("monitor", 0.3)])
def test_detector_actions(policy, name, action, factor):
    if name == "semantic":
        policy.semantic.action = action
    else:
        getattr(policy.controls, name).action = action
    result = posture(policy)
    assert control(result, name)["contribution"] == pytest.approx(WEIGHTS[name] * factor)
    assert result["score"] == int(100 - WEIGHTS[name] * (1 - factor) + 0.5)


@pytest.mark.parametrize("name", ["prompt_injection", "pii", "secrets", "signatures", "canary", "loop"])
@pytest.mark.parametrize("missing", [False, True])
def test_missing_or_disabled_detectors(policy, name, missing):
    if missing:
        setattr(policy.controls, name, None)
    else:
        getattr(policy.controls, name).enabled = False
    result = posture(policy)
    assert result["score"] == 100 - WEIGHTS[name]
    assert control(result, name)["enabled"] is False
    assert control(result, name)["contribution"] == 0
    assert any(name in gap for gap in result["gaps"])


@pytest.mark.parametrize("name", ["pii", "canary"])
def test_empty_detector_payloads(policy, name):
    cfg = getattr(policy.controls, name)
    setattr(cfg, "entities" if name == "pii" else "tokens", [])
    assert control(posture(policy), name)["contribution"] == 0


@pytest.mark.parametrize("name", ["flow", "semantic", "auth"])
def test_other_disabled_controls(policy, name):
    if name == "auth":
        policy.require_auth = False
    else:
        getattr(policy, name).enabled = False
    assert posture(policy)["score"] == 100 - WEIGHTS[name]


def test_global_monitor_only_multiplies_detector_part(policy):
    policy.mode = "monitor"
    result = posture(policy)
    assert result["score"] == 51  # 70 * .3 + 30
    for name in ("flow", "auth", "budgets", "approvals"):
        assert control(result, name)["contribution"] == WEIGHTS[name]
    policy.controls.prompt_injection.action = "monitor"
    assert control(posture(policy), "prompt_injection")["contribution"] == pytest.approx(18 * .3 * .3)


@pytest.mark.parametrize("rule", ["secret_to_egress", "untrusted_value_as_target", "untrusted_before_irreversible"])
def test_flow_rule_monitor_is_proportional(policy, rule):
    setattr(policy.flow.rules, rule, "monitor")
    assert control(posture(policy), "flow")["contribution"] == pytest.approx(14 * 2.3 / 3, abs=0.0001)
    policy.flow.rules.secret_to_egress = "monitor"
    policy.flow.rules.untrusted_value_as_target = "monitor"
    policy.flow.rules.untrusted_before_irreversible = "monitor"
    assert control(posture(policy), "flow")["contribution"] == 4.2
    policy.flow.enabled = False
    assert control(posture(policy), "flow")["contribution"] == 0


def test_budget_defaults_overrides_zero_and_no_agents(policy):
    assert control(posture(policy), "budgets")["contribution"] == 6  # includes zero-budget demo
    policy.budgets["default"].usd_per_day = None
    assert control(posture(policy), "budgets")["contribution"] == 0  # research agent inherits None
    for agent in policy.agents:
        agent.budget = Budget(usd_per_day=0)
    assert control(posture(policy), "budgets")["contribution"] == 6
    policy.agents = []
    assert control(posture(policy), "budgets")["contribution"] == 0


def test_approvals_require_an_irreversible_tool(policy):
    policy.tools["transfer_funds"].irreversible = False
    assert control(posture(policy), "approvals")["contribution"] == 0
    policy.tools["send_email"].irreversible = True
    assert control(posture(policy), "approvals")["contribution"] == 4


def test_fail_open_penalty_only_when_semantic_enabled(policy):
    policy.fail_mode = "open"
    assert posture(policy)["score"] == 98
    policy.semantic.enabled = False
    assert posture(policy)["score"] == 92


@pytest.mark.parametrize("state,expected", [(None, 100), ({}, 100), ({"breaker": "closed"}, 100),
                                           ({"breaker": "half_open"}, 100), ({"breaker": "open"}, 97)])
def test_breaker_penalty(policy, state, expected):
    assert posture(policy, judge_state=state)["score"] == expected


@pytest.mark.parametrize("chain,expected", [(None, 100), (True, 100), (False, 90)])
def test_chain_penalty(policy, chain, expected):
    assert posture(policy, chain_ok=chain)["score"] == expected


@pytest.mark.parametrize("summary,expected", [(None, 100), ({}, 100), ({"failed": 0, "errors": 0}, 100),
    ({"failed": 1}, 95), ({"errors": 1}, 95), ({"ok": False}, 95),
    ({"failed": 4, "errors": 3, "ok": False}, 95), ({"ok": True}, 100)])
def test_test_penalty_once(policy, summary, expected):
    assert posture(policy, test_summary=summary)["score"] == expected


def test_penalties_add_and_score_is_clamped(policy):
    policy.fail_mode = "open"
    assert posture(policy, {"breaker": "open"}, False, {"failed": 1})["score"] == 80
    policy.controls = type(policy.controls)()
    policy.semantic.enabled = False
    policy.flow.enabled = False
    policy.require_auth = False
    policy.budgets = {}
    policy.agents = []
    policy.tools = {}
    result = posture(policy, {"breaker": "open"}, False, {"failed": 1})
    assert result["score"] == 0
    assert result["grade"] == "F"


@pytest.mark.parametrize("disabled,score,grade", [
    ([], 100, "A"), (["signatures"], 92, "A"), (["pii"], 86, "B"),
    (["prompt_injection", "signatures"], 74, "C"),
    (["prompt_injection", "pii"], 68, "D"),
    (["prompt_injection", "pii", "secrets"], 54, "F"),
])
def test_grades(policy, disabled, score, grade):
    for name in disabled:
        getattr(policy.controls, name).enabled = False
    result = posture(policy)
    assert (result["score"], result["grade"]) == (score, grade)


def test_coverage_full_policy_is_honest_and_complete(policy):
    rows = coverage(policy)
    assert [row["id"] for row in rows] == [f"LLM{i:02d}" for i in range(1, 11)]
    expected = ["covered", "covered", "partial", "gap", "partial", "covered", "partial", "gap", "gap", "covered"]
    assert [row["status"] for row in rows] == expected
    for row in rows:
        assert set(row) == {"framework", "id", "title", "controls", "status"}
        assert row["framework"] == "OWASP LLM 2025"
        assert row["title"]
        assert all(name in WEIGHTS for name in row["controls"])


def test_coverage_partial_monitor_and_gaps(policy):
    policy.controls.pii.enabled = False
    assert coverage(policy)[1]["status"] == "partial"
    policy.controls.secrets.enabled = False
    assert coverage(policy)[1]["status"] == "gap"
    policy.controls.signatures.enabled = False
    assert coverage(policy)[2]["status"] == coverage(policy)[4]["status"] == "gap"
    policy.controls.canary.enabled = False
    assert coverage(policy)[6]["status"] == "gap"
    policy.mode = "monitor"
    assert coverage(policy)[0]["status"] == "partial"
    assert coverage(policy)[9]["status"] == "partial"
    policy.flow.enabled = False
    policy.require_auth = False
    policy.tools = {}
    assert coverage(policy)[5]["status"] == "gap"


def test_functions_are_pure_and_json_serializable(policy):
    import json
    before = policy.model_dump()
    judge = {"breaker": "open"}
    summary = {"failed": 2}
    json.dumps(posture(policy, judge, False, summary))
    json.dumps(coverage(policy))
    assert policy.model_dump() == before
    assert judge == {"breaker": "open"} and summary == {"failed": 2}
