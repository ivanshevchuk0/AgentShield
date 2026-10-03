"""Sample policies under examples/policies: each file is a valid Policy, and the postures differ."""

from pathlib import Path

import pytest
import yaml

from app.policy import parse_policy

DIR = Path(__file__).resolve().parents[1] / "examples" / "policies"
FILES = ("dev.yaml", "standard.yaml", "strict.yaml", "bank-production.yaml")
PII_ENTITIES = {"EMAIL", "PHONE", "PESEL", "NIP", "IBAN", "CREDIT_CARD"}
CONTROLS = ("prompt_injection", "pii", "secrets", "signatures", "canary", "loop")


def load(name: str):
    return parse_policy((DIR / name).read_text(encoding="utf-8"))


def test_directory_is_the_four_samples():
    assert sorted(p.name for p in DIR.glob("*.yaml")) == sorted(FILES)


@pytest.mark.parametrize("name", FILES)
def test_every_example_parses(name):
    policy = load(name)
    assert policy.version
    assert policy.models
    assert policy.agents
    assert policy.require_auth is True
    assert policy.block_response == "error"
    assert policy.flow.enabled is True
    assert policy.flow.rules.secret_to_egress == "block"
    assert policy.flow.rules.untrusted_value_as_target == "block"
    assert policy.semantic.usd_per_day > 0
    assert policy.kill_switch == []
    assert policy.controls.signatures.feed_file == "feeds/signatures.yaml"
    assert "WRDN-CANARY-7F3A" in policy.controls.canary.tokens
    assert set(policy.controls.pii.entities) == PII_ENTITIES
    for control in CONTROLS:
        assert policy.controls.active(control) is not None, control
    inj = policy.controls.prompt_injection
    assert inj.review_threshold < inj.block_threshold
    ids = [agent.id for agent in policy.agents]
    assert len(ids) == len(set(ids))
    assert policy.agent_by_id("judge-sandbox").allowed_tools == []
    assert "flow" not in policy.controls.model_dump()


@pytest.mark.parametrize("name", FILES)
def test_written_body_is_what_parse_enforces(name):
    """The profile overlay is empty, so the enforced policy is the text a judge reads."""
    raw = yaml.safe_load((DIR / name).read_text(encoding="utf-8"))
    policy = load(name)
    assert policy.profile == raw["profile"]
    assert policy.mode == raw["mode"]
    assert policy.fail_mode == raw["fail_mode"]
    assert policy.controls.pii.action == raw["controls"]["pii"]["action"]
    assert policy.semantic.backend == raw["semantic"]["backend"]
    assert policy.semantic.trigger == raw["semantic"]["trigger"]
    assert policy.flow.rules.untrusted_before_irreversible == raw["flow"]["rules"]["untrusted_before_irreversible"]
    assert raw["profiles"][policy.profile] == {}


def test_dev_is_monitor_mode():
    dev = load("dev.yaml")
    standard = load("standard.yaml")
    assert dev.profile == "dev"
    assert dev.mode == "monitor"
    assert dev.fail_mode == "open"
    assert standard.mode == "enforce"
    assert standard.fail_mode == "closed"
    # Actions stay at the standard decisions; monitor mode is what downgrades them.
    assert dev.controls.pii.action == "redact"
    assert dev.controls.secrets.action == "block"
    assert dev.semantic.backend == "heuristic"
    assert dev.semantic.trigger == "suspicious"
    assert dev.budgets["default"].usd_per_day > standard.budgets["default"].usd_per_day
    assert dev.budgets["default"].warn_at > standard.budgets["default"].warn_at
    assert dev.max_input_chars > standard.max_input_chars
    assert dev.approval_ttl_s > standard.approval_ttl_s
    assert dev.controls.loop.max_identical > standard.controls.loop.max_identical
    ops = dev.agent_by_id("bank-ops-agent")
    assert ops.allowed_models is None
    assert dev.model_allowed(ops, "ollama/qwen2.5:3b")
    assert dev.budget_for(dev.agent_by_id("budget-demo")).usd_per_day == pytest.approx(0.25)


def test_strict_blocks_pii_and_tightens_thresholds():
    strict = load("strict.yaml")
    standard = load("standard.yaml")
    assert strict.profile == "strict"
    assert strict.mode == "enforce"
    assert strict.fail_mode == "closed"
    assert strict.controls.pii.action == "block"
    assert standard.controls.pii.action == "redact"
    assert strict.controls.prompt_injection.block_threshold == pytest.approx(0.60)
    assert strict.controls.prompt_injection.review_threshold == pytest.approx(0.15)
    assert strict.controls.prompt_injection.block_threshold < standard.controls.prompt_injection.block_threshold
    assert strict.semantic.trigger == "always"
    assert standard.semantic.trigger == "suspicious"
    assert strict.semantic.threshold < standard.semantic.threshold
    assert strict.semantic.scan_output is True
    assert standard.semantic.scan_output is False
    assert strict.semantic.backend == "heuristic"
    assert strict.flow.rules.untrusted_before_irreversible == "block"
    assert standard.flow.rules.untrusted_before_irreversible == "approval"
    assert strict.tools["transfer_funds"].max_values["amount"] == pytest.approx(1000)
    assert standard.tools["transfer_funds"].max_values["amount"] == pytest.approx(10000)
    strict_ops = strict.budget_for(strict.agent_by_id("bank-ops-agent"))
    standard_ops = standard.budget_for(standard.agent_by_id("bank-ops-agent"))
    assert strict_ops.usd_per_day < standard_ops.usd_per_day
    assert strict.budgets["default"].warn_at < standard.budgets["default"].warn_at
    assert strict.max_input_chars < standard.max_input_chars
    assert strict.controls.loop.max_requests_per_session < standard.controls.loop.max_requests_per_session
    assert not strict.model_allowed(strict.agent_by_id("bank-ops-agent"), "ollama/qwen2.5:3b")


def test_standard_budget_inheritance_matches_the_shipped_shape():
    policy = load("standard.yaml")
    default = policy.budgets["default"]
    assert default.usd_per_day == pytest.approx(2.00)
    assert default.tokens_per_minute == 40000
    assert default.requests_per_minute == 120
    assert default.max_tokens_per_request == 4000
    assert default.warn_at == pytest.approx(0.80)
    ops = policy.budget_for(policy.agent_by_id("bank-ops-agent"))
    assert ops.usd_per_day == pytest.approx(0.50)
    assert ops.max_tokens_per_request == 2000
    assert ops.tokens_per_minute == default.tokens_per_minute
    assert ops.requests_per_minute == default.requests_per_minute
    assert ops.compute_seconds_per_day == default.compute_seconds_per_day
    assert ops.warn_at == pytest.approx(default.warn_at)
    research = policy.budget_for(policy.agent_by_id("research-agent"))
    assert research.model_dump() == default.model_dump()
    demo = policy.budget_for(policy.agent_by_id("budget-demo"))
    assert demo.usd_per_day == 0
    assert demo.tokens_per_minute == default.tokens_per_minute
    ops_agent = policy.agent_by_id("bank-ops-agent")
    assert policy.model_allowed(ops_agent, "mock/vulnerable-llm")
    assert not policy.model_allowed(ops_agent, "ollama/qwen2.5:3b")
    assert policy.model_allowed(policy.agent_by_id("judge-sandbox"), "ollama/qwen2.5:3b")
    assert policy.agent_by_key("wk_bank_ops_demo").id == "bank-ops-agent"
    assert set(ops_agent.allowed_tools) == {
        "lookup_customer", "read_document", "send_email", "transfer_funds",
    }


def test_bank_production_splits_duties_and_budgets():
    bank = load("bank-production.yaml")
    standard = load("standard.yaml")
    assert bank.profile == "bank-production"
    assert bank.mode == "enforce"
    assert bank.controls.pii.action == "block"
    assert bank.semantic.trigger == "suspicious"
    assert bank.semantic.scan_output is False
    assert bank.semantic.threshold < standard.semantic.threshold
    assert bank.semantic.backend == "openrouter"
    assert "BANK-CANARY-2026" in bank.controls.canary.tokens
    assert "BANK-CANARY-2026" not in standard.controls.canary.tokens
    ops = bank.agent_by_id("bank-ops-agent")
    pay = bank.agent_by_id("payments-agent")
    research = bank.agent_by_id("research-agent")
    assert pay is not None
    assert standard.agent_by_id("payments-agent") is None
    assert "transfer_funds" not in ops.allowed_tools
    assert pay.allowed_tools == ["transfer_funds"]
    assert "send_email" not in pay.allowed_tools
    assert research.allowed_tools == ["read_document"]
    assert bank.tools["transfer_funds"].irreversible is True
    assert bank.tools["transfer_funds"].max_values["amount"] == pytest.approx(2500)
    assert "subject" in bank.tools["send_email"].deny_arg_patterns
    assert "reference" in bank.tools["transfer_funds"].deny_arg_patterns
    assert bank.tools["send_email"].arg_patterns["to"] == r"^[\w.+-]+@bank\.example$"
    pay_budget = bank.budget_for(pay)
    assert pay_budget.usd_per_day == pytest.approx(0.10)
    assert pay_budget.max_tokens_per_request == 800
    assert pay_budget.requests_per_minute == 6
    assert pay_budget.tokens_per_minute == bank.budgets["default"].tokens_per_minute
    assert pay_budget.warn_at == pytest.approx(bank.budgets["default"].warn_at)
    assert bank.budgets["default"].warn_at == pytest.approx(0.70)
    assert bank.budget_for(bank.agent_by_id("budget-demo")).usd_per_day == 0
    assert all(agent.allowed_models is not None for agent in bank.agents)
    assert bank.agent_by_key("wk_payments_demo").id == "payments-agent"


@pytest.mark.parametrize("name", ("standard.yaml", "strict.yaml", "bank-production.yaml"))
def test_zero_budget_demo_agent_outside_dev(name):
    policy = load(name)
    assert policy.budget_for(policy.agent_by_id("budget-demo")).usd_per_day == 0
