"""Policy engine: validation, fail-safe hot reload, profiles, disabled-by-omission controls."""

import time
from pathlib import Path

import pytest
import yaml

from app.policy import PolicyStore, parse_policy

POLICY = Path(__file__).resolve().parents[1] / "backend" / "policy.yaml"


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY.read_text(encoding="utf-8"), encoding="utf-8")
    events = []
    s = PolicyStore(path, on_event=events.append)
    s.events = events
    return s


def edit(store, mutate):
    raw = yaml.safe_load(store.text())
    mutate(raw)
    return store.apply_text(yaml.safe_dump(raw, sort_keys=False))


def test_shipped_policy_is_valid():
    policy = parse_policy(POLICY.read_text(encoding="utf-8"))
    assert policy.controls.active("pii") is not None
    assert policy.flow.enabled


@pytest.mark.parametrize("text", ["", "   \n", "version: x\n"])
def test_empty_or_truncated_policy_rejected(text):
    with pytest.raises(ValueError):
        parse_policy(text)


def test_invalid_edit_keeps_last_good(store):
    _, good_hash, good_version = store.snapshot()
    entry = store.apply_text("controls: [broken\n" * 10)
    assert entry["status"] == "rejected"
    policy, h, v = store.snapshot()
    assert (h, v) == (good_hash, good_version)
    assert policy.controls.active("pii") is not None


def test_inverted_thresholds_rejected(store):
    def mutate(raw):
        raw["controls"]["prompt_injection"]["review_threshold"] = 0.95

    entry = edit(store, mutate)
    assert entry["status"] == "rejected"
    assert "review_threshold" in entry["error"]


def test_duplicate_yaml_keys_rejected(store):
    text = store.text().replace("mode: enforce", "mode: enforce\nmode: monitor", 1)
    assert store.apply_text(text)["status"] == "rejected"


def test_duplicate_api_key_rejected(store):
    def mutate(raw):
        raw["agents"][1]["api_key"] = raw["agents"][0]["api_key"]

    assert edit(store, mutate)["status"] == "rejected"


def test_unknown_tool_or_model_rejected(store):
    assert edit(store, lambda r: r["agents"][0]["allowed_tools"].append("rm_rf"))["status"] == "rejected"
    assert edit(store, lambda r: r["agents"][0]["allowed_models"].append("gpt-9"))["status"] == "rejected"


def test_removed_control_is_disabled_not_defaulted(store):
    entry = edit(store, lambda r: r["controls"].pop("pii"))
    assert entry["status"] == "applied"
    assert "controls.pii.enabled" in entry["changed"] or any(c.startswith("controls.pii") for c in entry["changed"])
    policy, _, _ = store.snapshot()
    assert policy.controls.active("pii") is None


def test_flow_survives_removing_all_detectors(store):
    edit(store, lambda r: r.update(controls={}))
    policy, _, _ = store.snapshot()
    assert all(policy.controls.active(n) is None for n in ("pii", "secrets", "prompt_injection"))
    assert policy.flow.enabled


def test_agent_without_tools_gets_none():
    policy = parse_policy(POLICY.read_text(encoding="utf-8"))
    assert policy.agent_by_key("wk_judge").allowed_tools == []


def test_agent_lookup_and_budget_merge():
    policy = parse_policy(POLICY.read_text(encoding="utf-8"))
    agent = policy.agent_by_key("wk_bank_ops_demo")
    assert agent.id == "bank-ops-agent"
    assert policy.agent_by_key("wrong") is None
    budget = policy.budget_for(agent)
    assert budget.usd_per_day == 0.50
    assert budget.tokens_per_minute == 40000  # inherited from default


def test_model_allow_list():
    policy = parse_policy(POLICY.read_text(encoding="utf-8"))
    ops = policy.agent_by_id("bank-ops-agent")
    judge = policy.agent_by_id("judge-sandbox")
    assert policy.model_allowed(ops, "mock/vulnerable-llm")
    assert not policy.model_allowed(ops, "ollama/qwen2.5:3b")
    assert policy.model_allowed(judge, "ollama/qwen2.5:3b")
    assert not policy.model_allowed(judge, "gpt-4o")


def test_profile_switch_strict_blocks_pii(store):
    entry = store.set_profile("strict")
    assert entry["status"] == "applied"
    policy, _, _ = store.snapshot()
    assert policy.controls.active("pii").action == "block"
    assert store.set_profile("nope")["status"] == "rejected"


def test_poll_picks_up_external_edit(store):
    _, h0, v0 = store.snapshot()
    time.sleep(0.01)
    store.path.write_text(store.text().replace("mode: enforce", "mode: monitor", 1), encoding="utf-8")
    entry = None
    deadline = time.monotonic() + 2
    while entry is None and time.monotonic() < deadline:
        entry = store.poll(debounce_s=0.05)
        time.sleep(0.02)
    assert entry and entry["status"] == "applied"
    policy, h1, v1 = store.snapshot()
    assert policy.mode == "monitor" and v1 == v0 + 1 and h1 != h0


def test_deleted_file_keeps_last_good(store):
    _, h0, _ = store.snapshot()
    store.path.unlink()
    entry = store.poll()
    assert entry and entry["status"] == "rejected"
    assert store.snapshot()[1] == h0
