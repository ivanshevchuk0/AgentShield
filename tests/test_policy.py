"""Policy engine: validation, fail-safe hot reload, profiles, disabled-by-omission controls."""

import threading
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


@pytest.mark.parametrize("pattern", ["[", "(a+)+$", "(a|aa)+$", r"(a)\1",
                                     "a{99999999999999999999}", "(" * 500 + "a" + ")" * 500])
def test_unsafe_tool_regex_rejected_keeps_last_good(store, pattern):
    before = store.snapshot()[1:]
    text = store.text()
    entry = edit(store, lambda r: r["tools"]["send_email"]["arg_patterns"].update(to=pattern))
    assert entry["status"] == "rejected"
    assert store.snapshot()[1:] == before
    assert store.text() == text


def test_reload_cannot_pin_stale_policy_over_new_apply(store, monkeypatch):
    import app.policy as module

    entered, release, applied = threading.Event(), threading.Event(), threading.Event()
    original = module.parse_policy
    errors = []

    def paused(text):
        if threading.current_thread().name == "old-reload":
            entered.set()
            assert release.wait(3)
        return original(text)

    def reload_old():
        try:
            store.reload(force=True)
        except Exception as exc:
            errors.append(exc)

    def apply_new():
        try:
            store.apply_text(store.text().replace("mode: enforce", "mode: monitor", 1))
            applied.set()
        except Exception as exc:
            errors.append(exc)

    monkeypatch.setattr(module, "parse_policy", paused)
    old = threading.Thread(target=reload_old, name="old-reload")
    new = threading.Thread(target=apply_new)
    old.start()
    try:
        assert entered.wait(3)
        new.start()
        assert not applied.wait(0.1)  # parsing and installation are one serialized operation
    finally:
        release.set()
        old.join(3)
        if new.ident is not None:
            new.join(3)
    assert not errors
    assert not old.is_alive() and not new.is_alive()
    assert store.snapshot()[0].mode == "monitor"
    assert parse_policy(store.text()).mode == "monitor"
    assert store.poll(debounce_s=0) is None


def test_apply_installs_validated_bytes_without_rereading(store, monkeypatch):
    import app.policy as module

    original = module.os.replace
    intended = store.text().replace("mode: enforce", "mode: monitor", 1)

    def replace_then_external_edit(src, dst):
        original(src, dst)
        store.path.write_text(store.text().replace("mode: monitor", "mode: enforce", 1), encoding="utf-8")

    monkeypatch.setattr(module.os, "replace", replace_then_external_edit)
    assert store.apply_text(intended)["status"] == "applied"
    assert store.snapshot()[0].mode == "monitor"
    assert store.poll(debounce_s=0) is None
    assert store.poll(debounce_s=0)["status"] == "applied"
    assert store.snapshot()[0].mode == "enforce"


@pytest.mark.parametrize("env", ["USER", "HOME", "PATH", "agent_key", "BAD KEY"])
def test_agent_key_env_requires_secret_variable(store, monkeypatch, env):
    monkeypatch.setenv(env, "predictable-value")
    before = store.snapshot()[1:]
    assert edit(store, lambda r: r["agents"][0].update(api_key_env=env))["status"] == "rejected"
    assert store.snapshot()[1:] == before


def test_agent_keys_have_demo_compatible_minimum_and_env_refs_are_unique(store, monkeypatch):
    assert edit(store, lambda r: r["agents"][0].update(api_key="a"))["status"] == "rejected"
    monkeypatch.delenv("BANK_AGENT_KEY", raising=False)

    def duplicate_env(raw):
        raw["agents"][0]["api_key_env"] = "BANK_AGENT_KEY"
        raw["agents"][1]["api_key_env"] = "BANK_AGENT_KEY"

    assert edit(store, duplicate_env)["status"] == "rejected"
    monkeypatch.setenv("BANK_AGENT_KEY", "short")
    assert edit(store, lambda r: r["agents"][0].update(api_key_env="BANK_AGENT_KEY"))["status"] == "rejected"
    assert store.snapshot()[0].agent_by_key("wk_judge").id == "judge-sandbox"


def test_unicode_keys_and_requests_do_not_break_auth(store, monkeypatch):
    assert edit(store, lambda r: r["agents"].insert(0, {"id": "unicode", "api_key": "café-key-xxxxxxxx"}))["status"] == "applied"
    policy = store.snapshot()[0]
    assert policy.agent_by_key("wk_bank_ops_demo").id == "bank-ops-agent"
    assert policy.agent_by_key("café-key-xxxxxxxx").id == "unicode"
    assert policy.agent_by_key("héllo-invalid") is None
    assert policy.agent_by_key("\ud800" * 8) is None
    monkeypatch.setenv("BANK_AGENT_KEY", "\udcff" * 8)
    policy.agents[0].api_key_env = "BANK_AGENT_KEY"
    assert policy.agent_by_key("wk_bank_ops_demo").id == "bank-ops-agent"
    policy.agents[0].api_key_env = None
    import hmac

    calls = []
    original = hmac.compare_digest

    def compared(a, b):
        calls.append((len(a), len(b)))
        return original(a, b)

    monkeypatch.setattr(hmac, "compare_digest", compared)
    assert policy.agent_by_key("wk_judge").id == "judge-sandbox"
    assert calls == [(32, 32)] * len(policy.agents)


def test_environment_key_changes_fail_closed_on_ambiguity_or_short_key(store, monkeypatch):
    monkeypatch.delenv("BANK_AGENT_KEY", raising=False)
    assert edit(store, lambda r: r["agents"][0].update(api_key_env="BANK_AGENT_KEY"))["status"] == "applied"
    policy = store.snapshot()[0]
    monkeypatch.setenv("BANK_AGENT_KEY", "wk_research_demo")
    assert policy.agent_by_key("wk_research_demo") is None
    monkeypatch.setenv("BANK_AGENT_KEY", "short")
    assert policy.agent_by_key("short") is None
    monkeypatch.setenv("BANK_AGENT_KEY", "unique-bank-key")
    assert policy.agent_by_key("unique-bank-key").id == "bank-ops-agent"


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/", "https://attacker.example/v1", "http://openrouter.ai/api/v1",
    "https://user:pass@openrouter.ai/api/v1", "https://openrouter.ai.evil.example/v1",
    "file:///etc/passwd", "https://openrouter.ai:bad/v1", "https://openrouter.ai/v1#fragment",
])
@pytest.mark.parametrize("section", ["semantic", "model"])
def test_policy_provider_urls_reject_untrusted_destinations(store, url, section):
    before = store.snapshot()[1:]
    def mutate(raw):
        cfg = raw["semantic"] if section == "semantic" else raw["models"]["mock/vulnerable-llm"]
        cfg["base_url"] = url
    assert edit(store, mutate)["status"] == "rejected"
    assert store.snapshot()[1:] == before


def test_policy_provider_urls_keep_loopback_and_official_hosts(store):
    for url in ["http://localhost:11434/v1", "http://127.0.0.1:9/v1", "http://[::1]:11434/v1",
                "https://api.openai.com/v1", "https://openrouter.ai/api/v1"]:
        assert edit(store, lambda r: r["semantic"].update(base_url=url))["status"] == "applied"
    assert edit(store, lambda r: r["semantic"].update(api_key_env="USER"))["status"] == "rejected"


@pytest.mark.parametrize("rule", ["secret_to_egress", "untrusted_value_as_target"])
def test_flow_redact_rejected_but_explicit_monitor_supported(store, rule):
    before = store.snapshot()[1:]
    assert edit(store, lambda r: r["flow"]["rules"].update({rule: "redact"}))["status"] == "rejected"
    assert store.snapshot()[1:] == before
    assert edit(store, lambda r: r["flow"]["rules"].update({rule: "monitor"}))["status"] == "applied"
    assert store.snapshot()[0].flow.enabled


@pytest.mark.parametrize("name", ["/etc/passwd", "../../x.yaml", "feeds/../x.yaml",
                                   "feeds/signatures.yaml\u0000", "", "feeds/x.txt"])
def test_feed_path_is_relative_yaml_without_traversal(store, name):
    before = store.snapshot()[1:]
    assert edit(store, lambda r: r["controls"]["signatures"].update(feed_file=name))["status"] == "rejected"
    assert store.snapshot()[1:] == before


def test_bad_file_encoding_is_recorded_and_last_good_survives(store):
    before = store.snapshot()[1:]
    store.path.write_bytes(b"\xff\xfe" + b"x" * 80)
    assert store.poll(debounce_s=0) is None
    entry = store.poll(debounce_s=0)
    assert entry["status"] == "rejected"
    assert store.snapshot()[1:] == before
    assert store.poll(debounce_s=0) is None
    store.path.write_text(POLICY.read_text(encoding="utf-8"), encoding="utf-8")
    store.poll(debounce_s=0)
    store.poll(debounce_s=0)
    assert store.snapshot()[1:] == before


def test_io_failures_are_rejections_not_exceptions(store, monkeypatch):
    before = store.snapshot()[1:]
    with monkeypatch.context() as patch:
        original = Path.stat
        def denied(path, *args, **kwargs):
            if path == store.path:
                raise PermissionError("policy permission denied")
            return original(path, *args, **kwargs)
        patch.setattr(Path, "stat", denied)
        assert store.poll()["status"] == "rejected"
        assert store.reload()["status"] == "rejected"
    import app.policy as module
    with monkeypatch.context() as patch:
        def denied_replace(*args):
            raise PermissionError("cannot replace policy")
        patch.setattr(module.os, "replace", denied_replace)
        assert store.apply_text(store.text())["status"] == "rejected"
    assert store.snapshot()[1:] == before
    assert list(store.path.parent.iterdir()) == [store.path]


def test_policy_size_and_yaml_aliases_are_bounded(store):
    before = store.snapshot()[1:]
    text = store.text()
    assert store.apply_text(text + "#" + "x" * 256_001)["status"] == "rejected"
    raw = yaml.safe_load(text)
    raw.pop("profiles")
    bomb = yaml.safe_dump(raw) + "\nprofiles:\n  a: &a [1, 1]\n"
    previous = "a"
    for i in range(12):
        current = f"x{i}"
        bomb += f"  {current}: &{current} [*{previous}, *{previous}]\n"
        previous = current
    assert store.apply_text(bomb)["status"] == "rejected"
    assert store.snapshot()[1:] == before
    store.path.write_text(text + "#" + "x" * 256_001, encoding="utf-8")
    assert store.reload()["status"] == "rejected"
    assert store.snapshot()[1:] == before


def test_deep_yaml_and_malformed_profile_shapes_keep_last_good(store):
    before = store.snapshot()[1:]
    text = store.text() + "\nunused: " + "[" * 1500 + "0" + "]" * 1500
    assert store.apply_text(text)["status"] == "rejected"
    for value in [[], ["strict"], "strict", 1]:
        assert edit(store, lambda r: r.update(profiles=value))["status"] == "rejected"
    assert store.snapshot()[1:] == before


def test_wide_policy_diff_keeps_security_fields_and_agent_key_paths(store):
    def add_models(raw):
        raw["models"].update({f"m{i}": {"upstream": "mock", "input_per_1m": 1} for i in range(60)})
    assert edit(store, add_models)["status"] == "applied"

    def mutate(raw):
        for cfg in raw["models"].values():
            cfg["input_per_1m"] = 2
        raw["require_auth"] = False
        raw["semantic"]["base_url"] = "http://127.0.0.1:9/v1"
        raw["tools"]["transfer_funds"]["max_values"]["amount"] = 1
        raw["agents"][0]["api_key"] = "replacement-bank-key"

    entry = edit(store, mutate)
    assert entry["status"] == "applied"
    assert {"require_auth", "semantic.base_url", "tools.transfer_funds.max_values.amount",
            "agents.0.api_key"} <= set(entry["changed"])
    assert len(entry["changed"]) > 50
    assert "replacement-bank-key" not in str(entry)


def test_debounce_restarts_when_file_changes_again(store, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    before = store.snapshot()[1:]
    text = store.text().replace("mode: enforce", "mode: monitor", 1)
    store.path.write_text(text, encoding="utf-8")
    assert store.poll() is None
    now[0] = 0.10
    store.path.write_text(text + "\n# still editing\n", encoding="utf-8")
    assert store.poll() is None
    now[0] = 0.16
    assert store.poll() is None
    assert store.snapshot()[1:] == before
    now[0] = 0.26
    assert store.poll()["status"] == "applied"


def test_snapshot_mutations_do_not_change_store_or_other_snapshots(store):
    policy, digest, version = store.snapshot()
    policy.controls.pii.enabled = False
    policy.agents[0].allowed_tools.clear()
    policy.flow.enabled = False
    other, new_digest, new_version = store.snapshot()
    assert other.controls.pii.enabled and other.flow.enabled
    assert other.agents[0].allowed_tools
    assert (new_digest, new_version) == (digest, version)


@pytest.mark.parametrize("section,field,value", [
    ("flow", "min_chars", 10**6), (None, "max_input_chars", 10**12),
    (None, "approval_ttl_s", 10**9),
])
def test_extreme_control_knobs_rejected(store, section, field, value):
    before = store.snapshot()[1:]
    def mutate(raw):
        cfg = raw[section] if section else raw
        cfg[field] = value
    assert edit(store, mutate)["status"] == "rejected"
    assert store.snapshot()[1:] == before


def test_flow_minimum_preserves_existing_80_char_tuning_and_has_upper_bound(store):
    assert edit(store, lambda r: r["flow"].update(min_chars=80))["status"] == "applied"
    assert edit(store, lambda r: r["flow"].update(min_chars=128))["status"] == "applied"
    assert edit(store, lambda r: r["flow"].update(min_chars=129))["status"] == "rejected"


def test_documented_optional_caps_and_monitor_configuration_stay_valid(store):
    def mutate(raw):
        raw.pop("budgets")
        raw["agents"][0]["budget"]["usd_per_day"] = None
        raw["controls"]["prompt_injection"].update(action="monitor", block_threshold=1, review_threshold=0.99)
        raw["controls"]["pii"]["entities"] = []
        raw["controls"]["canary"]["tokens"] = []
    assert edit(store, mutate)["status"] == "applied"
    policy = store.snapshot()[0]
    assert policy.budget_for(policy.agents[0]).usd_per_day is None
    assert policy.flow.enabled
    assert policy.model_allowed(policy.agent_by_key("wk_judge"), "mock/vulnerable-llm")
    assert not policy.model_allowed(policy.agent_by_key("wk_judge"), "invented-model")
    assert policy.model_allowed(None, "mock/vulnerable-llm")  # require_auth controls anonymous access


def test_profile_name_cannot_inject_optional_yaml_fields(store):
    assert edit(store, lambda r: r.pop("require_auth"))["status"] == "applied"
    before = store.snapshot()[1:]
    text = store.text()
    assert store.set_profile("standard\nrequire_auth: false")["status"] == "rejected"
    assert store.snapshot()[1:] == before
    assert store.text() == text
    assert store.snapshot()[0].require_auth
    assert store.set_profile("strict")["status"] == "applied"


def test_deleted_file_keeps_last_good(store):
    _, h0, _ = store.snapshot()
    store.path.unlink()
    entry = store.poll()
    assert entry and entry["status"] == "rejected"
    assert store.snapshot()[1] == h0
