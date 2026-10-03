"""Tool governance and durable approvals, with deterministic offline clocks."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from app import governance
from app.governance import ApprovalStore, LoopGuard, check_tool_call
from app.models import Action
from app.policy import AgentCfg, LoopCfg, Policy, ToolCfg


@pytest.fixture
def policy() -> Policy:
    return Policy(
        version="test", models={"mock": {"upstream": "mock"}},
        agents=[AgentCfg(id="bank", allowed_tools=["lookup_customer", "read_document", "send_email", "transfer_funds"]),
                AgentCfg(id="reader", allowed_tools=["read_document"]), AgentCfg(id="no-tools")],
        tools={"lookup_customer": ToolCfg(labels=["secret"]), "read_document": ToolCfg(labels=["untrusted"]),
               "send_email": ToolCfg(egress=True, arg_patterns={"to": r"[\w.+-]+@bank\.example"},
                                     deny_arg_patterns={"body": r"(?i)forbidden|evil\.example"}),
               "transfer_funds": ToolCfg(egress=True, irreversible=True, max_values={"amount": 10000})},
    )


@pytest.fixture
def store(tmp_path: Path) -> ApprovalStore:
    return ApprovalStore(tmp_path / "state" / "approvals.jsonl")


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [1000.0]
    monkeypatch.setattr(governance.time, "time", lambda: now[0])
    return now


def check(policy: Policy, store: ApprovalStore, tool: str, args: Any, approval_id: str | None = None,
          agent_id: str = "bank", policy_hash: str = "policy-v1"):
    return check_tool_call(policy, policy.agent_by_id(agent_id), tool, args, store, approval_id, policy_hash)


def approved(store: ApprovalStore, args: dict[str, Any] | None = None, ttl: float = 120) -> str:
    item = store.create("bank", "transfer_funds", args or {"amount": 50}, "policy-v1", ttl)
    store.decide(item["id"], True)
    return item["id"]


def test_allowlisted_tool_and_json_object_pass(policy: Policy, store: ApprovalStore) -> None:
    args, findings = check(policy, store, "read_document", '{"doc_id":"invoice-7"}')
    assert args == {"doc_id": "invoice-7"}
    assert findings == []
    original = {"nested": {"items": [1, "x", None, True]}}
    args, findings = check(policy, store, "read_document", original)
    args["nested"]["items"].append(2)
    assert original["nested"]["items"] == [1, "x", None, True]
    assert findings == []


@pytest.mark.parametrize("agent_id", ["reader", "no-tools", "missing"])
def test_allowlist_missing_allowed_tools_means_none(policy: Policy, store: ApprovalStore, agent_id: str) -> None:
    args, findings = check(policy, store, "lookup_customer", {}, agent_id=agent_id)
    assert args is None
    assert [f.control_id for f in findings] == ["tools.allowlist"]
    assert findings[0].action == Action.BLOCK
    assert findings[0].owasp == "LLM06"
    assert store.list() == []


def test_unknown_tool_is_rejected_before_argument_parsing(policy: Policy, store: ApprovalStore) -> None:
    args, findings = check(policy, store, "not-in-catalog", "invalid")
    assert args is None
    assert [f.control_id for f in findings] == ["tools.unknown"]


def test_kill_switch_has_priority_over_unknown_allowlist_and_args(policy: Policy, store: ApprovalStore) -> None:
    policy.kill_switch = ["bank"]
    args, findings = check(policy, store, "unknown", "invalid")
    assert args is None
    assert [f.control_id for f in findings] == ["tools.kill_switch"]
    assert check(policy, store, "read_document", {}, agent_id="reader")[1] == []


@pytest.mark.parametrize("raw", [
    "{", "", "null", "[]", "42", '"string"', "true", None, [], 42,
    '{"amount":1,"amount":2}', '{"outer":{"key":1,"key":2}}', '{"list":[{"key":1,"key":2}]}',
    '{"key":1,"\\u006bey":2}', '{"amount":NaN}', '{"amount":Infinity}', '{"amount":-Infinity}',
    '{"amount":1e999}', {"amount": float("nan")}, {"amount": float("inf")},
    {"value": object()}, {"value": (1, 2)}, {123: "value"},
])
def test_invalid_nonobject_duplicate_or_nonfinite_json_rejected(policy: Policy, store: ApprovalStore, raw: Any) -> None:
    args, findings = check(policy, store, "read_document", raw)
    assert args is None
    assert [f.control_id for f in findings] == ["tools.args"]
    assert store.list() == []


def test_cyclic_argument_dict_rejected_without_crashing(policy: Policy, store: ApprovalStore) -> None:
    args: dict[str, Any] = {}
    args["cycle"] = args
    assert check(policy, store, "read_document", args)[1][0].control_id == "tools.args"


@pytest.mark.parametrize("to", ["audit@evil.example", "ops@bank.example.evil", "prefix ops@bank.example", "ops@bank.example\n", "", None, 7, ["ops@bank.example"]])
def test_arg_patterns_use_fullmatch_and_require_string(policy: Policy, store: ApprovalStore, to: Any) -> None:
    args, findings = check(policy, store, "send_email", {"to": to, "body": "benign"})
    assert args is not None
    assert [f.control_id for f in findings] == ["tools.arg_pattern"]
    assert "evil.example" not in findings[0].detail


def test_missing_pattern_argument_rejected(policy: Policy, store: ApprovalStore) -> None:
    assert check(policy, store, "send_email", {"body": "hello"})[1][0].control_id == "tools.arg_pattern"
    assert check(policy, store, "send_email", {"to": "ops@bank.example", "body": "hello"})[1] == []


@pytest.mark.parametrize("body", ["FORBIDDEN", "Visit https://evil.example/x", ["safe", {"text": "forbidden"}], {"nested": ["forbidden"]}])
def test_deny_patterns_search_nested_string_leaves(policy: Policy, store: ApprovalStore, body: Any) -> None:
    _, findings = check(policy, store, "send_email", {"to": "ops@bank.example", "body": body})
    assert [f.control_id for f in findings] == ["tools.arg_pattern"]


@pytest.mark.parametrize("amount", [10001, 10000.01, "100", None, True, False, [], {}])
def test_max_values_fail_closed_for_missing_invalid_and_over_limit(policy: Policy, store: ApprovalStore, amount: Any) -> None:
    args, findings = check(policy, store, "transfer_funds", {"amount": amount})
    assert args is not None
    assert [f.control_id for f in findings] == ["tools.max_value"]
    assert store.list() == []


def test_missing_max_value_argument_rejected(policy: Policy, store: ApprovalStore) -> None:
    assert check(policy, store, "transfer_funds", {})[1][0].control_id == "tools.max_value"


@pytest.mark.parametrize("amount", [0, 50, 9999.99, 10000, 10000.0])
def test_max_values_inclusive_boundary_requires_approval(policy: Policy, store: ApprovalStore, amount: int | float) -> None:
    args, findings = check(policy, store, "transfer_funds", {"amount": amount})
    assert args == {"amount": amount}
    assert [f.control_id for f in findings] == ["tools.approval"]
    assert findings[0].action == Action.REQUIRE_APPROVAL
    pending = store.list("pending")
    assert len(pending) == 1
    assert f"approval_id={pending[0]['id']}" in findings[0].detail
    assert pending[0]["policy_hash"] == "policy-v1"


def test_create_approve_consume_is_single_use_and_recoverable(store: ApprovalStore, clock: list[float]) -> None:
    args = {"amount": 50, "iban": "PL61109010140000071219812874"}
    item = store.create("bank", "transfer_funds", args, "policy-v1", 120)
    assert item["status"] == "pending"
    assert item["created_at"] == 1000
    assert item["expires_at"] == 1120
    assert store.consume(item["id"], "bank", "transfer_funds", args) is False
    decision = store.decide(item["id"], True, "alice")
    assert decision["status"] == "approved"
    assert decision["who"] == "alice"
    assert decision["decided_at"] == 1000
    restarted = ApprovalStore(store.path)
    assert restarted.consume(item["id"], "bank", "transfer_funds", args) is True
    assert restarted.consume(item["id"], "bank", "transfer_funds", args) is False
    assert ApprovalStore(store.path).consume(item["id"], "bank", "transfer_funds", args) is False
    assert [r["status"] for r in map(json.loads, store.path.read_text().splitlines())] == ["pending", "approved", "consumed"]
    assert "PL61109010140000071219812874" not in store.path.read_text()
    assert restarted.list("consumed")[0]["policy_hash"] == "policy-v1"


def test_canonical_args_are_order_independent_but_type_sensitive(store: ApprovalStore) -> None:
    args = {"iban": "żą", "nested": {"b": [1, True], "a": "x"}, "amount": 50}
    id = approved(store, args)
    reordered = {"amount": 50, "nested": {"a": "x", "b": [1, True]}, "iban": "żą"}
    assert store.consume(id, "bank", "transfer_funds", {**reordered, "amount": "50"}) is False
    assert store.consume(id, "bank", "transfer_funds", reordered) is True


@pytest.mark.parametrize("agent,tool,args", [("other", "transfer_funds", {"amount": 50}), ("bank", "send_email", {"amount": 50}), ("bank", "transfer_funds", {"amount": 51})])
def test_approval_mismatched_bindings_do_not_consume(store: ApprovalStore, agent: str, tool: str, args: dict[str, Any]) -> None:
    id = approved(store)
    assert store.consume(id, agent, tool, args) is False
    assert store.consume(id, "bank", "transfer_funds", {"amount": 50}) is True


def test_unknown_denied_and_invalid_args_cannot_consume(store: ApprovalStore) -> None:
    assert store.consume("missing", "bank", "transfer_funds", {}) is False
    item = store.create("bank", "transfer_funds", {}, "policy-v1", 120)
    assert store.decide(item["id"], False)["status"] == "denied"
    assert store.consume(item["id"], "bank", "transfer_funds", {}) is False
    id = approved(store)
    assert store.consume(id, "bank", "transfer_funds", {"amount": float("nan")}) is False
    assert store.consume(id, "bank", "transfer_funds", {"amount": 50}) is True


@pytest.mark.parametrize("state", ["pending", "approved"])
def test_expiry_at_exact_deadline_is_durable(store: ApprovalStore, clock: list[float], state: str) -> None:
    item = store.create("bank", "transfer_funds", {}, "policy-v1", 5)
    if state == "approved":
        store.decide(item["id"], True)
    clock[0] = 1005
    assert store.consume(item["id"], "bank", "transfer_funds", {}) is False
    assert store.list("expired")[0]["id"] == item["id"]
    assert ApprovalStore(store.path).list()[0]["status"] == "expired"
    with pytest.raises(ValueError):
        store.decide(item["id"], True)


def test_approval_works_just_before_expiry(store: ApprovalStore, clock: list[float]) -> None:
    id = approved(store, ttl=5)
    clock[0] = 1004.999
    assert store.consume(id, "bank", "transfer_funds", {"amount": 50}) is True


@pytest.mark.parametrize("ttl", [0, -1, float("nan"), float("inf"), True])
def test_invalid_ttl_rejected(store: ApprovalStore, ttl: float) -> None:
    with pytest.raises(ValueError):
        store.create("bank", "transfer_funds", {}, "policy-v1", ttl)
    assert store.list() == []


def test_decisions_terminal_and_unknown_id_explicit(store: ApprovalStore) -> None:
    with pytest.raises(KeyError):
        store.decide("missing", True)
    id = approved(store)
    with pytest.raises(ValueError):
        store.decide(id, False)
    assert store.consume(id, "bank", "transfer_funds", {"amount": 50})
    with pytest.raises(ValueError):
        store.decide(id, True)
    item = store.create("bank", "transfer_funds", {}, "policy-v1", 120)
    with pytest.raises(ValueError):
        store.decide(item["id"], "yes")


def test_record_return_values_cannot_mutate_store(store: ApprovalStore) -> None:
    item = store.create("bank", "transfer_funds", {}, "policy-v1", 120)
    id = item["id"]
    item["status"] = "approved"
    assert store.consume(id, "bank", "transfer_funds", {}) is False
    records = store.list()
    records[0]["status"] = "approved"
    assert store.list()[0]["status"] == "pending"
    decision = store.decide(id, True)
    decision["args_hash"] = "forged"
    assert store.consume(id, "bank", "transfer_funds", {}) is True


def test_parallel_consumers_authorize_exactly_one(store: ApprovalStore) -> None:
    id = approved(store)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.consume(id, "bank", "transfer_funds", {"amount": 50}), range(32)))
    assert sum(results) == 1
    assert len(store.list("consumed")) == 1


def test_parallel_creates_and_journal_restore(store: ApprovalStore) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(lambda n: store.create("bank", "transfer_funds", {"amount": n}, "policy-v1", 120), range(32)))
    assert len({r["id"] for r in records}) == 32
    assert len(ApprovalStore(store.path).list("pending")) == 32


@pytest.mark.parametrize("journal", ['{"id":"truncated"', '{}\n', '{"id":"a","id":"b"}\n', '[]\n'])
def test_malformed_journal_fails_closed(tmp_path: Path, journal: str) -> None:
    path = tmp_path / "approvals.jsonl"
    path.write_text(journal)
    with pytest.raises(ValueError):
        ApprovalStore(path)


def test_persistence_error_does_not_authorize_in_memory(store: ApprovalStore, monkeypatch: pytest.MonkeyPatch) -> None:
    item = store.create("bank", "transfer_funds", {}, "policy-v1", 120)
    def fail(*args: Any, **kwargs: Any) -> int:
        raise OSError("disk unavailable")
    monkeypatch.setattr(governance.os, "open", fail)
    with pytest.raises(OSError):
        store.decide(item["id"], True)
    assert store.list()[0]["status"] == "pending"
    assert store.consume(item["id"], "bank", "transfer_funds", {}) is False


def test_check_approval_roundtrip_replay_and_policy_binding(policy: Policy, store: ApprovalStore) -> None:
    args = {"amount": 50}
    _, findings = check(policy, store, "transfer_funds", args)
    id = store.list("pending")[0]["id"]
    assert id in findings[0].detail
    store.decide(id, True)
    assert check(policy, store, "transfer_funds", args, id)[1] == []
    assert check(policy, store, "transfer_funds", args, id)[1][0].control_id == "tools.approval"
    other = approved(store)
    _, findings = check(policy, store, "transfer_funds", args, other, policy_hash="policy-v2")
    assert findings[0].control_id == "tools.approval"
    assert other in {r["id"] for r in store.list("approved")}
    assert store.list("pending")[-1]["policy_hash"] == "policy-v2"


@pytest.mark.parametrize("id_kind", ["missing", "pending", "denied", "expired", "args_mismatch"])
def test_invalid_approval_creates_new_pending(policy: Policy, store: ApprovalStore, clock: list[float], id_kind: str) -> None:
    id = "missing"
    if id_kind != "missing":
        item = store.create("bank", "transfer_funds", {"amount": 51 if id_kind == "args_mismatch" else 50}, "policy-v1", 5)
        id = item["id"]
        if id_kind in {"expired", "args_mismatch"}:
            store.decide(id, True)
        elif id_kind == "denied":
            store.decide(id, False)
        if id_kind == "expired":
            clock[0] += 5
    _, findings = check(policy, store, "transfer_funds", {"amount": 50}, id)
    assert findings[0].control_id == "tools.approval"
    assert any(r["id"] != id for r in store.list("pending"))


@pytest.mark.parametrize("constraint", ["kill", "allowlist", "max", "pattern"])
def test_approval_never_overrides_earlier_controls_or_is_consumed(policy: Policy, store: ApprovalStore, constraint: str) -> None:
    id = approved(store)
    if constraint == "kill":
        policy.kill_switch = ["bank"]
    elif constraint == "allowlist":
        policy.agents[0].allowed_tools.remove("transfer_funds")
    elif constraint == "max":
        policy.tools["transfer_funds"].max_values["amount"] = 40
    else:
        policy.tools["transfer_funds"].arg_patterns["iban"] = r"PL[0-9]+"
    _, findings = check(policy, store, "transfer_funds", {"amount": 50}, id)
    assert all(f.action == Action.BLOCK for f in findings)
    assert store.list("approved")[0]["id"] == id


def test_irreversible_false_does_not_consume_unneeded_approval(policy: Policy, store: ApprovalStore) -> None:
    id = approved(store)
    policy.tools["transfer_funds"].irreversible = False
    assert check(policy, store, "transfer_funds", {"amount": 50}, id)[1] == []
    assert store.list("approved")[0]["id"] == id


def test_loop_repeat_threshold_and_sliding_window() -> None:
    now = [0.0]
    guard = LoopGuard(lambda: now[0])
    cfg = LoopCfg(max_identical=3, window_seconds=10, max_requests_per_session=20)
    for _ in range(3):
        assert guard.check("bank", "s", "same", cfg) is None
    finding = guard.check("bank", "s", "same", cfg)
    assert finding.control_id == "loop.repeat"
    assert finding.action == Action.BLOCK
    assert finding.owasp == "LLM10"
    assert guard.check("bank", "s", "different", cfg) is None
    now[0] = 10.0
    assert guard.check("bank", "s", "same", cfg) is None


def test_loop_is_scoped_to_agent_and_session() -> None:
    guard = LoopGuard(lambda: 0.0)
    cfg = LoopCfg(max_identical=1)
    assert guard.check("bank", "s", "same", cfg) is None
    assert guard.check("bank", "s", "same", cfg).control_id == "loop.repeat"
    assert guard.check("other", "s", "same", cfg) is None
    assert guard.check("bank", "other", "same", cfg) is None


def test_session_limit_is_lifetime_not_sliding_window() -> None:
    now = [0.0]
    guard = LoopGuard(lambda: now[0])
    cfg = LoopCfg(max_requests_per_session=2, window_seconds=5)
    assert guard.check("bank", "s", "one", cfg) is None
    now[0] = 100.0
    assert guard.check("bank", "s", "two", cfg) is None
    finding = guard.check("bank", "s", "three", cfg)
    assert finding.control_id == "loop.session_limit"
    assert guard.check("bank", "new", "three", cfg) is None


@pytest.mark.parametrize("action", ["monitor", "redact", "block"])
def test_loop_actions_and_disabled_no_accounting(action: str) -> None:
    guard = LoopGuard(lambda: 0.0)
    cfg = LoopCfg(enabled=False, action=action, max_identical=1, max_requests_per_session=2)
    for _ in range(10):
        assert guard.check("bank", "s", "same", cfg) is None
    cfg.enabled = True
    assert guard.check("bank", "s", "same", cfg) is None
    assert guard.check("bank", "s", "same", cfg).action == Action(action)
    assert guard.check("bank", "s", "same", cfg).control_id == "loop.session_limit"


def test_parallel_loop_checks_enforce_session_limit() -> None:
    guard = LoopGuard(lambda: 0.0)
    cfg = LoopCfg(max_identical=100, max_requests_per_session=5)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda n: guard.check("bank", "s", str(n), cfg), range(32)))
    assert sum(f is None for f in results) == 5
    assert all(f is None or f.control_id == "loop.session_limit" for f in results)
