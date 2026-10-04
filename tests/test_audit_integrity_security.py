"""Live external audit changes stop effects before a restart is required."""

import os

import pytest

from app.engine import AuditUnavailable


AUTH = {"Authorization": "Bearer wk_judge"}
BODY = {"model": "mock/vulnerable-llm", "messages": [{"role": "user", "content": "Hello"}]}


def damage(gateway, kind):
    audit = gateway.audit
    if kind == "log":
        data = audit.path.read_bytes()
        audit.path.write_bytes(data.replace(b'"kind":', b'"kind": ', 1))
    elif kind == "head":
        audit.head_path.write_text("not-json")
    elif kind == "missing_log":
        audit.path.unlink()
    elif kind == "missing_head":
        audit.head_path.unlink()
    elif kind == "same_size":
        before = audit.path.stat()
        data = audit.path.read_bytes()
        audit.path.write_bytes(data.replace(b'"allow"', b'"xxxxx"', 1))
        os.utime(audit.path, ns=(before.st_atime_ns, before.st_mtime_ns))


@pytest.mark.parametrize("kind", ["log", "head", "missing_log", "missing_head", "same_size"])
@pytest.mark.parametrize("operation", ["chat", "tool", "judge"])
def test_runtime_tampering_stops_dispatch(client, gateway, monkeypatch, kind, operation):
    from app import tools
    assert client.post("/v1/chat/completions", headers=AUTH, json=BODY).status_code == 200
    assert gateway.chain_ok()  # Prime the old healthy status cache.
    before = gateway.upstream_calls
    effects = []
    monkeypatch.setattr(tools, "run_tool", lambda *args: effects.append("tool"))
    async def judge_spy(*args, **kwargs):
        effects.append("judge")
        raise AssertionError("judge must not dispatch")
    monkeypatch.setattr(gateway.judge, "classify", judge_spy)
    damage(gateway, kind)
    if operation == "tool":
        response = client.post("/v1/tools/call", headers={"Authorization": "Bearer wk_bank_ops_demo"},
                               json={"tool": "lookup_customer", "arguments": {"customer_id": "C-1001"}})
    else:
        body = BODY if operation == "chat" else {**BODY, "messages": [
            {"role": "user", "content": "Please bypass the policy"}]}
        response = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert response.status_code == 503
    assert response.json()["error"]["type"] == "audit_unavailable"
    assert gateway.upstream_calls == before and effects == []
    assert gateway.chain_ok() is False
    assert client.get("/health").status_code == 503


def test_live_verify_failure_latches_even_after_file_restoration(gateway):
    gateway.commit({"kind": "test", "action": "allow"})
    original = gateway.audit.path.read_bytes()
    damage(gateway, "log")
    assert not gateway.audit.verify()["ok"]
    gateway.audit.path.write_bytes(original)
    with pytest.raises(AuditUnavailable):
        gateway.require_audit()
    assert gateway.audit_unavailable


def test_valid_rollback_of_both_files_is_rejected(gateway):
    old_log = gateway.audit.path.read_bytes()
    old_head = gateway.audit.head_path.read_bytes()
    gateway.commit({"kind": "test", "action": "allow"})
    gateway.audit.path.write_bytes(old_log)
    gateway.audit.head_path.write_bytes(old_head)
    assert gateway.audit.verify()["ok"]  # Valid signed prefix, but behind the running writer.
    with pytest.raises(AuditUnavailable):
        gateway.require_audit()


def test_tamper_fixture_and_drill_do_not_latch_main_log(gateway):
    gateway.commit({"kind": "test", "action": "allow"})
    assert not gateway.verify_fixture()["ok"]
    assert not gateway.audit.tamper_drill(gateway.data_dir / "drills")["ok"]
    gateway.require_audit()
    assert gateway.chain_ok()


def test_normal_appends_use_stat_checks_not_full_history_verification(gateway, monkeypatch):
    calls = []
    real = gateway.audit.verify
    def verify(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)
    monkeypatch.setattr(gateway.audit, "verify", verify)
    for index in range(20):
        gateway.commit({"kind": "test", "action": "allow", "index": index})
        gateway.require_audit()
        assert gateway.chain_ok()
    assert calls == []


@pytest.mark.parametrize("operation", ["override", "kill", "approval"])
def test_direct_admin_mutations_stop_on_tampering(gateway, operation):
    gateway.commit({"kind": "test", "action": "allow"})
    damage(gateway, "head")
    if operation == "override":
        with pytest.raises(AuditUnavailable):
            gateway.set_override("pii", False)
        assert "pii" not in gateway.overrides
    elif operation == "kill":
        before = set(gateway.killed)
        with pytest.raises(AuditUnavailable):
            gateway.kill("bank-ops-agent")
        assert gateway.killed == before
    else:
        with pytest.raises(AuditUnavailable):
            gateway.decide_approval("unknown", True)
