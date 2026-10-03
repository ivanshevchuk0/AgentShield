"""Protected tool-result fingerprints survive restarts without raw content."""
import pytest
from fastapi.testclient import TestClient

from app.audit import AuditLog
from app.flow import TaintStore
from app.main import create_app
from app.policy import FlowCfg, ToolCfg

SECRET = "PL61109010140000071219812874"
SEND = ToolCfg(egress=True)


def test_persist_restore_and_clear(tmp_path):
    audit = AuditLog(tmp_path, b"audit-key")
    store = TaintStore(persist=audit.append, key=b"flow-key")
    store.add("agent:a", "lookup", ["secret"], SECRET)
    restored = TaintStore(audit.all(), audit.append, b"flow-key")
    assert restored.check_egress("agent:a", "send", SEND, {"body": SECRET}, FlowCfg())
    assert not restored.check_egress("agent:b", "send", SEND, {"body": SECRET}, FlowCfg())
    assert SECRET not in audit.path.read_text()
    assert audit.verify()["ok"]
    assert "- Requests: 0" in audit.report_md({})
    restored.clear("agent:a")
    assert not TaintStore(audit.all(), key=b"flow-key").labels("agent:a")


def test_persistence_failure_does_not_publish_state():
    def fail(record):
        raise OSError("disk full")
    store = TaintStore(persist=fail, key=b"key")
    with pytest.raises(OSError):
        store.add("agent:a", "lookup", ["secret"], SECRET)
    assert store.labels("agent:a") == set()


def test_gateway_restart_keeps_flow_protection(client, policy_file, data_dir):
    headers = {"Authorization": "Bearer wk_bank_ops_demo"}
    assert client.post("/v1/tools/call", headers=headers, json={
        "tool": "lookup_customer", "arguments": {"customer_id": "C-1001"}}).status_code == 200
    with TestClient(create_app(policy_path=policy_file, data_dir=data_dir)) as restarted:
        response = restarted.post("/v1/tools/call", headers={**headers, "X-Session": "after-restart"}, json={
            "tool": "send_email", "arguments": {"to": "ops@bank.example", "subject": "hi", "body": SECRET}})
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "flow.secret_egress"
