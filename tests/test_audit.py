import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.audit import AuditLog

KEY = b"test-only-audit-key"


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path, KEY)


def populate(audit):
    return [audit.append({"kind": "chat", "agent_id": "bank", "action": "allow",
                          "summary": f"entry-{i}", "cost_usd": 0.01}) for i in range(4)]


def test_empty_log_and_verify(audit):
    assert audit.verify() == {"ok": True, "count": 0, "broken_at": None, "reason": "ok"}
    assert audit.all() == audit.tail() == []
    head = json.loads(audit.head_path.read_text())
    assert head == {"hash": "0" * 64, "count": 0}


def test_append_canonical_hmac_and_durable_head(audit):
    first = audit.append({"action": "allow", "summary": "Polski: ąść / Україна",
                          "seq": 999, "prev": "forged", "hash": "forged", "ts": 0})
    assert first["seq"] == 1 and first["ts"] > 0 and first["prev"] == "0" * 64
    body = {k: v for k, v in first.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert first["hash"] == hmac.new(KEY, (first["prev"] + canonical).encode(), hashlib.sha256).hexdigest()
    second = audit.append({"action": "block"})
    assert second["seq"] == 2 and second["prev"] == first["hash"]
    assert audit.verify()["ok"]
    assert audit.all() == [first, second]
    assert json.loads(audit.head_path.read_text()) == {"hash": second["hash"], "count": 2}


def test_reopen_continues_verified_chain(audit):
    records = populate(audit)
    reopened = AuditLog(audit.directory, KEY)
    next_record = reopened.append({"action": "monitor"})
    assert next_record["seq"] == 5 and next_record["prev"] == records[-1]["hash"]
    assert reopened.verify()["count"] == 5


@pytest.mark.parametrize("tamper,broken_at", [
    ("edited_byte", 2), ("deleted_middle", 2), ("reordered", 1),
    ("truncated_tail", 4), ("partial_tail", 4), ("deleted_all", 1),
])
def test_tampering_is_detected(audit, tamper, broken_at):
    populate(audit)
    lines = audit.path.read_bytes().splitlines(keepends=True)
    if tamper == "edited_byte":
        lines[1] = lines[1].replace(b"entry-1", b"entry-X")
    elif tamper == "deleted_middle":
        del lines[1]
    elif tamper == "reordered":
        lines[0], lines[1] = lines[1], lines[0]
    elif tamper == "truncated_tail":
        lines.pop()
    elif tamper == "partial_tail":
        lines[-1] = lines[-1][:-10]
    else:
        lines.clear()
    audit.path.write_bytes(b"".join(lines))
    result = audit.verify()
    assert not result["ok"] and result["broken_at"] == broken_at
    assert result["count"] == broken_at - 1 and result["reason"] != "ok"
    with pytest.raises(ValueError, match="invalid audit chain"):
        AuditLog(audit.directory, KEY)


def test_canonical_equivalent_byte_edit_is_detected(audit):
    populate(audit)
    original = audit.path.read_bytes()
    audit.path.write_bytes(original.replace(b'"action":', b'"action": ', 1))
    result = audit.verify()
    assert not result["ok"] and result["broken_at"] == 1
    assert "bytes changed" in result["reason"]


def test_recomputed_unkeyed_hash_does_not_pass(audit):
    populate(audit)
    lines = audit.path.read_text().splitlines()
    changed = json.loads(lines[0])
    changed["summary"] = "forged"
    body = {k: v for k, v in changed.items() if k != "hash"}
    changed["hash"] = hashlib.sha256((changed["prev"] + json.dumps(body, sort_keys=True)).encode()).hexdigest()
    lines[0] = json.dumps(changed)
    audit.path.write_text("\n".join(lines) + "\n")
    assert audit.verify()["reason"] == "HMAC mismatch"


@pytest.mark.parametrize("key", [None, b"", "not-bytes", bytearray(b"key")])
def test_nonempty_bytes_hmac_key_required(tmp_path, key):
    with pytest.raises(ValueError, match="HMAC key"):
        AuditLog(tmp_path, key)
    assert not (tmp_path / "audit.jsonl").exists()


def test_key_argument_cannot_be_omitted(tmp_path):
    with pytest.raises(TypeError):
        AuditLog(tmp_path)


def test_wrong_key_rejected_on_reopen(audit):
    populate(audit)
    with pytest.raises(ValueError, match="HMAC mismatch"):
        AuditLog(audit.directory, b"wrong-key")


@pytest.mark.parametrize("damage", ["missing_head", "count", "hash", "invalid_head", "missing_log"])
def test_checkpoint_damage_detected(audit, damage):
    populate(audit)
    if damage == "missing_head":
        audit.head_path.unlink()
    elif damage == "missing_log":
        audit.path.unlink()
    elif damage == "invalid_head":
        audit.head_path.write_text("not-json")
    else:
        head = json.loads(audit.head_path.read_text())
        head[damage] = 100 if damage == "count" else "f" * 64
        audit.head_path.write_text(json.dumps(head))
    assert not audit.verify()["ok"]
    with pytest.raises(ValueError):
        AuditLog(audit.directory, KEY)


def test_external_fixture_and_adjacent_checkpoint(audit, tmp_path):
    populate(audit)
    fixture = tmp_path / "fixture.jsonl"
    fixture.write_bytes(audit.path.read_bytes())
    assert audit.verify(fixture)["ok"]  # External fixtures can verify without a checkpoint.
    fixture.with_suffix(".head").write_bytes(audit.head_path.read_bytes())
    fixture.write_bytes(b"".join(fixture.read_bytes().splitlines(keepends=True)[:-1]))
    assert "tail truncation" in audit.verify(fixture)["reason"]
    assert not audit.verify(tmp_path / "nonexistent.jsonl")["ok"]


@pytest.mark.parametrize("content", [b"\n", b"[]\n", b"{invalid}\n", b"\xff\n",
                                      b'{"seq":1,"seq":1}\n'])
def test_malformed_lines_fail_closed(audit, content):
    audit.path.write_bytes(content)
    result = audit.verify()
    assert not result["ok"] and result["broken_at"] == 1


def test_tail_filters_and_sizes(audit):
    for i in range(6):
        audit.append({"action": "block" if i % 2 else "allow", "agent_id": "a" if i < 4 else "b"})
    assert [r["seq"] for r in audit.tail(2)] == [5, 6]
    assert [r["seq"] for r in audit.tail(2, action="block")] == [4, 6]
    assert [r["seq"] for r in audit.tail(50, action="block", agent_id="a")] == [2, 4]
    assert audit.tail(0) == audit.tail(action="nonexistent") == []
    with pytest.raises(ValueError):
        audit.tail(-1)


def test_nested_caller_and_return_mutation_cannot_change_stored_record(audit):
    record = {"primary": {"control_id": "pii.email"}, "findings": [{"action": "redact"}]}
    saved = audit.append(record)
    record["primary"]["control_id"] = "changed"
    saved["findings"][0]["action"] = "changed"
    fetched = audit.all()
    assert fetched[0]["primary"]["control_id"] == "pii.email"
    assert fetched[0]["findings"][0]["action"] == "redact"
    fetched.clear()
    assert audit.verify()["ok"] and len(audit.all()) == 1


@pytest.mark.parametrize("record", [{"number": float("nan")}, {"number": float("inf")}, {"value": object()}])
def test_unserializable_record_does_not_write_or_advance(audit, record):
    with pytest.raises((ValueError, TypeError)):
        audit.append(record)
    assert audit.verify()["ok"] and audit.verify()["count"] == 0
    assert audit.append({"action": "allow"})["seq"] == 1


def test_concurrent_appends_have_unique_ordered_chain(audit):
    with ThreadPoolExecutor(max_workers=10) as pool:
        records = list(pool.map(lambda i: audit.append({"action": "allow", "request_id": str(i)}), range(50)))
    assert sorted(r["seq"] for r in records) == list(range(1, 51))
    assert len({r["hash"] for r in records}) == 50
    assert audit.verify()["ok"] and audit.verify()["count"] == 50


def test_checkpoint_write_failure_is_not_silently_accepted(audit, monkeypatch):
    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(audit, "_write_head", fail)
    with pytest.raises(OSError, match="disk full"):
        audit.append({"action": "allow"})
    assert not audit.verify()["ok"]
    with pytest.raises(RuntimeError, match="reopen"):
        audit.append({"action": "allow"})


def test_report_md_renders_security_sections_and_why(audit):
    audit.append({"kind": "chat", "action": "allow", "agent_id": "bank"})
    audit.append({"kind": "chat", "action": "block", "agent_id": "bank",
                  "summary": "unsafe request", "primary": {"control_id": "budget.usd", "detail": "Limit | exceeded\nnow"}})
    audit.append({"kind": "policy", "status": "applied", "changed": ["controls.pii.enabled"]})
    report = audit.report_md({"policy": {"version": 3, "hash": "abc", "profile": "strict", "mode": "enforce"},
                              "posture": {"score": 90, "gaps": ["<script>disabled</script>"]}})
    for section in ("Summary", "Posture", "Counts", "Top blocks", "Policy changes", "Chain status"):
        assert f"## {section}" in report
    assert "Audit records: 3" in report and "Requests: 2" in report
    assert "budget.usd" in report and "Limit \\| exceeded now" in report
    assert "controls.pii.enabled" in report and "OK: 3 verified records" in report
    assert "<script>" not in report and "&lt;script&gt;" in report
    assert "| block | 1 |" in report and "| allow | 1 |" in report


def test_report_empty_and_broken_chain(audit):
    report = audit.report_md({})
    assert "No blocks recorded" in report and "No policy changes" in report
    assert "No reported gaps" in report and "OK: 0" in report
    populate(audit)
    audit.path.write_bytes(b"".join(audit.path.read_bytes().splitlines(keepends=True)[:-1]))
    report = audit.report_md({})
    assert "BROKEN" in report and "Broken at #4" in report
    audit.path.write_bytes(b"not-json\n")
    report = audit.report_md({})
    assert "BROKEN" in report and "Broken at #1" in report
