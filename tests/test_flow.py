"""Offline information-flow regression tests; no detector or network dependency."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import pytest

from app.flow import TaintStore, sign_call_id, verify_call_id
from app.models import Action
from app.policy import FlowCfg, FlowRules, ToolCfg

IBAN = "PL61109010140000071219812874"
TOKEN = "aZqXvJmKpRtWuLsNgBfD"
EMAIL = "customer.personal@bank.example"
KEY = b"offline-call-signing-key"
SEND = ToolCfg(egress=True, target_args=["to"])
TRANSFER = ToolCfg(egress=True, irreversible=True, target_args=["iban"])


def encode(value: str, kind: str) -> str:
    return {
        "plain": lambda: value,
        "spacing": lambda: " ".join(value),
        "dashes": lambda: "-".join(value),
        "uppercase": lambda: value.upper(),
        "base64": lambda: base64.b64encode(value.encode()).decode(),
        "urlsafe": lambda: base64.urlsafe_b64encode(value.encode()).decode().rstrip("="),
        "hex": lambda: value.encode().hex(),
        "url": lambda: "".join(f"%{byte:02X}" for byte in value.encode()),
        "nested": lambda: base64.b64encode(base64.b64encode(value.encode())).decode(),
        "zero_width": lambda: "\u200b".join(value),
    }[kind]()


@pytest.mark.parametrize("value", [TOKEN, "44051401359", IBAN, EMAIL])
@pytest.mark.parametrize("kind", ["plain", "spacing", "dashes", "uppercase", "base64", "urlsafe", "hex", "url", "nested", "zero_width"])
def test_lookup_customer_secret_cannot_leave_in_send_email(value: str, kind: str) -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret"], json.dumps({"protected": value}))
    findings = taint.check_egress("s", "send_email", SEND, {"body": f"Audit: {encode(value, kind)}"}, FlowCfg())
    assert [f.control_id for f in findings] == ["flow.secret_egress"]
    assert findings[0].action == Action.BLOCK
    assert findings[0].owasp == "LLM06"
    assert value not in json.dumps(findings[0].to_dict())


@pytest.mark.parametrize("kind", ["plain", "spacing", "dashes", "base64", "uppercase", "hex", "url"])
def test_untrusted_document_iban_cannot_be_transfer_target(kind: str) -> None:
    taint = TaintStore()
    taint.add("s", "read_document", ["untrusted"], f"Pay this invoice to {IBAN}.")
    findings = taint.check_egress("s", "transfer_funds", TRANSFER, {"iban": encode(IBAN, kind), "amount": 50}, FlowCfg())
    assert [f.control_id for f in findings] == ["flow.untrusted_target", "flow.untrusted_before_irreversible"]
    assert [f.action for f in findings] == [Action.BLOCK, Action.REQUIRE_APPROVAL]


def test_identical_iban_typed_only_by_user_is_not_tainted() -> None:
    # User messages do not call add(); the value alone is not a flow violation.
    taint = TaintStore()
    assert taint.check_egress("s", "transfer_funds", TRANSFER, {"iban": IBAN}, FlowCfg()) == []
    taint.add("other", "read_document", ["untrusted"], IBAN)
    assert taint.check_egress("s", "transfer_funds", TRANSFER, {"iban": IBAN}, FlowCfg()) == []


def test_untrusted_context_requires_approval_even_without_value_copy() -> None:
    taint = TaintStore()
    taint.add("s", "read_document", ["untrusted"], "x")
    findings = taint.check_egress("s", "transfer_funds", TRANSFER, {"iban": IBAN}, FlowCfg())
    assert [f.control_id for f in findings] == ["flow.untrusted_before_irreversible"]
    assert findings[0].action == Action.REQUIRE_APPROVAL
    assert taint.check_egress("s", "send_email", SEND, {"body": "hello"}, FlowCfg()) == []


@pytest.mark.parametrize("rule,action", [("block", Action.BLOCK), ("monitor", Action.MONITOR), ("approval", Action.REQUIRE_APPROVAL)])
def test_f4_obeys_policy_action(rule: str, action: Action) -> None:
    taint = TaintStore()
    taint.add("s", "read_document", ["untrusted"], "")
    cfg = FlowCfg(rules=FlowRules(untrusted_before_irreversible=rule))
    assert taint.check_egress("s", "transfer_funds", TRANSFER, {}, cfg)[0].action == action


def test_f1_only_applies_to_egress_f2_only_to_target_args() -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret"], TOKEN)
    assert taint.check_egress("s", "local", ToolCfg(), {"body": TOKEN}, FlowCfg()) == []
    taint.clear("s")
    taint.add("s", "read_document", ["untrusted"], IBAN)
    assert taint.check_egress("s", "send_email", SEND, {"body": IBAN, "to": "ops@bank.example"}, FlowCfg()) == []
    assert taint.check_egress("s", "send_email", SEND, {"to": IBAN}, FlowCfg())[0].control_id == "flow.untrusted_target"


def test_all_nested_argument_leaves_and_numeric_values_are_checked() -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret"], "pesel: 44051401359")
    for args in ({"body": {"attachments": ["hello", {"id": 44051401359}]}}, {"id": 44051401359}):
        assert taint.check_egress("s", "send_email", SEND, args, FlowCfg())[0].control_id == "flow.secret_egress"


@pytest.mark.parametrize("minimum,copied,blocked", [(6, 5, False), (6, 6, True), (11, 10, False), (11, 11, True), (12, 11, False), (12, 12, True), (18, 17, False), (18, 18, True), (24, 20, False)])
def test_min_chars_controls_general_shingle_match(minimum: int, copied: int, blocked: bool) -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret"], TOKEN)
    findings = taint.check_egress("s", "send_email", SEND, {"body": TOKEN[:copied]}, FlowCfg(min_chars=minimum))
    assert bool(findings) == blocked


@pytest.mark.parametrize("value", ["12345678", "person@bank.example", IBAN])
def test_explicit_entities_keep_contract_minima_independent_of_shingles(value: str) -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret"], value)
    assert taint.check_egress("s", "send_email", SEND, {"body": value}, FlowCfg(min_chars=80))


def test_shingle_runs_cannot_be_assembled_across_separate_tool_results() -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret"], TOKEN[:12])
    taint.add("s", "lookup_customer", ["secret"], TOKEN[1:13])
    assert taint.check_egress("s", "send_email", SEND, {"body": TOKEN[:13]}, FlowCfg(min_chars=13)) == []


def test_flow_disabled_clear_labels_copies_and_hash_only_storage() -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret", "internal"], TOKEN)
    taint.add("s", "read_document", ["untrusted"], IBAN)
    assert TOKEN not in repr(taint.__dict__)
    assert IBAN not in repr(taint.__dict__)
    labels = taint.labels("s")
    assert labels == {"secret", "internal", "untrusted"}
    labels.clear()
    assert taint.labels("s") == {"secret", "internal", "untrusted"}
    assert taint.check_egress("s", "send_email", SEND, {"body": TOKEN}, FlowCfg(enabled=False)) == []
    taint.clear("s")
    taint.clear("missing")
    assert taint.labels("s") == set()
    assert taint.check_egress("s", "send_email", SEND, {"body": TOKEN}, FlowCfg()) == []


def test_internal_label_does_not_taint_values() -> None:
    taint = TaintStore()
    taint.add("s", "local", ["internal"], TOKEN)
    assert taint.check_egress("s", "send_email", SEND, {"body": TOKEN}, FlowCfg()) == []


@pytest.mark.parametrize("action", ["monitor", "redact"])
def test_f1_f2_obey_configured_actions(action: str) -> None:
    taint = TaintStore()
    taint.add("s", "lookup_customer", ["secret", "untrusted"], TOKEN)
    cfg = FlowCfg(rules=FlowRules(secret_to_egress=action, untrusted_value_as_target=action))
    findings = taint.check_egress("s", "send_email", SEND, {"to": TOKEN}, cfg)
    assert len(findings) == 2
    assert all(f.action == Action(action) for f in findings)


def test_encoded_source_is_protected_and_session_labels_are_thread_safe() -> None:
    taint = TaintStore()
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda label: taint.add("s", "lookup_customer", [label], quote(encode(TOKEN, "base64"))), ["secret", "untrusted", "internal"]))
    assert taint.labels("s") == {"secret", "untrusted", "internal"}
    assert taint.check_egress("s", "send_email", SEND, {"body": TOKEN}, FlowCfg())


@pytest.mark.parametrize("key", [KEY, "offline-call-signing-key"])
def test_signed_call_id_roundtrip_binds_all_provenance_fields(key: bytes | str) -> None:
    signed = sign_call_id("call-original.1", "lookup_customer", "session-żą", key)
    assert signed.startswith("call_w.")
    assert verify_call_id(signed, key) == "lookup_customer"
    _, payload, _ = signed.split(".")
    assert json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))) == ["call-original.1", "lookup_customer", "session-żą"]
    assert sign_call_id("call-original.1", "read_document", "session-żą", key) != signed
    assert sign_call_id("call-original.1", "lookup_customer", "other", key) != signed
    assert verify_call_id(signed, b"wrong-key") is None


@pytest.mark.parametrize("call_id", ["", "call_plain", "call_w.x", "call_w.x.y.z", "other.eA.abcd", "call_w.!!.abcd", None, 123, "x" * 20000])
def test_malformed_ids_are_untrusted(call_id: object) -> None:
    assert verify_call_id(call_id, KEY) is None


def test_forged_payload_or_signature_rejected() -> None:
    signed = sign_call_id("raw", "lookup_customer", "s", KEY)
    _, payload, signature = signed.split(".")
    forged_payload = base64.urlsafe_b64encode(json.dumps(["raw", "send_email", "s"]).encode()).decode().rstrip("=")
    assert verify_call_id(f"call_w.{forged_payload}.{signature}", KEY) is None
    assert verify_call_id(f"call_w.{payload}.{'0' * 64}", KEY) is None
    assert verify_call_id(f"call_w.{payload}.é", KEY) is None


@pytest.mark.parametrize("data", [{"tool": "lookup_customer"}, ["raw", "tool"], ["raw", "tool", 123], ["raw", "", "s"]])
def test_even_authenticated_malformed_payload_rejected(data: object) -> None:
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    signature = hmac.new(KEY, payload.encode(), hashlib.sha256).hexdigest()
    assert verify_call_id(f"call_w.{payload}.{signature}", KEY) is None
