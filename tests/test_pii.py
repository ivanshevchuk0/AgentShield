from __future__ import annotations

import base64
from statistics import median
from time import perf_counter

import pytest

from app.guardrails.normalize import views
from app.guardrails.pii import luhn, redact, scan, valid_iban, valid_nip, valid_pesel
from app.models import Action, Finding
from app.policy import PiiCfg


@pytest.mark.parametrize("value,expected", [("44051401359", True), ("44051401358", False), ("00000000000", False), ("4405140135", False), ("440514013599", False), ("４４０５１４０１３５９", False), ("a4051401359", False), ("", False)])
def test_pesel_validation(value: str, expected: bool) -> None:
    assert valid_pesel(value) is expected


@pytest.mark.parametrize("prefix", ["4434010135", "4402310135", "4400000135", "4413140135"])
def test_pesel_rejects_checksum_valid_impossible_dates(prefix: str) -> None:
    check = (-sum(int(c) * w for c, w in zip(prefix, (1,3,7,9,1,3,7,9,1,3)))) % 10
    assert not valid_pesel(prefix + str(check))


@pytest.mark.parametrize("month", ["01", "21", "41", "61", "81"])
def test_pesel_all_centuries(month: str) -> None:
    prefix = "04" + month + "140135"
    check = (-sum(int(c) * w for c, w in zip(prefix, (1,3,7,9,1,3,7,9,1,3)))) % 10
    assert valid_pesel(prefix + str(check))


@pytest.mark.parametrize("value,expected", [("8567346215", True), ("8567346216", False), ("0000000000", False), ("856734621", False), ("85673462155", False), ("856-734-62-15", False), ("", False)])
def test_nip_validation(value: str, expected: bool) -> None:
    assert valid_nip(value) is expected


@pytest.mark.parametrize("value", ["PL61109010140000071219812874", "PL61 1090 1014 0000 0712 1981 2874", "DE89370400440532013000", "GB82 WEST 1234 5698 7654 32", "FR1420041010050500013M02606", "pl61109010140000071219812874"])
def test_iban_validation(value: str) -> None:
    assert valid_iban(value)


@pytest.mark.parametrize("value", ["PL61109010140000071219812875", "DE89370400440532013001", "PL6110901014000007121981287", "ZZ61109010140000071219812874", "PLxx109010140000071219812874", "", "😀" * 28, "PL61" + "0" * 10000])
def test_iban_rejects_invalid(value: str) -> None:
    assert not valid_iban(value)


@pytest.mark.parametrize("value,expected", [("4111111111111111", True), ("5555555555554444", True), ("79927398713", True), ("378282246310005", True), ("4111111111111112", False), ("0000000000000000", False), ("4111 1111 1111 1111", False), ("", False), ("a111111111111111", False)])
def test_luhn(value: str, expected: bool) -> None:
    assert luhn(value) is expected


@pytest.mark.parametrize("entity,value", [
    ("PESEL", "44051401359"), ("PESEL", "440514 01359"), ("PESEL", "440514\u200b01359"),
    ("PESEL", "4 4 0 5 1 4 0 1 3 5 9"), ("PESEL", "４４０５１４０１３５９"),
    ("NIP", "8567346215"), ("NIP", "856-734-62-15"),
    ("IBAN", "PL61109010140000071219812874"), ("IBAN", "PL61 1090 1014 0000 0712 1981 2874"),
    ("IBAN", "DE89370400440532013000"), ("IBAN", "GB82 WEST 1234 5698 7654 32"),
    ("CREDIT_CARD", "4111111111111111"), ("CREDIT_CARD", "4111 1111 1111 1111"),
    ("EMAIL", "alice.smith+bank@example.co.uk"), ("PHONE", "+48 123 456 789"),
    ("PHONE", "123-456-789"), ("PHONE", "+1 (212) 555-1234"),
])
def test_exact_original_spans_and_redaction(entity: str, value: str) -> None:
    text = "Prefix: " + value + "; suffix."
    found = scan(text, views(text), PiiCfg(entities=[entity]))
    originals = [f for f in found if f.via == "original"]
    assert len(originals) == 1
    finding = originals[0]
    assert finding.control_id == "pii." + entity.lower()
    assert finding.start == len("Prefix: ") and finding.end == len("Prefix: " + value)
    assert text[finding.start:finding.end] == value
    assert finding.action == Action.REDACT and finding.owasp == "LLM02"
    assert "*" in finding.evidence and value not in finding.evidence
    assert redact(text, found) == "Prefix: [" + entity + "]; suffix."


@pytest.mark.parametrize("value", ["44051401358", "8567346216", "PL61109010140000071219812875", "4111111111111112"])
def test_bad_checksums_allowed_by_default(value: str) -> None:
    assert scan(value, views(value), PiiCfg()) == []


@pytest.mark.parametrize("valid", ["44051401359", "8567346215"])
def test_every_other_check_digit_allowed(valid: str) -> None:
    for digit in "0123456789":
        if digit != valid[-1]:
            value = valid[:-1] + digit
            assert not scan(value, views(value), PiiCfg())


@pytest.mark.parametrize("text", ["a44051401359z", "994405140135999", "440514 x 01359", "not an email: person@localhost", "numbers 440514\n01359", "No personal data here.", ""])
def test_boundaries_and_unrelated_digits(text: str) -> None:
    assert scan(text, views(text), PiiCfg()) == []


@pytest.mark.parametrize("encoding", ["base64", "hex"])
def test_decoded_no_original_span(encoding: str) -> None:
    value = "44051401359"
    encoded = base64.b64encode(value.encode()).decode() if encoding == "base64" else value.encode().hex()
    text = "encoded: " + encoded
    found = scan(text, views(text), PiiCfg(entities=["PESEL"]))
    assert len(found) == 1
    assert found[0].via == encoding and found[0].start is None and found[0].end is None
    assert redact(text, found) == text


def test_repeat_spans_and_view_deduplication() -> None:
    text = "44051401359, 44051401359; NDQwNTE0MDEzNTk="
    found = scan(text, views(text), PiiCfg(entities=["PESEL"]))
    assert len(found) == 2 and all(f.via == "original" for f in found)
    assert redact(text, found) == "[PESEL], [PESEL]; NDQwNTE0MDEzNTk="


def test_config_and_adjacent_different_numbers() -> None:
    text = "44051401359 8567346215, user@example.org"
    assert not scan(text, views(text), PiiCfg(enabled=False))
    assert not scan(text, views(text), PiiCfg(entities=[]))
    found = scan(text, views(text), PiiCfg(action="monitor", entities=["NIP"]))
    assert len(found) == 1 and found[0].action == Action.MONITOR
    found = scan(text, [], PiiCfg(action="block", entities=["PESEL", "NIP", "EMAIL"]))
    assert len(found) == 3 and all(f.action == Action.BLOCK for f in found)
    assert redact(text, found) == "[PESEL] [NIP], [EMAIL]"


def test_redaction_handles_overlaps_invalid_and_unsorted_spans() -> None:
    found = [Finding("pii.pesel", Action.REDACT, start=3, end=7),
             Finding("pii.phone", Action.REDACT, start=1, end=5),
             Finding("pii.email", Action.REDACT),
             Finding("pii.nip", Action.REDACT, start=-1, end=2),
             Finding("pii.nip", Action.REDACT, start=9, end=99),
             Finding("pii.email", Action.REDACT, start=7, end=9)]
    assert redact("0123456789", found) == "0[PHONE][EMAIL]9"


@pytest.mark.parametrize("text", ["a" * 4096, "1" * 4096, "1 " * 2048, ("user@example.org; 44051401359; " * 140)[:4096], ("PL61 " + "a " * 2045)[:4096]])
def test_pii_scan_is_linear_on_adversarial_input(text: str) -> None:
    candidates = views(text)
    cfg = PiiCfg()
    durations = []
    for _ in range(15):
        start = perf_counter()
        scan(text, candidates, cfg)
        durations.append(perf_counter() - start)
    assert median(durations) < 0.010  # catastrophic backtracking would take seconds
