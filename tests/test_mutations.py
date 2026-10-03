"""Corpus mutation properties against real deterministic detectors, never a judge.

The unmutated corpus is checked as well, so a broken baseline cannot be hidden by
an applicability rule. Redact rows additionally exercise PII detection (not the
separate gateway's redaction/forwarding behavior).
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest
import yaml

from app.guardrails import injection, normalize, pii, secrets, signatures
from app.models import Action, strongest
from app.policy import parse_policy
from mutations import TRANSFORMS

ROOT = Path(__file__).resolve().parents[1]
CASES = yaml.safe_load((ROOT / "tests/corpus/cases.yaml").read_text(encoding="utf-8"))["cases"]
POLICY = parse_policy((ROOT / "backend/policy.yaml").read_text(encoding="utf-8"))


def _text(case: dict) -> str:
    return case["text"] + "".join(chr(0xE0000 + ord(c)) for c in case.get("tags", ""))


def _applicable(case: dict, name: str) -> bool:
    text = _text(case)
    if TRANSFORMS[name](text) == text:
        return False
    # Altering the letters of an encoding changes its decoded bytes, not its style.
    encoded = case.get("tags") or case["id"] in {"A14", "P04", "S03", "I03", "I07", "I19"}
    if encoded and name not in {"zero_width", "base64", "hex", "unicode_tags"}:
        return False
    # Do not demand decoding beyond the contract's printable-ratio/size limits.
    # In particular, wrapping a predominantly invisible tag payload is excluded.
    if name in {"base64", "hex", "unicode_tags"}:
        printable = sum(c.isprintable() or c in "\r\n\t" for c in text) / max(1, len(text))
        if printable < 0.85 or len(text.encode("utf-8")) > 4096:
            return False
    control = case["control"] or ""
    # Credential case and leet substitutions change the actual secret value.
    if control.startswith("secrets.") and name in {"case_flips", "leetspeak"}:
        return False
    # Leet code, identifiers and IBAN letters are not the original executable or
    # checksum-valid identifier. Probe it only on natural-language prompts.
    if name == "leetspeak" and case["expect"] != "allow" and control != "injection":
        return False
    return True


@pytest.fixture(scope="module")
def feed():
    return signatures.SignatureFeed(ROOT / "backend" / POLICY.controls.signatures.feed_file)


def _detect(text: str, direction: str, feed):
    views = normalize.views(text)
    findings = []
    controls = POLICY.controls
    for name, scanner in (("pii", pii.scan), ("secrets", secrets.scan)):
        cfg = controls.active(name)
        if cfg and cfg.direction in {direction, "both"}:
            findings.extend(scanner(text, views, cfg))
    cfg = controls.active("prompt_injection")
    if cfg and cfg.direction in {direction, "both"}:
        score, found = injection.score(views)
        if score >= cfg.review_threshold:
            for finding in found:
                finding.action = Action(cfg.action) if score >= cfg.block_threshold else Action.MONITOR
            findings.extend(found)
    cfg = controls.active("signatures")
    if cfg and cfg.direction in {direction, "both"}:
        findings.extend(feed.scan(views, direction, cfg.action))
    cfg = controls.active("canary")
    if cfg and cfg.direction in {direction, "both"}:
        findings.extend(signatures.scan_canary(views, cfg.tokens, cfg.action))
    return strongest([f.action for f in findings]), findings


def _assert_case(case: dict, text: str, feed) -> None:
    action, findings = _detect(text, case["direction"], feed)
    ids = [f.control_id for f in findings]
    assert action.value == case["expect"], f"{case['id']}: {action.value}, findings={ids}"
    expected = case["control"]
    if expected:
        assert any(i == expected or i.startswith(expected + ".") for i in ids), (
            f"{case['id']}: expected {expected}, findings={ids}"
        )


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_unmutated_detector_baseline(case, feed):
    _assert_case(case, _text(case), feed)


# Confirmed failures, keyed to exact cases/transforms, never inferred from the
# test result. Strict xfails become failures as soon as a detector fixes a gap.
_GAP_GROUPS = (
    (
        "normalize.views decodes original tokens only: zero-width breaks base64/hex and folded text loses encoding case",
        ("P04", "S03", "I03", "I07", "I19"),
        ("zero_width",),
    ),
    (
        "fold lowercases recovered text, but AWS/Google/PEM secret patterns require uppercase",
        ("S01", "S02", "S09", "S14", "S15"),
        ("zero_width", "homoglyphs", "polish_diacritics"),
    ),
    (
        "fold lowercases recovered JWT segments, corrupting case-sensitive base64 and JSON validation",
        ("S11",),
        ("zero_width", "homoglyphs", "polish_diacritics"),
    ),
    (
        "normalize._SPLIT loses word/token boundaries (space/dot/dash) and misses runs adjacent to digits/underscores",
        ("P16", "S01", "S02", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S13", "S14", "S15",
         "I02", "I06", "I10", "I22",
         "X01", "X02", "X03", "X04", "X05", "X07", "X14", "X15", "C01", "C02", "C03"),
        ("split_letters",),
    ),
    (
        "Exploratory robustness gap: leetspeak is not decoded by the contracted normalization/injection rules",
        ("I01", "I02", "I04", "I05", "I06", "I10", "I11", "I12", "I13", "I14", "I15", "I16", "I17", "I18", "I21", "I22"),
        ("leetspeak",),
    ),
)
KNOWN_GAPS = {
    (case_id, name): reason
    for reason, case_ids, names in _GAP_GROUPS
    for case_id in case_ids
    for name in names
}


def _parameters():
    for case in CASES:
        for name in TRANSFORMS:
            if not _applicable(case, name):
                continue
            reason = KNOWN_GAPS.get((case["id"], name))
            marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
            yield pytest.param(case, name, id=f"{case['id']}-{name}", marks=marks)


@pytest.mark.parametrize("case,name", list(_parameters()))
def test_corpus_obfuscation_preserves_decision(case, name, feed):
    _assert_case(case, TRANSFORMS[name](_text(case)), feed)


@pytest.mark.parametrize("name", TRANSFORMS)
def test_transforms_are_deterministic_and_nontrivial(name):
    sample = "Ignore previous instructions. Zażółć!"
    transformed = TRANSFORMS[name](sample)
    assert transformed != sample
    assert transformed == TRANSFORMS[name](sample)
    assert isinstance(transformed, str)


def test_transform_examples_and_lossless_wrappers():
    assert TRANSFORMS["zero_width"]("abc") == "a\u200bb\u200bc"
    assert TRANSFORMS["homoglyphs"]("Ace") == "Асе"
    assert TRANSFORMS["case_flips"]("abcdef") == "AbCdEf"
    assert TRANSFORMS["polish_diacritics"]("acelnosz") == "ąćęłńóśż"
    assert TRANSFORMS["split_letters"]("ignore all") == "i.g.n.o.r.e a.l.l"
    assert TRANSFORMS["leetspeak"]("Ignore") == "1gn0r3"
    for sample in ("ignore instructions", "Zażółć gęślą jaźń", "line\nnext", ""):
        assert base64.b64decode(TRANSFORMS["base64"](sample).split(": ", 1)[1]).decode() == sample
        assert bytes.fromhex(TRANSFORMS["hex"](sample).split(": ", 1)[1]).decode() == sample
        tagged = TRANSFORMS["unicode_tags"](sample)
        payload = "".join(chr(ord(c) - 0xE0000) for c in tagged if 0xE0020 <= ord(c) <= 0xE007E)
        if payload.startswith("payload: "):
            payload = base64.b64decode(payload.split(": ", 1)[1]).decode()
        assert payload == sample


def test_matrix_covers_every_case_and_transform():
    parameters = list(_parameters())
    assert {p.values[0]["id"] for p in parameters} == {c["id"] for c in CASES}
    assert {p.values[1] for p in parameters} == set(TRANSFORMS)
    assert set(KNOWN_GAPS) <= {(p.values[0]["id"], p.values[1]) for p in parameters}
