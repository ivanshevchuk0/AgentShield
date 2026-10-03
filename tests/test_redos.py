"""Every shipped guardrail regex on 10 KiB ASCII near-miss inputs, offline.

Discover compiled module patterns (including constructed injection expressions)
and literal inline re calls via AST; compile feed patterns through the real
validator. A wall-clock alarm prevents a future catastrophic pattern hanging CI.
"""
from __future__ import annotations

import ast
import inspect
import re
import signal
from pathlib import Path
from time import perf_counter

import pytest
import yaml

from app.guardrails import injection, normalize, pii, secrets, signatures

MODULES = (normalize, pii, secrets, injection, signatures)
FEED = Path(__file__).resolve().parents[1] / "backend/feeds/signatures.yaml"
SIZE = 10 * 1024
LIMIT_S = 0.050


def _compiled(value, label):
    if isinstance(value, re.Pattern):
        yield label, value
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            yield from _compiled(item, f"{label}[{i}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _compiled(item, f"{label}.{key}")


def _patterns():
    for module in MODULES:
        prefix = module.__name__.rsplit(".", 1)[-1]
        seen = set()
        for name, value in vars(module).items():
            for label, pattern in _compiled(value, f"{prefix}.{name}"):
                key = pattern.pattern, pattern.flags
                if key not in seen:
                    seen.add(key)
                    yield label, pattern
        for node in ast.walk(ast.parse(inspect.getsource(module))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                    and node.func.attr in {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                continue
            pattern = re.compile(node.args[0].value)
            key = pattern.pattern, pattern.flags
            if key not in seen:
                seen.add(key)
                yield f"{prefix}.inline:{node.lineno}", pattern
    for row in yaml.safe_load(FEED.read_text(encoding="utf-8")):
        yield "feed." + row["id"], signatures._safe_regex(row["pattern"])


PATTERNS = list(_patterns())


def _input(prefix: str, repeated: str, suffix: str = "!") -> str:
    available = SIZE - len(prefix) - len(suffix)
    return prefix + (repeated * (available // len(repeated) + 1))[:available] + suffix


ADVERSARIAL = {
    "alnum": _input("", "a"),
    "digits": _input("", "9"),
    "base64_padding": _input("", "a", "===!"),
    "split_letters": _input("", "a."),
    "email_local": _input("", "a", "@!"),
    "email_domains": _input("a@", "a.", "-!"),
    "iban_spaces": _input("PL61", " ", "1!"),
    "generic_assignment": _input("api_key", " ", "=\"a!"),
    "dsn_fields": _input("server=", "uid=user;pwd=", "!"),
    "jwt": _input("eyJ", "a.a", ".!"),
    "connstr": _input("postgres://", "a", ":password@!"),
    "repeated_override": _input("", "ignore all previous ", "instruction!"),
    "exfil": _input("", "send ", "to http:/!"),
    "pickle_whitespace": _input("pickle.", " ", "load!"),
    "shell_pipe": _input("", "curl a| ", "bas!"),
    "markdown_unclosed": _input("", "![a](https://", "!"),
    "traversal_near_miss": _input("", ".%2e%2", "!"),
    "role_whitespace": _input("<|im_start|>", " ", "syste!"),
    "jndi_whitespace": _input("${", " ", "jnd!"),
}


@pytest.fixture(scope="module")
def regex_alarm():
    def expired(signum, frame):
        raise TimeoutError("guardrail regex exceeded the 50 ms wall-clock limit")

    previous = signal.signal(signal.SIGALRM, expired)
    yield
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, previous)


@pytest.mark.parametrize("label,pattern", PATTERNS, ids=[label for label, _ in PATTERNS])
@pytest.mark.parametrize("input_name,text", ADVERSARIAL.items(), ids=list(ADVERSARIAL))
def test_regex_finishes_under_50_ms(label, pattern, input_name, text, regex_alarm):
    assert len(text.encode("ascii")) == SIZE
    started = perf_counter()
    signal.setitimer(signal.ITIMER_REAL, LIMIT_S)
    try:
        # Scan all matches, not just a cheap success at the start. fullmatch also
        # exercises metadata validators' failure/backtracking at the final byte.
        for _ in pattern.finditer(text):
            pass
        pattern.fullmatch(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    elapsed = perf_counter() - started
    assert elapsed < LIMIT_S, f"{label}/{input_name}: {elapsed * 1000:.3f} ms"


def test_regex_inventory_includes_all_modules_inline_calls_and_feed():
    labels = [label for label, _ in PATTERNS]
    assert len(labels) == len(set(labels))
    for module in MODULES:
        prefix = module.__name__.rsplit(".", 1)[-1] + "."
        assert any(label.startswith(prefix) for label in labels), prefix
    rows = yaml.safe_load(FEED.read_text(encoding="utf-8"))
    assert {label for label in labels if label.startswith("feed.")} == {"feed." + row["id"] for row in rows}
    assert any(label.startswith("normalize.inline:") for label in labels)
    assert any(label.startswith("signatures.inline:") for label in labels)
