"""Static safety checks for the dashboard in frontend/app (no browser, no network).

All server data contains attacker-controlled text by design, so the app must never turn strings
into markup or code, and index.html must stay compatible with a strict CSP (script-src 'self').
Vendored third-party modules in frontend/app/vendor/ are excluded from the source scan.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent / "frontend" / "app"
VENDOR_DIR = APP_DIR / "vendor"
INDEX = APP_DIR / "index.html"

BANNED = re.compile(
    r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML"
    r"|\beval\s*\(|new\s+Function\b"
)
SOURCE_SUFFIXES = {".js", ".mjs", ".html", ".css"}


def _app_sources() -> list[Path]:
    return sorted(
        p for p in APP_DIR.rglob("*")
        if p.is_file() and p.suffix in SOURCE_SUFFIXES and VENDOR_DIR not in p.parents
    )


def _all_js() -> list[Path]:
    return sorted(p for p in APP_DIR.rglob("*") if p.is_file() and p.suffix in {".js", ".mjs"})


class _IndexScan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, str | None]] = []
        self.inline_bodies: list[str] = []
        self.handlers: list[tuple[str, str]] = []
        self.stylesheets: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        for name, _ in attrs:
            if name.lower().startswith("on"):
                self.handlers.append((tag, name))
        if tag == "script":
            self.scripts.append(attr)
            self._in_script = True
        if tag == "link" and (attr.get("rel") or "").lower() == "stylesheet":
            self.stylesheets.append(attr.get("href") or "")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_bodies.append(data.strip())


def _scan_index() -> _IndexScan:
    scan = _IndexScan()
    scan.feed(INDEX.read_text(encoding="utf-8"))
    return scan


def _is_local(url: str) -> bool:
    return bool(url) and not re.match(r"^(?:[a-z][a-z0-9+.-]*:|//)", url, re.I)


def test_app_exists_with_vendored_libraries():
    assert INDEX.is_file(), "frontend/app/index.html missing"
    assert (APP_DIR / "app.js").is_file()
    assert any(VENDOR_DIR.glob("*.js")), "vendored Preact/htm/signals modules missing"


def test_no_html_injection_or_dynamic_code_in_app_sources():
    sources = _app_sources()
    assert sources, "no app sources found"
    hits = []
    for path in sources:
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if BANNED.search(line):
                hits.append(f"{path.relative_to(APP_DIR)}:{no}: {line.strip()[:120]}")
    assert not hits, "banned DOM/code sinks:\n" + "\n".join(hits)


def test_index_has_no_inline_script_or_event_handlers():
    scan = _scan_index()
    assert not scan.inline_bodies, f"inline <script> body found: {scan.inline_bodies[0][:80]!r}"
    assert not scan.handlers, f"inline event handler attributes: {scan.handlers}"
    assert scan.scripts, "index.html loads no script"


def test_index_references_only_local_scripts_and_styles():
    scan = _scan_index()
    for attrs in scan.scripts:
        src = attrs.get("src") or ""
        assert _is_local(src), f"non-local or missing script src: {src!r}"
        assert attrs.get("type") == "module", f"script {src!r} must be an ES module"
    for href in scan.stylesheets:
        assert _is_local(href), f"non-local stylesheet: {href!r}"


def test_modules_import_only_relative_paths():
    pattern = re.compile(r"""^\s*(?:import|export)\b[^'"]*?\bfrom\s*['"]([^'"]+)['"]""", re.M)
    bad = []
    for path in _app_sources():
        if path.suffix not in {".js", ".mjs"}:
            continue
        for spec in pattern.findall(path.read_text(encoding="utf-8")):
            if not spec.startswith(("./", "../")):
                bad.append(f"{path.relative_to(APP_DIR)}: {spec}")
    assert not bad, "imports must be relative (no CDN, no bare specifiers):\n" + "\n".join(bad)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("path", _all_js(), ids=lambda p: str(p.relative_to(APP_DIR)))
def test_javascript_parses(path):
    proc = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
