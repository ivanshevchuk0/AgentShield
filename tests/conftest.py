"""Shared fixtures: a fresh gateway per test on a temp copy of the policy (stub judge, offline)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "backend"


def _test_policy_text() -> str:
    text = (BACKEND / "policy.yaml").read_text(encoding="utf-8")
    # offline + deterministic judge; a short timeout keeps judge-down tests fast
    text = text.replace("backend: openrouter      #", "backend: stub      #", 1)
    if "backend: stub" not in text:
        text = text.replace("  backend: openrouter", "  backend: stub", 1)
    text = text.replace("  timeout_ms: 1200", "  timeout_ms: 300", 1)
    assert "backend: stub" in text, "could not switch semantic.backend to stub"
    return text


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    work = tmp_path / "policy"
    work.mkdir()
    if (BACKEND / "feeds").exists():
        shutil.copytree(BACKEND / "feeds", work / "feeds")
    path = work / "policy.yaml"
    path.write_text(_test_policy_text(), encoding="utf-8")
    return path


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture
def app(policy_file: Path, data_dir: Path, monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_AUDIT_KEY", "test-audit-key-0123456789")
    monkeypatch.setenv("AGENTSHIELD_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from app.main import create_app

    return create_app(policy_path=policy_file, data_dir=data_dir)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app, headers={"X-Admin-Token": "test-admin-token"}) as c:
        yield c


@pytest.fixture
def gateway(app):
    return app.state.gateway
