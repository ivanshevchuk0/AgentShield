"""Every documented launch command must point at an importable app factory."""

import importlib
import re
from pathlib import Path

import pytest
from fastapi import FastAPI

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["Dockerfile", "Makefile", "README.md"])
def test_launch_command_targets_the_factory(name, tmp_path, monkeypatch):
    targets = re.findall(r"uvicorn (--factory )?(app\.[\w.]+):(\w+)", (ROOT / name).read_text())
    assert targets, f"no uvicorn command in {name}"
    monkeypatch.setenv("AGENTSHIELD_DATA_DIR", str(tmp_path))
    for factory, module, attr in targets:
        assert factory, f"{name}: {module}:{attr} needs --factory (main.py has no module-level app)"
        assert isinstance(getattr(importlib.import_module(module), attr)(), FastAPI)
