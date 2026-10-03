"""Offline demo tools. Authorization, flow rules and approvals belong to the gateway."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .database import lookup_customer
from .email import send_email
from .files import read_document
from .payments import transfer_funds

REGISTRY: dict[str, Callable[[dict[str, Any]], str]] = {
    "lookup_customer": lambda args: lookup_customer(**args),
    "read_document": lambda args: read_document(**args),
    "send_email": lambda args: send_email(**args),
    "transfer_funds": lambda args: transfer_funds(**args),
}


def run_tool(name: str, args: dict[str, Any]) -> str:
    """Run a known demo tool; unknown names raise KeyError, bad arguments raise errors."""
    if not isinstance(name, str):
        raise TypeError("tool name must be a string")
    if not isinstance(args, dict) or any(not isinstance(key, str) for key in args):
        raise TypeError("tool arguments must be an object with string keys")
    return REGISTRY[name](args)
