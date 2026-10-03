"""Payment simulator; never moves money or persists financial data."""

from __future__ import annotations

import math


def transfer_funds(iban: str, amount: float, reference: str) -> str:
    """Acknowledge a simulated transfer; limits and approval belong to the gateway."""
    if not isinstance(iban, str) or not iban.strip():
        raise ValueError("iban must be a nonempty string")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not 0 < amount < math.inf:
        raise ValueError("amount must be finite and positive")
    if not isinstance(reference, str):
        raise ValueError("reference must be a string")
    return "transfer queued"
