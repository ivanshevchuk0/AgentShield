"""Synthetic customer records: no database access and no real customer data."""

from __future__ import annotations

import json


def lookup_customer(customer_id: str) -> str:
    """Return a fresh JSON record, suitable for an OpenAI tool message."""
    if not isinstance(customer_id, str) or not customer_id.strip():
        raise ValueError("customer_id must be a nonempty string")
    return json.dumps({
        "customer_id": customer_id,
        "name": "Jan Kowalski",
        "pesel": "44051401359",
        "iban": "PL61109010140000071219812874",
        "balance": 12500.00,
    }, ensure_ascii=False)
