"""Email simulator; deliberately performs no network or filesystem operations."""

from __future__ import annotations


def send_email(to: str, subject: str, body: str) -> str:
    """Acknowledge a simulated send; recipient policy is enforced by the gateway."""
    if not isinstance(to, str) or not to.strip():
        raise ValueError("to must be a nonempty string")
    if not isinstance(subject, str) or not isinstance(body, str):
        raise ValueError("subject and body must be strings")
    return "queued"
