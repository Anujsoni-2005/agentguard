"""
AgentGuard ID generation — §0.4

IDs: f"{prefix}_{ULID()}" — 26-char Crockford base32, lexicographically
time-sortable.  Each entity type has a dedicated prefix.
"""

from __future__ import annotations

from ulid import ULID


def generate_id(prefix: str) -> str:
    """Generate a prefixed ULID identifier."""
    return f"{prefix}_{ULID()!s}"


def run_id() -> str:
    return generate_id("run")


def action_id() -> str:
    return generate_id("act")


def approval_id() -> str:
    return generate_id("apr")


def grant_id() -> str:
    return generate_id("grt")


def finding_id() -> str:
    return generate_id("fnd")


def request_id() -> str:
    return generate_id("req")


def advisory_id() -> str:
    return generate_id("adv")
