"""
Grant model — stub for §7.

Full grant semantics defined in §7; hub only needs GrantStore.match/consume (§0.11).
"""

from __future__ import annotations

from pydantic import BaseModel


class Grant(BaseModel):
    """Stub grant model — full definition in §7."""

    grant_id: str
    run_id: str
    fingerprint: str = ""
    remaining_uses: int = 0
