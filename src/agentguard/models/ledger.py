"""
Ledger record model — §0.7
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel


class LedgerRecord(BaseModel):
    """A single entry in the tamper-evident audit ledger. §0.7"""

    v: Literal[1] = 1
    idx: int                                                  # 0-based global, gapless
    ts: str                                                   # UTC RFC 3339
    run_id: str | None = None
    event_type: str                                           # from LEDGER_EVENT_TYPES registry
    actor: str                                                # "hub" | "agent" | "human:<id>" | "proxy" | "system"
    action_id: str | None = None
    payload: dict[str, Any]                                   # redacted
    prev_hash: str                                            # 64 hex chars; genesis = "0"*64
    hash: str                                                 # sha256_hex(prev_hash.encode() + canonical_json(record_without_hash))
