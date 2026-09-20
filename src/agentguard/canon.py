"""
AgentGuard canonical JSON and hashing — §0.4

The spec defines canonical JSON using stdlib json.dumps with exact separators.
We use that for hashing (byte-exact). orjson is used for *responses/ledger lines*
for speed, but canonical hashing always goes through this module.

Floats inside hashed objects MUST be rounded to 6 decimals before serialization.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _round_floats(obj: Any) -> Any:
    """Recursively round all floats to 6 decimal places for hashing."""
    if isinstance(obj, float):
        return round(obj, 6)
    if isinstance(obj, dict):
        return {k: _round_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round_floats(item) for item in obj]
    return obj


def canonical_json(obj: Any) -> bytes:
    """
    Produce canonical JSON bytes per §0.4.

    Uses stdlib json.dumps with sort_keys=True, separators=(",", ":"),
    ensure_ascii=False, allow_nan=False.
    """
    rounded = _round_floats(obj)
    return json.dumps(
        rounded,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    """Return SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(b).hexdigest()
