"""
AgentGuard time utilities — §0.4

All timestamps are UTC RFC 3339 with microseconds and 'Z'.
Durations use time.perf_counter_ns(); exposed as ms float rounded to 3 decimals.
"""

from __future__ import annotations

import datetime
import time


def utcnow() -> str:
    """Return current UTC time as RFC 3339 string with microsecond precision and Z suffix."""
    dt = datetime.datetime.now(datetime.timezone.utc)
    # isoformat gives +00:00; we need Z
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def perf_counter_ns() -> int:
    """Return monotonic nanosecond counter for duration measurements."""
    return time.perf_counter_ns()


def duration_ms(start_ns: int, end_ns: int) -> float:
    """Compute elapsed milliseconds rounded to 3 decimal places."""
    return round((end_ns - start_ns) / 1_000_000, 3)


def monotonic() -> float:
    """Return time.monotonic() for TTL enforcement (§1.7 F-13)."""
    return time.monotonic()
