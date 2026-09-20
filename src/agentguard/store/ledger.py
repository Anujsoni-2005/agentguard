"""
Audit Ledger Writer — §8.3 (MVP)

Implements the LedgerWriter protocol (§0.7) with:
- JSONL file format with hash chaining (§8.3.1)
- Single writer with asyncio.Lock (§8.3.2)
- Durable/non-durable append semantics
- Startup recovery for crash-truncated records (§8.3.4)
- Segment rotation (§8.3.1)

The ledger is the tamper-evident audit trail. Every record's hash depends
on the previous record's hash, forming an unbroken chain.

Genesis: prev_hash = "0" * 64
Hash = sha256_hex(prev_hash.encode("ascii") + canonical_json(record_without_hash_field))
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import structlog

from agentguard.canon import canonical_json, sha256_hex
from agentguard.models.ledger import LedgerRecord
from agentguard.timeutil import utcnow

logger = structlog.get_logger(__name__)

GENESIS_HASH = "0" * 64
MAX_PAYLOAD_BYTES = 256 * 1024  # §8.3.1: total line <= 256 KiB


def _compute_hash(prev_hash: str, record_dict: dict[str, Any]) -> str:
    """
    Compute ledger record hash per §8.3.1.

    hash = sha256_hex(prev_hash.encode("ascii") + canonical_json(record_without_hash_field))
    The record still contains prev_hash but NOT hash itself.
    """
    without_hash = {k: v for k, v in record_dict.items() if k != "hash"}
    return sha256_hex(prev_hash.encode("ascii") + canonical_json(without_hash))


def _truncate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Replace oversized payload values with truncation markers. §8.3.1"""
    serialized = canonical_json(payload)
    if len(serialized) <= MAX_PAYLOAD_BYTES:
        return payload
    # Truncate large values
    truncated = {}
    for k, v in payload.items():
        val_bytes = canonical_json(v)
        if len(val_bytes) > 8192:
            truncated[k] = {
                "_truncated": True,
                "sha256": sha256_hex(val_bytes),
                "size": len(val_bytes),
            }
        else:
            truncated[k] = v
    return truncated


def _segment_path(ledger_dir: str, segment_num: int) -> str:
    """Generate segment file path: ledger-000001.jsonl"""
    return os.path.join(ledger_dir, f"ledger-{segment_num:06d}.jsonl")


class FileLedgerWriter:
    """
    Production ledger writer — §8.3.

    Thread-safety: single writer enforced by asyncio.Lock.
    Durability: durable=True → os.fsync before returning.
    """

    def __init__(
        self,
        ledger_dir: str,
        *,
        fsync_policy: str = "always",
        segment_max_bytes: int = 268_435_456,
    ) -> None:
        self._ledger_dir = ledger_dir
        self._fsync_policy = fsync_policy
        self._segment_max_bytes = segment_max_bytes
        self._lock = asyncio.Lock()
        self._fd: int = -1
        self._segment_num: int = 1
        self._segment_path: str = ""
        self._segment_size: int = 0
        self._last_hash: str = GENESIS_HASH
        self._next_idx: int = 0
        self._last_fsync_ns: int = 0
        self._index_batch: list[tuple[int, str | None, str, str, str | None, int]] = []

        os.makedirs(ledger_dir, exist_ok=True)

    async def initialize(self) -> None:
        """
        Initialize or recover the ledger. §8.3.4

        1. Find existing segments and load state from the last one.
        2. Recover truncated records from crashes.
        3. Verify tail hash chain.
        """
        segments = sorted(Path(self._ledger_dir).glob("ledger-*.jsonl"))

        if not segments:
            # Fresh start — open first segment
            self._segment_num = 1
            self._open_segment()
            logger.info("ledger.initialized", segment=1, idx=0)
            return

        # Load from the last segment
        last_segment = segments[-1]
        self._segment_num = int(last_segment.stem.split("-")[1])
        self._segment_path = str(last_segment)

        # Read all records from the last segment to rebuild state
        await self._recover_segment(last_segment)

        # Re-open for appending
        self._fd = os.open(
            self._segment_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        self._segment_size = os.path.getsize(self._segment_path)

        logger.info(
            "ledger.recovered",
            segment=self._segment_num,
            next_idx=self._next_idx,
            last_hash=self._last_hash[:16] + "...",
        )

    async def _recover_segment(self, path: Path) -> None:
        """
        Read segment, recover from truncated writes, rebuild state. §8.3.4
        """
        content = path.read_bytes()
        lines = content.split(b"\n")

        good_lines: list[bytes] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                # Verify hash chain
                expected_hash = _compute_hash(
                    record.get("prev_hash", GENESIS_HASH), record
                )
                if record.get("hash") != expected_hash:
                    logger.warning(
                        "ledger.hash_mismatch",
                        idx=record.get("idx"),
                        expected=expected_hash[:16],
                        got=record.get("hash", "")[:16],
                    )
                    break
                good_lines.append(line)
                self._last_hash = record["hash"]
                self._next_idx = record["idx"] + 1
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("ledger.truncated_record", error=str(exc))
                break

        # Truncate to last good line if needed (§8.3.4 step 1)
        good_content = b"\n".join(good_lines) + b"\n" if good_lines else b""
        if len(good_content) < len(content):
            truncated_bytes = len(content) - len(good_content)
            logger.warning("ledger.truncating", truncated_bytes=truncated_bytes)
            with open(path, "wb") as f:
                f.write(good_content)
                f.flush()
                os.fsync(f.fileno())

    def _open_segment(self) -> None:
        """Open a new ledger segment file."""
        if self._fd != -1:
            os.close(self._fd)
        self._segment_path = _segment_path(self._ledger_dir, self._segment_num)
        self._fd = os.open(
            self._segment_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        self._segment_size = 0

    def _maybe_rotate(self) -> None:
        """Rotate to a new segment if current exceeds max size. §8.3.1"""
        if self._segment_size >= self._segment_max_bytes:
            self._segment_num += 1
            self._open_segment()
            logger.info("ledger.rotated", segment=self._segment_num)

    async def append(
        self,
        *,
        run_id: str | None,
        event_type: str,
        actor: str,
        action_id: str | None,
        payload: dict[str, Any],
        durable: bool,
    ) -> LedgerRecord:
        """
        Append a record to the ledger. §8.3.2

        When durable=True, the record and all earlier records are guaranteed
        on disk (os.fsync) before this method returns.
        """
        async with self._lock:
            # Truncate oversized payloads
            safe_payload = _truncate_payload(payload)

            # Build record (without hash initially)
            rec_dict: dict[str, Any] = {
                "v": 1,
                "idx": self._next_idx,
                "ts": utcnow(),
                "run_id": run_id,
                "event_type": event_type,
                "actor": actor,
                "action_id": action_id,
                "payload": safe_payload,
                "prev_hash": self._last_hash,
            }

            # Compute hash
            rec_hash = _compute_hash(self._last_hash, rec_dict)
            rec_dict["hash"] = rec_hash

            # Serialize to canonical JSON + newline
            line = canonical_json(rec_dict) + b"\n"

            # Write (O_APPEND)
            offset = self._segment_size
            os.write(self._fd, line)
            self._segment_size += len(line)

            # Update state
            self._last_hash = rec_hash
            idx = self._next_idx
            self._next_idx += 1

            # Index batch entry
            self._index_batch.append(
                (idx, run_id, event_type, rec_dict["ts"], action_id, offset)
            )

            # Durability — §8.3.2
            now_ns = time.perf_counter_ns()
            should_fsync = durable or self._fsync_policy == "always"

            if not should_fsync:
                # Batch fsync: if > 100ms since last fsync, schedule one
                if (now_ns - self._last_fsync_ns) > 100_000_000:
                    should_fsync = True

            if should_fsync:
                os.fsync(self._fd)
                self._last_fsync_ns = now_ns

            # Check segment rotation
            self._maybe_rotate()

        # Build the LedgerRecord model to return
        record = LedgerRecord(**rec_dict)

        # TODO(spec-gap): publish to EventBus after releasing lock (§8.3.2)
        # TODO(spec-gap): checkpoint enqueue logic (§8.3.3)

        return record

    @property
    def next_idx(self) -> int:
        return self._next_idx

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def close(self) -> None:
        """Close the file descriptor."""
        if self._fd != -1:
            try:
                os.fsync(self._fd)
            except OSError:
                pass
            os.close(self._fd)
            self._fd = -1
