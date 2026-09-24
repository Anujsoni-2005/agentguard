"""
Database connection and migration — §1.3

SQLite with WAL mode, foreign keys ON, synchronous=NORMAL, busy_timeout=5000.
Migrations are applied at startup. The hub MUST refuse to start if the DB
version is newer than the code (§12.4).
"""

from __future__ import annotations

import os
from pathlib import Path

import aiosqlite
import structlog

from agentguard.timeutil import utcnow

logger = structlog.get_logger(__name__)

_SCHEMA_SQL = Path(__file__).parent / "schema.sql"


async def get_connection(db_path: str) -> aiosqlite.Connection:
    """Open an aiosqlite connection with required PRAGMAs."""
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    db = await aiosqlite.connect(db_path)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA busy_timeout=5000")
    db.row_factory = aiosqlite.Row
    return db


async def apply_schema(db: aiosqlite.Connection) -> None:
    """
    Apply the schema if not already present.

    Uses schema_migrations table to track applied versions.
    On first run, creates all tables from schema.sql and records version 1.
    """
    # Check if schema_migrations exists
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    )
    row = await cursor.fetchone()

    if row is None:
        # First run — apply full schema
        logger.info("database.initializing", msg="Applying initial schema")
        sql = _SCHEMA_SQL.read_text(encoding="utf-8")
        await db.executescript(sql)
        await db.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (1, utcnow()),
        )
        await db.commit()
        logger.info("database.initialized", version=1)
    else:
        # Check current version
        cursor = await db.execute("SELECT MAX(version) FROM schema_migrations")
        version_row = await cursor.fetchone()
        current = version_row[0] if version_row and version_row[0] is not None else 0  # type: ignore[index]
        logger.info("database.version", current=current)
        # TODO(spec-gap): apply incremental migrations here when we have > 1 version
