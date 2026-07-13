"""
db/database.py — SQLite connection management

Uses aiosqlite for async access. The DB file lives at:
  gui/db/reporter.db   (relative to this file, created on first startup)

Call `init_db()` once at application startup.
Call `get_db()` as a FastAPI dependency to get a per-request connection.
"""

from __future__ import annotations

import aiosqlite
from pathlib import Path

_DB_PATH = Path(__file__).parent / "reporter.db"
_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


async def init_db() -> None:
    """
    Create all tables if they don't exist and apply any missing column migrations.
    Safe to call on every startup.
    """
    schema = _SCHEMA_PATH.read_text(encoding="utf-8")
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.executescript(schema)
        await db.commit()

        # ── Column migrations ─────────────────────────────────────────
        # ALTER TABLE ADD COLUMN is safe to run on existing DBs.
        # Add new columns here when schema.sql adds them.
        migrations = [
            ("scans", "scan_type",    "TEXT NOT NULL DEFAULT 'prowler_aws'"),
            ("scans", "tenant_domain","TEXT NOT NULL DEFAULT ''"),
            ("scans", "m365_environment", "TEXT NOT NULL DEFAULT 'commercial'"),
        ]
        for table, column, definition in migrations:
            try:
                await db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                )
                await db.commit()
            except Exception:
                pass  # column already exists — safe to ignore


async def get_db():
    """
    FastAPI dependency. Yields an open aiosqlite connection with
    row_factory set so rows behave like dicts.
    """
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        yield db