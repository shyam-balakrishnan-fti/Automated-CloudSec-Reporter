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
    """Create all tables if they don't exist. Safe to call on every startup."""
    schema = _SCHEMA_PATH.read_text(encoding="utf-8")
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.executescript(schema)
        await db.commit()


async def get_db():
    """
    FastAPI dependency. Yields an open aiosqlite connection with
    row_factory set so rows behave like dicts.
    """
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        yield db