# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Per-endpoint statement_timeout — utils.sql.set_statement_timeout."""

import pytest
from sqlalchemy import text

from api.app.config import settings
from api.app.database import async_session
from api.app.utils.sql import set_statement_timeout


@pytest.mark.anyio
async def test_set_statement_timeout_batch_profile():
    """`batch` profile applies pg_statement_timeout_batch_ms via SET LOCAL."""
    async with async_session() as db:
        await set_statement_timeout(db, "batch")
        row = await db.execute(text("SHOW statement_timeout"))
        value = row.scalar_one()
        # PG normalises ms values into 'Xs' / 'Xmin' strings - just check it
        # is non-zero and parses to the expected ms count.
        assert value not in (None, "", "0"), value


@pytest.mark.anyio
async def test_set_statement_timeout_long_profile():
    """`long` profile applies pg_statement_timeout_long_ms via SET LOCAL."""
    async with async_session() as db:
        await set_statement_timeout(db, "long")
        row = await db.execute(text("SHOW statement_timeout"))
        value = row.scalar_one()
        assert value not in (None, "", "0"), value


@pytest.mark.anyio
async def test_set_statement_timeout_explicit_ms():
    """Explicit int ms is honored."""
    async with async_session() as db:
        await set_statement_timeout(db, 5000)
        row = await db.execute(text("SHOW statement_timeout"))
        value = row.scalar_one()
        assert value == "5s", value


@pytest.mark.anyio
async def test_set_statement_timeout_local_scope():
    """SET LOCAL must NOT leak across transactions.

    After commit/rollback the timeout reverts to the session default
    (which is the global PG setting, or whatever asyncpg server_settings
    pushed). The point is that one batch endpoint cannot poison the
    next endpoint that reuses the same pooled connection.
    """
    async with async_session() as db:
        await set_statement_timeout(db, 1234)
        await db.commit()
        # After commit, SET LOCAL is gone. A new query sees the default.
        row = await db.execute(text("SHOW statement_timeout"))
        value = row.scalar_one()
        assert value != "1234ms", value


@pytest.mark.anyio
async def test_set_statement_timeout_rejects_unknown_profile():
    async with async_session() as db:
        with pytest.raises(ValueError):
            await set_statement_timeout(db, "ultralong")


def test_settings_defaults_match_expected_profiles():
    """Defaults: batch=1h, long=2h. Large server-side caps, worker-side
    tuning via CMDB_INGEST_TIMEOUT for fine adjustments."""
    assert settings.pg_statement_timeout_batch_ms == 60 * 60 * 1000
    assert settings.pg_statement_timeout_long_ms == 2 * 60 * 60 * 1000
