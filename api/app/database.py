# DO NOT REMOVE: SPDX header + copyright are part of the Apache-2.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Constellation · Author: shdw · License: Apache-2.0
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Async SQLAlchemy session factory — PostgreSQL via asyncpg.

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
See: NOTICE, LICENSE
"""

import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from .config import settings

_pool_args: dict = (
    {"poolclass": NullPool}
    if "pytest" in sys.modules
    else {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_pre_ping": True,
        "pool_recycle": settings.db_pool_recycle,
        "pool_timeout": settings.db_pool_timeout,
    }
)

# Tag every connection with `application_name=cmdb_api` so it shows up
# in pg_stat_activity and our /api/v1/health/db endpoint can group
# pool consumers (cmdb_api vs sync-opencve vs sync-wazuh vs ansible).
# Belt-and-braces timeouts: even if PG server-side config is wrong, the
# client enforces its own kill switches against zombie transactions.
_connect_args = {
    "server_settings": {
        "application_name": "cmdb_api",
        "idle_in_transaction_session_timeout": str(settings.pg_idle_in_tx_timeout_ms),
        "statement_timeout": str(settings.pg_statement_timeout_ms),
    }
}

engine = create_async_engine(
    settings.database_url, connect_args=_connect_args, **_pool_args
)

async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with async_session() as session:
        yield session


async def db_activity_snapshot(slow_query_seconds: int = 5) -> dict:
    """Snapshot of `pg_stat_activity` — server-side connection state.

    Complements `pool_snapshot()` (which only sees this worker's
    SQLAlchemy pool) with what postgres itself reports for ALL
    connections from any client (4 uvicorn workers + sync containers
    + ansible scripts + interactive psql sessions). Used by
    `/api/v1/health/db` and the periodic activity logger.

    Returns:
      states:    {"active": N, "idle": N, "idle in transaction": N, ...}
      total:     total connections to this database
      slow:      list of queries running ≥ slow_query_seconds (truncated)
      blocked:   list of queries currently waiting on a lock
      by_source: counts grouped by application_name (best-effort)
    """
    sql = """
    SELECT
        pid,
        state,
        wait_event_type,
        wait_event,
        application_name,
        client_addr::text AS client_addr,
        usename,
        backend_type,
        EXTRACT(EPOCH FROM (NOW() - state_change))::int AS state_age_s,
        EXTRACT(EPOCH FROM (NOW() - query_start))::int AS query_age_s,
        EXTRACT(EPOCH FROM (NOW() - xact_start))::int AS xact_age_s,
        substr(query, 1, 200) AS query_excerpt,
        pg_blocking_pids(pid) AS blocked_by
    FROM pg_stat_activity
    WHERE datname = current_database()
      AND pid <> pg_backend_pid()
    """
    async with async_session() as s:
        rows = await s.execute(text(sql))
        records = [dict(r._mapping) for r in rows]

    states: dict = {}
    by_source: dict = {}
    slow: list = []
    blocked: list = []
    for r in records:
        st = r.get("state") or "unknown"
        states[st] = states.get(st, 0) + 1
        src = r.get("application_name") or r.get("backend_type") or "unknown"
        by_source[src] = by_source.get(src, 0) + 1
        # active query running too long
        if (
            r.get("state") == "active"
            and (r.get("query_age_s") or 0) >= slow_query_seconds
        ):
            slow.append(
                {
                    "pid": r["pid"],
                    "age_s": r["query_age_s"],
                    "wait": r.get("wait_event"),
                    "client": r.get("client_addr"),
                    "app": r.get("application_name"),
                    "query": r.get("query_excerpt"),
                }
            )
        # blocked
        if r.get("blocked_by"):
            blocked.append(
                {
                    "pid": r["pid"],
                    "blocked_by": r["blocked_by"],
                    "age_s": r.get("query_age_s"),
                    "query": r.get("query_excerpt"),
                }
            )
        # idle-in-transaction stuck — these hold locks without working
        if r.get("state") == "idle in transaction" and (r.get("xact_age_s") or 0) >= 60:
            slow.append(
                {
                    "pid": r["pid"],
                    "age_s": r["xact_age_s"],
                    "wait": "idle-in-tx",
                    "client": r.get("client_addr"),
                    "app": r.get("application_name"),
                    "query": r.get("query_excerpt"),
                }
            )

    return {
        "total": len(records),
        "states": states,
        "by_source": by_source,
        "slow": slow,
        "blocked": blocked,
    }


def pool_snapshot() -> dict:
    """Return a snapshot of the SQLAlchemy connection pool state.

    Used by `/api/v1/health/pool` and the periodic pool logger to
    diagnose connection leaks. Counters are best-effort (the
    underlying NullPool used by tests doesn't track them) and the
    snapshot is taken without acquiring any pool slot.
    """
    pool = engine.pool
    info: dict = {
        "class": type(pool).__name__,
        "size": getattr(pool, "size", lambda: None)(),
        "checked_in": getattr(pool, "checkedin", lambda: None)(),
        "checked_out": getattr(pool, "checkedout", lambda: None)(),
        "overflow": getattr(pool, "overflow", lambda: None)(),
    }
    try:
        size = info["size"] or 0
        checked_out = info["checked_out"] or 0
        overflow = info["overflow"] or 0
        info["total_capacity"] = size + settings.db_max_overflow
        info["in_use"] = checked_out
        info["free"] = info["total_capacity"] - checked_out
        info["overflow_used"] = max(overflow, 0)
    except Exception:
        pass
    return info
