# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Safe SQL clause builders — prevent structural injection."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings


async def set_statement_timeout(db: AsyncSession, profile_or_ms: str | int) -> None:
    """Cap the current transaction's statement_timeout via SET LOCAL.

    Opt-in per-endpoint defense in depth. The global default
    statement_timeout stays at 0 (disabled) because too many legitimate
    reads can drift over a tight cap; long-running endpoints call this
    helper to declare their own ceiling.

    Accepts either:
      - "batch" -> `pg_statement_timeout_batch_ms` (5 min default)
      - "long"  -> `pg_statement_timeout_long_ms`  (30 min default)
      - an explicit int (milliseconds)

    Must be called inside a transaction (the SET is `LOCAL` so it
    reverts on COMMIT/ROLLBACK). Calling at the very top of a handler
    is the canonical pattern.
    """
    if profile_or_ms == "batch":
        ms = settings.pg_statement_timeout_batch_ms
    elif profile_or_ms == "long":
        ms = settings.pg_statement_timeout_long_ms
    elif isinstance(profile_or_ms, int):
        ms = profile_or_ms
    else:
        raise ValueError(f"set_statement_timeout: unknown profile {profile_or_ms!r}")
    await db.execute(text(f"SET LOCAL statement_timeout = {int(ms)}"))


def where_clause(clauses: list[str]) -> str:
    """Build a WHERE clause from a list of safe, hardcoded condition strings.

    Each clause MUST be a static string with named parameters (e.g. "col = :val").
    Never pass user input as a clause — only parameterized conditions.
    """
    return "WHERE " + " AND ".join(clauses) if clauses else ""


_DIRECTIONS = {"asc": "ASC", "desc": "DESC"}


def order_clause(
    sort_by: str | None,
    sort_map: dict[str, str],
    sort_dir: str = "asc",
    default: str = "",
) -> str:
    """Build ORDER BY from a whitelist map. Ignores unknown sort keys.

    sort_map: user-facing names → SQL expressions (e.g. {"hostname": "n.hostname"}).
    """
    direction = _DIRECTIONS.get(sort_dir, "ASC")
    if sort_by and sort_by in sort_map:
        return f"ORDER BY {sort_map[sort_by]} {direction}"
    return f"ORDER BY {default}" if default else ""
