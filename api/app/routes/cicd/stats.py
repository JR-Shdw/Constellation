# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CI/CD overview stats."""

from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_permission
from ...database import get_db
from . import _get_cache, _set_cache, router


@router.get("/stats")
async def cicd_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "r")),
):
    """CI/CD overview stats."""
    cached = _get_cache("cicd_stats")
    if cached:
        return cached

    repos = await db.execute(text("SELECT COUNT(*) FROM cicd_repositories"))
    total_repos = repos.scalar() or 0

    stats = await db.execute(
        text("""
        SELECT
            COUNT(*)                                       AS total_runs_30d,
            COUNT(*) FILTER (WHERE status = 'success')     AS success_30d,
            COUNT(*) FILTER (WHERE status = 'failure')     AS failure_30d,
            ROUND(
                100.0 * COUNT(*) FILTER (WHERE status = 'success')
                / NULLIF(COUNT(*), 0), 1
            )                                              AS success_rate_30d,
            ROUND(AVG(duration_secs) FILTER (WHERE duration_secs > 0))
                                                           AS avg_duration_30d
        FROM cicd_pipelines
        WHERE started_at >= NOW() - INTERVAL '30 days'
    """)
    )
    row = stats.mappings().first() or {}

    latest = await db.execute(
        text("""
        SELECT * FROM v_cicd_latest ORDER BY started_at DESC NULLS LAST
    """)
    )

    result = {
        "total_repos": total_repos,
        **dict(row),
        "latest_per_repo": [dict(r._mapping) for r in latest],
    }
    _set_cache("cicd_stats", result)
    return result
