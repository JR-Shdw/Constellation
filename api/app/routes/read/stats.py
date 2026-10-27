# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import asyncio

from fastapi import Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_permission
from ...database import async_session, get_db
from . import _get_cache, _set_cache, router


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    cached = _get_cache("stats")
    if cached:
        return cached

    excl_rows = await db.execute(
        text("""
        SELECT key, value FROM alert_settings
        WHERE key IN ('cve_count_exclude_medium', 'cve_count_exclude_low')
        """)
    )
    excl_settings = {r.key: r.value for r in excl_rows}
    exclude_medium = excl_settings.get("cve_count_exclude_medium") == "true"
    exclude_low = excl_settings.get("cve_count_exclude_low") == "true"
    sev_filter = ""
    if exclude_medium:
        sev_filter += " AND severity != 'medium'"
    if exclude_low:
        sev_filter += " AND severity != 'low'"

    row = await db.execute(
        text(f"""
        WITH hp AS (
            SELECT COUNT(*) FILTER (
                WHERE TRUE{sev_filter}) AS total,
                   COUNT(*) FILTER (WHERE severity = 'critical') AS crit,
                   COUNT(*) FILTER (WHERE severity = 'high') AS high,
                   COUNT(*) FILTER (WHERE severity = 'medium') AS med,
                   COUNT(*) FILTER (WHERE (severity = 'low'
                       OR fix_status IN ('will_not_fix', 'not_affected'))
                       {sev_filter}
                   ) AS noise
            FROM cve_host_packages
            WHERE status = 'open'
        ),
        cc AS (
            SELECT COUNT(*) FILTER (
                WHERE TRUE{sev_filter}) AS total,
                   COUNT(*) FILTER (WHERE severity = 'critical') AS crit,
                   COUNT(*) FILTER (WHERE severity = 'high') AS high,
                   COUNT(*) FILTER (WHERE severity = 'medium') AS med,
                   COUNT(*) FILTER (WHERE (severity = 'low'
                       OR fix_status IN ('will_not_fix', 'not_affected'))
                       {sev_filter}
                   ) AS noise
            FROM cve_containers
            WHERE status = 'open'
        ),
        bk AS (
            SELECT COUNT(*) FILTER (
                WHERE status = 'success' AND NOT overdue) AS ok,
                   COUNT(*) FILTER (WHERE status = 'failure') AS failed,
                   COUNT(*) FILTER (WHERE overdue) AS overdue
            FROM v_backup_latest
        ),
        sc AS (
            SELECT COUNT(*) FILTER (
                WHERE last_trivy_host_scan IS NOT NULL) AS scanned,
                   COUNT(*) FILTER (WHERE last_trivy_host_scan IS NULL
                       OR last_trivy_host_scan < NOW() - INTERVAL '25 hours'
                   ) AS stale
            FROM v_scan_status
        ),
        mc AS (
            SELECT COUNT(*) AS total
            FROM misconfigurations WHERE status = 'open'
        ),
        sd AS (
            SELECT COUNT(*) AS total
            FROM secrets_detected WHERE status = 'open'
        )
        SELECT
            (SELECT COUNT(*) FROM nodes) AS nodes_total,
            (SELECT COUNT(*) FROM nodes WHERE is_active) AS nodes_active,
            (SELECT COUNT(*) FROM packages) AS packages_total,
            (SELECT COUNT(*) FROM containers) AS containers_total,
            hp.crit + cc.crit AS cves_critical,
            hp.high + cc.high AS cves_high,
            hp.high AS cves_host_high,
            cc.high AS cves_container_high,
            hp.med + cc.med AS cves_medium,
            hp.med AS cves_host_medium,
            cc.med AS cves_container_medium,
            hp.total + cc.total AS cves_total,
            hp.total - hp.noise AS cves_host_total,
            hp.crit AS cves_host_critical,
            cc.total - cc.noise AS cves_container_total,
            cc.crit AS cves_container_critical,
            bk.ok AS backups_ok,
            bk.failed AS backups_failed,
            bk.overdue AS backups_overdue,
            sc.scanned AS trivy_host_scanned,
            sc.stale AS trivy_host_stale,
            (SELECT COUNT(*) FROM repositories
                WHERE update_available) AS repos_update_available,
            (SELECT COUNT(*) FROM repositories) AS repos_total,
            (SELECT COUNT(*) FROM automation_log
                WHERE status = 'pending') AS automation_pending,
            mc.total AS misconf_open,
            sd.total AS secrets_open
        FROM hp, cc, bk, sc, mc, sd
    """)
    )
    result = dict(row.mappings().first())
    result["cve_count_exclude_medium"] = exclude_medium
    result["cve_count_exclude_low"] = exclude_low

    from ..settings import feature_enabled

    if not await feature_enabled("cve", db):
        for k in list(result.keys()):
            excl_keys = ("cve_count_exclude_medium", "cve_count_exclude_low")
            if "cve" in k and k not in excl_keys:
                result[k] = 0
        result["feature_cve_enabled"] = False
    else:
        result["feature_cve_enabled"] = True

    if not await feature_enabled("backup", db):
        for k in ("backups_ok", "backups_failed", "backups_overdue"):
            result[k] = 0
        result["feature_backup_enabled"] = False
    else:
        result["feature_backup_enabled"] = True

    _set_cache("stats", result)
    return result


async def _q_one(sql: str, params: dict) -> list[dict]:
    """Run a query in its own short-lived session and return rows as dicts."""
    async with async_session() as s:
        rows = await s.execute(text(sql), params)
        return [dict(r._mapping) for r in rows]


async def _q_first(sql: str, params: dict) -> dict:
    """Run a query in its own short-lived session and return the first row."""
    async with async_session() as s:
        row = await s.execute(text(sql), params)
        return dict(row.mappings().first())


@router.get("/stats/trends")
async def get_stats_trends(
    days: int = Query(30, ge=1, le=365),
    _: str = Depends(require_permission("read", "r")),
):
    """Daily time series for dashboard sparklines.

    The five sub-queries are independent and run concurrently on
    distinct sessions — releases each pool connection as soon as the
    individual query finishes instead of pinning one for the whole
    handler duration.
    """
    cache_key = f"trends:{days}"
    cached = _get_cache(cache_key)
    if cached:
        return cached

    params = {"days": days}

    if days <= 1:
        bucket = "hour"
    elif days <= 90:
        bucket = "day"
    else:
        bucket = "week"

    cves_sql = f"""
        WITH periods AS (
            SELECT date_trunc('{bucket}', d)::date AS day
            FROM generate_series(
                NOW() - make_interval(days => :days),
                NOW(), '1 {bucket}'
            ) d
        ),
        resolved AS (
            SELECT date_trunc('{bucket}', updated_at)::date AS day,
                   COUNT(*) AS resolved,
                   COUNT(*) FILTER (WHERE src = 'host')
                       AS resolved_host,
                   COUNT(*) FILTER (WHERE src = 'container')
                       AS resolved_container
            FROM (
                SELECT cs.updated_at, 'host' AS src
                FROM cve_status cs
                JOIN cve_host_packages hp
                    ON hp.node_id = cs.node_id
                    AND hp.cve_id = cs.cve_id
                WHERE cs.status IN (
                    'mitigated','resolved',
                    'false_positive','accepted_risk'
                )
                AND cs.updated_at > NOW()
                    - make_interval(days => :days)
                UNION ALL
                SELECT cs.updated_at, 'container' AS src
                FROM cve_status cs
                JOIN cve_containers cc
                    ON cc.node_id = cs.node_id
                    AND cc.cve_id = cs.cve_id
                WHERE cs.status IN (
                    'mitigated','resolved',
                    'false_positive','accepted_risk'
                )
                AND cs.updated_at > NOW()
                    - make_interval(days => :days)
            ) rs
            GROUP BY 1
        ),
        detected AS (
            SELECT date_trunc('{bucket}', scanned_at)::date AS day,
                   COUNT(*) AS detected,
                   COUNT(*) FILTER (
                       WHERE severity = 'critical'
                   ) AS detected_critical,
                   COUNT(*) FILTER (WHERE src = 'host')
                       AS detected_host,
                   COUNT(*) FILTER (WHERE src = 'host'
                       AND severity = 'critical')
                       AS detected_host_critical,
                   COUNT(*) FILTER (WHERE src = 'container')
                       AS detected_container,
                   COUNT(*) FILTER (WHERE src = 'container'
                       AND severity = 'critical')
                       AS detected_container_critical
            FROM (
                SELECT scanned_at, severity, 'host' AS src
                FROM cve_host_packages
                WHERE scanned_at > NOW()
                    - make_interval(days => :days)
                UNION ALL
                SELECT scanned_at, severity, 'container' AS src
                FROM cve_containers
                WHERE scanned_at > NOW()
                    - make_interval(days => :days)
            ) u
            GROUP BY 1
        )
        SELECT p.day,
               COALESCE(d.detected, 0) AS detected,
               COALESCE(d.detected_critical, 0)
                   AS detected_critical,
               COALESCE(d.detected_host, 0) AS detected_host,
               COALESCE(d.detected_host_critical, 0)
                   AS detected_host_critical,
               COALESCE(d.detected_container, 0)
                   AS detected_container,
               COALESCE(d.detected_container_critical, 0)
                   AS detected_container_critical,
               COALESCE(r.resolved, 0) AS resolved,
               COALESCE(r.resolved_host, 0)
                   AS resolved_host,
               COALESCE(r.resolved_container, 0)
                   AS resolved_container
        FROM periods p
        LEFT JOIN detected d ON d.day = p.day
        LEFT JOIN resolved r ON r.day = p.day
        ORDER BY p.day
    """

    stock_sql = """
        SELECT
            COUNT(*) FILTER (WHERE status = 'open')
                AS open_total,
            COUNT(*) FILTER (WHERE status = 'open'
                AND severity = 'critical') AS open_critical,
            COUNT(*) FILTER (WHERE status = 'open'
                AND severity = 'high') AS open_high,
            COUNT(*) FILTER (WHERE status != 'open')
                AS resolved_total,
            COUNT(*) FILTER (WHERE status = 'open'
                AND src = 'host') AS open_host,
            COUNT(*) FILTER (WHERE status = 'open'
                AND src = 'host' AND severity = 'critical')
                AS open_host_critical,
            COUNT(*) FILTER (WHERE status = 'open'
                AND src = 'host' AND severity = 'high')
                AS open_host_high,
            COUNT(*) FILTER (WHERE status = 'open'
                AND src = 'container') AS open_container,
            COUNT(*) FILTER (WHERE status = 'open'
                AND src = 'container' AND severity = 'critical')
                AS open_container_critical,
            COUNT(*) FILTER (WHERE status = 'open'
                AND src = 'container' AND severity = 'high')
                AS open_container_high
        FROM (
            SELECT status, severity, 'host' AS src
            FROM cve_host_packages
            UNION ALL
            SELECT status, severity, 'container' AS src
            FROM cve_containers
        ) all_cves
    """

    hb_sql = f"""
        WITH periods AS (
            SELECT date_trunc('{bucket}', d)::date AS day
            FROM generate_series(
                NOW() - make_interval(days => :days),
                NOW(), '1 {bucket}'
            ) d
        )
        SELECT p.day,
               COALESCE(h.up, 0) AS up,
               COALESCE(h.down, 0) AS down
        FROM periods p
        LEFT JOIN (
            SELECT date_trunc('{bucket}', checked_at)::date
                AS day,
                   COUNT(*) FILTER (WHERE status = 'up')
                       AS up,
                   COUNT(*) FILTER (WHERE status = 'down')
                       AS down
            FROM node_heartbeats
            WHERE checked_at > NOW()
                - make_interval(days => :days)
            GROUP BY 1
        ) h ON h.day = p.day
        ORDER BY p.day
    """

    bk_sql = f"""
        WITH periods AS (
            SELECT date_trunc('{bucket}', d)::date AS day
            FROM generate_series(
                NOW() - make_interval(days => :days),
                NOW(), '1 {bucket}'
            ) d
        )
        SELECT p.day,
               COALESCE(b.ok, 0) AS ok,
               COALESCE(b.failed, 0) AS failed
        FROM periods p
        LEFT JOIN (
            SELECT date_trunc('{bucket}', finished_at)::date
                AS day,
                   COUNT(*) FILTER (
                       WHERE status = 'success') AS ok,
                   COUNT(*) FILTER (
                       WHERE status != 'success') AS failed
            FROM backup_runs
            WHERE finished_at > NOW()
                - make_interval(days => :days)
            GROUP BY 1
        ) b ON b.day = p.day
        ORDER BY p.day
    """

    au_sql = f"""
        WITH periods AS (
            SELECT date_trunc('{bucket}', d)::date AS day
            FROM generate_series(
                NOW() - make_interval(days => :days),
                NOW(), '1 {bucket}'
            ) d
        )
        SELECT p.day,
               COALESCE(a.executed, 0) AS executed,
               COALESCE(a.errors, 0) AS errors
        FROM periods p
        LEFT JOIN (
            -- automation_log statuses are completed/failed/ignored/… (see the
            -- table CHECK); 'executed'/'error' were never written, so this
            -- sparkline was permanently zero.
            SELECT date_trunc('{bucket}', created_at)::date
                AS day,
                   COUNT(*) FILTER (
                       WHERE status = 'completed') AS executed,
                   COUNT(*) FILTER (
                       WHERE status = 'failed') AS errors
            FROM automation_log
            WHERE created_at > NOW()
                - make_interval(days => :days)
            GROUP BY 1
        ) a ON a.day = p.day
        ORDER BY p.day
    """

    cves, cve_stock, heartbeat, backups, automation = await asyncio.gather(
        _q_one(cves_sql, params),
        _q_first(stock_sql, {}),
        _q_one(hb_sql, params),
        _q_one(bk_sql, params),
        _q_one(au_sql, params),
    )

    result = {
        "days": days,
        "cves": cves,
        "cve_stock": cve_stock,
        "heartbeat": heartbeat,
        "backups": backups,
        "automation": automation,
    }
    _set_cache(cache_key, result)
    return result
