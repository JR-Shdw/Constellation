# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Package updates — packages with CVEs that have a fixed version available."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_permission
from ..database import get_db
from ..utils.sql import where_clause

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/pkg-updates", tags=["pkg-updates"])


@router.get("")
async def list_pkg_updates(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None),
    node_id: str | None = Query(None),
    hostname: str | None = Query(None),
    search: str | None = Query(None),
    fix_status: str | None = Query(None, description="fixed_available, unfixed, all"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("repositories", "r")),
):
    """Packages that have CVEs, grouped by package+installed_ver.

    Shows max severity, CVE count, fixed version if available,
    and which nodes are affected.
    """
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = ["hp.status != 'resolved'"]

    if severity:
        clauses.append("hp.severity = :sev")
        params["sev"] = severity
    if node_id:
        clauses.append("hp.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if hostname:
        clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    if search:
        clauses.append("(hp.pkg_name ILIKE :search OR hp.cve_id ILIKE :search)")
        params["search"] = f"%{search}%"
    if fix_status and fix_status != "all":
        clauses.append("hp.fix_status = :fstatus")
        params["fstatus"] = fix_status

    where = where_clause(clauses)
    join_nodes = "JOIN nodes n ON n.id = hp.node_id" if hostname else ""

    count_result = await db.execute(
        text(f"""
        SELECT COUNT(*) FROM (
            SELECT 1 FROM cve_host_packages hp
            {join_nodes}
            {where}
            GROUP BY hp.pkg_name, hp.installed_ver
        ) sub
        """),
        params,
    )
    total = count_result.scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT
            hp.pkg_name,
            hp.installed_ver,
            COUNT(DISTINCT hp.cve_id) AS cve_count,
            COUNT(DISTINCT hp.node_id) AS node_count,
            MAX(cat.cvss_score) AS max_cvss,
            (ARRAY_AGG(hp.severity ORDER BY
                CASE hp.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
                END)
                FILTER (WHERE hp.severity IS NOT NULL))[1] AS max_severity,
            MAX(hp.fixed_ver) FILTER (WHERE hp.fixed_ver IS NOT NULL
                AND hp.fixed_ver != '') AS fixed_ver,
            BOOL_OR(hp.fix_status = 'fixed_available') AS has_fix,
            BOOL_OR(COALESCE(cat.exploited, false)) AS exploited,
            ARRAY_AGG(DISTINCT n.hostname ORDER BY n.hostname) AS hostnames,
            ARRAY_AGG(DISTINCT hp.cve_id ORDER BY hp.cve_id) AS cve_ids,
            MAX(hp.scanned_at) AS last_seen
        FROM cve_host_packages hp
        JOIN cve_catalog cat ON cat.cve_id = hp.cve_id
        JOIN nodes n ON n.id = hp.node_id
        {where}
        GROUP BY hp.pkg_name, hp.installed_ver
        ORDER BY
            BOOL_OR(COALESCE(cat.exploited, false)) DESC,
            MAX(cat.cvss_score) DESC NULLS LAST,
            COUNT(DISTINCT hp.cve_id) DESC
        LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/summary")
async def pkg_updates_summary(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("repositories", "r")),
):
    """Quick stats for the updates page header."""
    row = await db.execute(
        text("""
        SELECT
            COUNT(DISTINCT hp.pkg_name) AS packages_with_cves,
            COUNT(DISTINCT hp.cve_id) AS total_cves,
            COUNT(DISTINCT hp.pkg_name)
                FILTER (WHERE hp.fix_status = 'fixed_available') AS fixable,
            COUNT(DISTINCT hp.pkg_name)
                FILTER (WHERE hp.severity = 'critical'
                    AND hp.status != 'resolved') AS critical,
            COUNT(DISTINCT hp.pkg_name)
                FILTER (WHERE cat.exploited AND hp.status != 'resolved') AS exploited
        FROM cve_host_packages hp
        JOIN cve_catalog cat ON cat.cve_id = hp.cve_id
        WHERE hp.status != 'resolved'
        """)
    )
    return dict(row.mappings().first())
