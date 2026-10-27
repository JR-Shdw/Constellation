# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_permission
from ...database import get_db
from ...utils.sql import where_clause
from . import router


@router.get("/packages")
async def list_packages(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    name: str | None = None,
    version: str | None = None,
    node_id: str | None = None,
    hostname: str | None = None,
    search: str | None = None,
    upgrade_only: bool = Query(False),
    sort_by: str | None = None,
    sort_dir: str = Query("asc"),
    group: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if search:
        clauses.append("(pc.name ILIKE :search OR n.hostname ILIKE :search)")
        params["search"] = f"%{search}%"
    if name:
        clauses.append("pc.name ILIKE :name")
        params["name"] = f"%{name}%"
    if version:
        clauses.append("pc.version ILIKE :version")
        params["version"] = f"%{version}%"
    if node_id:
        clauses.append("p.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if hostname:
        clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    if upgrade_only:
        clauses.append(
            "pa.available_ver IS NOT NULL AND pa.available_ver != pc.version"
        )
    where = where_clause(clauses)

    _SORT_MAP = {
        "name": "pc.name",
        "upgrade": "available_ver",
        "hosts": "host_count",
    }
    direction = "DESC" if sort_dir == "desc" else "ASC"
    order = (
        f"{_SORT_MAP[sort_by]} {direction}, pc.name"
        if sort_by in _SORT_MAP
        else "pc.name, pc.version"
    )

    # LEFT JOIN package_availability on the node's OS profile.
    # `cmdb_os_family(n.os)` keeps the matching logic aligned with
    # the Python `_detect_os_family` used by check_updates. The join is
    # nullable: a package on a node whose OS family isn't recognised
    # simply yields available_ver=NULL, same shape as the old per-node
    # column.
    _pkg_joins = (
        "FROM packages p"
        " JOIN package_catalog pc ON pc.id = p.package_id"
        " JOIN nodes n ON n.id = p.node_id"
        " LEFT JOIN package_availability pa"
        "   ON pa.package_id = p.package_id"
        "  AND pa.os_family  = cmdb_os_family(n.os)"
        "  AND pa.os_version = COALESCE(n.os_version, '')"
        "  AND pa.arch       = COALESCE(n.arch, '')"
    )

    if group:
        count_result = await db.execute(
            text(f"""
            SELECT COUNT(*) FROM (
                SELECT 1 {_pkg_joins}
                {where}
                GROUP BY pc.name, pc.version
            ) sub
        """),
            params,
        )
        total = count_result.scalar_one()

        rows = await db.execute(
            text(f"""
            SELECT pc.name, pc.version, pc.arch,
                   MAX(pa.available_ver) AS available_ver,
                   COUNT(*) AS host_count,
                   ARRAY_AGG(DISTINCT n.hostname ORDER BY n.hostname) AS hostnames,
                   MODE() WITHIN GROUP (ORDER BY n.os) AS os
            {_pkg_joins}
            {where}
            GROUP BY pc.name, pc.version, pc.arch
            ORDER BY {order}
            LIMIT :limit OFFSET :offset
        """),
            params,
        )
    else:
        count_result = await db.execute(
            text(f"SELECT COUNT(*) {_pkg_joins} {where}"),
            params,
        )
        total = count_result.scalar_one()

        rows = await db.execute(
            text(f"""
            SELECT p.id, pc.name, pc.version, pc.arch, pc.manager,
                   pa.available_ver, n.hostname, n.id AS node_id
            {_pkg_joins}
            {where}
            ORDER BY pc.name, n.hostname
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


@router.get("/packages/hosts")
async def package_hosts(
    name: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Liste des hôtes où un package est installé, enrichi CVE + upgrade."""
    rows = await db.execute(
        text("""
        SELECT pc.name, pc.version, pc.arch, pc.manager,
               pa.available_ver,
               n.hostname, n.id AS node_id,
               n.os, n.os_version, n.arch AS node_arch,
               COALESCE(cv.cve_count, 0) AS cve_count,
               cv.max_severity,
               cv.max_cvss,
               COALESCE(cv.has_fix, false) AS has_fix,
               COALESCE(cv.exploited, false) AS exploited,
               cv.cve_ids
        FROM packages p
        JOIN package_catalog pc ON pc.id = p.package_id
        JOIN nodes n ON n.id = p.node_id
        LEFT JOIN package_availability pa
               ON pa.package_id = p.package_id
              AND pa.os_family  = cmdb_os_family(n.os)
              AND pa.os_version = COALESCE(n.os_version, '')
              AND pa.arch       = COALESCE(n.arch, '')
        LEFT JOIN LATERAL (
            SELECT COUNT(*) AS cve_count,
                   (ARRAY_AGG(hp.severity ORDER BY
                       CASE hp.severity
                           WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                           WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
                       END)
                       FILTER (WHERE hp.severity IS NOT NULL))[1] AS max_severity,
                   MAX(cat.cvss_score) AS max_cvss,
                   BOOL_OR(hp.fix_status = 'fixed_available') AS has_fix,
                   BOOL_OR(COALESCE(cat.exploited, false)) AS exploited,
                   ARRAY_AGG(DISTINCT hp.cve_id ORDER BY hp.cve_id) AS cve_ids
            FROM cve_host_packages hp
            JOIN cve_catalog cat ON cat.cve_id = hp.cve_id
            WHERE hp.node_id = p.node_id
              AND hp.pkg_name = pc.name
              AND hp.status != 'resolved'
        ) cv ON true
        WHERE pc.name = :name
        ORDER BY n.hostname
    """),
        {"name": name},
    )
    return {"items": [dict(r._mapping) for r in rows]}
