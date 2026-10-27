# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...audit import log_action, validate_uuid
from ...auth import require_permission
from ...database import get_db
from ...models.schemas import EnvironmentPatch
from ...utils.sql import where_clause
from . import _get_cache, _set_cache, router


@router.get("/nodes/list")
async def list_nodes_light(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Lightweight node list for dropdowns — no aggregates."""
    cached = _get_cache("nodes_list")
    if cached:
        return cached
    rows = await db.execute(
        text("SELECT id, hostname FROM nodes WHERE is_active = true ORDER BY hostname")
    )
    result = {"items": [dict(r._mapping) for r in rows]}
    _set_cache("nodes_list", result)
    return result


@router.get("/nodes")
async def list_nodes(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    type: str | None = None,
    os: str | None = None,
    active: bool | None = None,
    environment: str | None = None,
    hostname: str | None = None,
    search: str | None = Query(None, max_length=200),
    sort_by: str | None = None,
    sort_dir: str = Query("asc"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    offset = (page - 1) * per_page
    where_clauses = []
    params: dict = {"limit": per_page, "offset": offset}

    if type:
        where_clauses.append("n.type LIKE :type")
        params["type"] = f"%{type}%"
    if os:
        where_clauses.append("n.os = :os")
        params["os"] = os
    if active is not None:
        where_clauses.append("n.is_active = :active")
        params["active"] = active
    if environment:
        where_clauses.append("n.environment = :env")
        params["env"] = environment
    if hostname:
        where_clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    if search:
        # Hostname is intentionally excluded — covered by `#filter-node` (?hostname=).
        where_clauses.append(
            "(n.type ILIKE :q OR n.environment ILIKE :q OR n.os ILIKE :q)"
        )
        params["q"] = f"%{search}%"

    where = where_clause(where_clauses)

    _SORT_MAP = {
        "hostname": "n.hostname",
        "env": "n.environment",
        "os": "n.os",
        "pkgs": "package_count",
        "containers": "container_count",
        "cve_host": "cve_package_count",
        "cve_ctr": "cve_container_count",
        "cve_critical": "cve_critical_count",
        "last_seen": "n.last_seen",
    }
    direction = "DESC" if sort_dir == "desc" else "ASC"
    order = (
        f"{_SORT_MAP[sort_by]} {direction}, n.hostname"
        if sort_by in _SORT_MAP
        else "n.hostname"
    )

    count_result = await db.execute(
        text(f"SELECT COUNT(*) FROM nodes n {where}"), params
    )
    total = count_result.scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT * FROM v_node_summary n {where}
        ORDER BY {order}
        LIMIT :limit OFFSET :offset
    """),
        params,
    )
    items = [dict(r._mapping) for r in rows]
    return {"items": items, "total": total, "page": page, "per_page": per_page}


@router.put("/nodes/{node_id}/environment")
async def set_node_environment(
    node_id: str,
    patch: EnvironmentPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("read", "w")),
):
    validate_uuid(node_id, "node_id")
    valid = ("production", "staging", "development", "lab")
    if patch.environment not in valid:
        return {"error": f"environment must be one of {valid}"}
    await db.execute(
        text("UPDATE nodes SET environment = :env WHERE id = CAST(:id AS uuid)"),
        {"env": patch.environment, "id": node_id},
    )
    await log_action(
        db,
        actor=actor,
        action="set_environment",
        target_type="node",
        target_id=node_id,
        detail={"environment": patch.environment},
    )
    await db.commit()
    return {"status": "ok"}


@router.get("/nodes/{node_id}")
async def get_node(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    validate_uuid(node_id, "node_id")
    row = await db.execute(
        text("SELECT * FROM v_node_summary WHERE id = :nid"), {"nid": node_id}
    )
    node = row.mappings().first()
    if not node:
        return {"error": "not found"}

    pkgs = await db.execute(
        text("""
        SELECT pc.name, pc.version, pc.arch
        FROM packages p
        JOIN package_catalog pc ON pc.id = p.package_id
        WHERE p.node_id = :nid ORDER BY pc.name
    """),
        {"nid": node_id},
    )

    conts = await db.execute(
        text("""
        SELECT c.name, ci.image, ci.tag, c.status
        FROM containers c
        JOIN container_images ci ON ci.id = c.image_id
        WHERE c.node_id = :nid ORDER BY c.name
    """),
        {"nid": node_id},
    )

    cves = await db.execute(
        text("""
        SELECT * FROM v_all_cves
        WHERE node_id = :nid
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
            END,
            cvss_score DESC NULLS LAST
        LIMIT 100
    """),
        {"nid": node_id},
    )

    return {
        "node": dict(node),
        "packages": [dict(r._mapping) for r in pkgs],
        "containers": [dict(r._mapping) for r in conts],
        "cves": [dict(r._mapping) for r in cves],
    }
