# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_permission
from ...database import get_db
from . import _composite_key, _get_cache, _set_cache, router


@router.get("/search")
async def global_search(
    q: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Recherche globale sur nodes, packages, containers, CVEs."""
    cache_key = _composite_key("search", q=q)
    cached = _get_cache(cache_key)
    if cached:
        return cached

    pattern = f"%{q}%"

    nodes = await db.execute(
        text("""
        SELECT id, hostname, type, os FROM nodes
        WHERE hostname ILIKE :q OR os ILIKE :q
        LIMIT 10
    """),
        {"q": pattern},
    )

    pkgs = await db.execute(
        text("""
        SELECT pc.name, pc.version, n.hostname, n.id AS node_id
        FROM packages p
        JOIN package_catalog pc ON pc.id = p.package_id
        JOIN nodes n ON n.id = p.node_id
        WHERE pc.name ILIKE :q
        LIMIT 10
    """),
        {"q": pattern},
    )

    conts = await db.execute(
        text("""
        SELECT c.name, ci.image, n.hostname, n.id AS node_id
        FROM containers c
        JOIN container_images ci ON ci.id = c.image_id
        JOIN nodes n ON n.id = c.node_id
        WHERE c.name ILIKE :q OR ci.image ILIKE :q
        LIMIT 10
    """),
        {"q": pattern},
    )

    cves = await db.execute(
        text("""
        SELECT cve_id, severity, cvss_score, target, target_type, node_id
        FROM v_all_cves WHERE cve_id ILIKE :q
        LIMIT 10
    """),
        {"q": pattern},
    )

    result = {
        "nodes": [dict(r._mapping) for r in nodes],
        "packages": [dict(r._mapping) for r in pkgs],
        "containers": [dict(r._mapping) for r in conts],
        "cves": [dict(r._mapping) for r in cves],
    }
    _set_cache(cache_key, result)
    return result
