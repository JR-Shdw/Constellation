# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""History / diff — view recent changes across the CMDB."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_permission
from ..database import get_db

router = APIRouter(prefix="/api/v1/history", tags=["history"])


@router.get("")
async def get_history(
    days: int = Query(7, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Get infrastructure changes over the last N days.

    Returns new/updated nodes, packages, containers, CVEs,
    and workflow changes. Uses existing timestamps in the DB.
    """
    # New / recently seen nodes
    rows = await db.execute(
        text("""
        SELECT hostname, type, os, environment, first_seen, last_seen
        FROM nodes
        WHERE first_seen > NOW() - make_interval(days => :days)
        ORDER BY first_seen DESC
        """),
        {"days": days},
    )
    new_nodes = [dict(r._mapping) for r in rows]

    # Recently collected packages (new installs)
    rows = await db.execute(
        text("""
        SELECT pc.name, pc.version, n.hostname, p.collected_at
        FROM packages p
        JOIN package_catalog pc ON pc.id = p.package_id
        JOIN nodes n ON p.node_id = n.id
        WHERE p.collected_at > NOW() - make_interval(days => :days)
        ORDER BY p.collected_at DESC
        LIMIT 200
        """),
        {"days": days},
    )
    new_packages = [dict(r._mapping) for r in rows]

    # Recently collected containers
    rows = await db.execute(
        text("""
        SELECT c.name, ci.image, ci.tag, c.exposure, n.hostname, c.collected_at
        FROM containers c
        JOIN container_images ci ON ci.id = c.image_id
        JOIN nodes n ON c.node_id = n.id
        WHERE c.collected_at > NOW() - make_interval(days => :days)
        ORDER BY c.collected_at DESC
        LIMIT 200
        """),
        {"days": days},
    )
    new_containers = [dict(r._mapping) for r in rows]

    # Recent host CVEs detected
    rows = await db.execute(
        text("""
        SELECT h.cve_id, h.severity, h.pkg_name, h.status,
               n.hostname, h.scanned_at
        FROM cve_host_packages h JOIN nodes n ON h.node_id = n.id
        WHERE h.scanned_at > NOW() - make_interval(days => :days)
        ORDER BY h.scanned_at DESC
        LIMIT 200
        """),
        {"days": days},
    )
    new_host_cves = [dict(r._mapping) for r in rows]

    # Recent container CVEs detected
    rows = await db.execute(
        text("""
        SELECT c.cve_id, c.severity, c.pkg_name, c.status,
               n.hostname, c.scanned_at
        FROM cve_containers c JOIN nodes n ON c.node_id = n.id
        WHERE c.scanned_at > NOW() - make_interval(days => :days)
        ORDER BY c.scanned_at DESC
        LIMIT 200
        """),
        {"days": days},
    )
    new_container_cves = [dict(r._mapping) for r in rows]

    # CVE workflow changes (from audit_log)
    rows = await db.execute(
        text("""
        SELECT actor, action, target_type, target_id, detail, created_at
        FROM audit_log
        WHERE action IN ('set_cve_workflow', 'patch_host_finding',
                         'patch_container_finding')
          AND created_at > NOW() - make_interval(days => :days)
        ORDER BY created_at DESC
        LIMIT 100
        """),
        {"days": days},
    )
    workflow_changes = [dict(r._mapping) for r in rows]

    return {
        "days": days,
        "summary": {
            "new_nodes": len(new_nodes),
            "new_packages": len(new_packages),
            "new_containers": len(new_containers),
            "new_host_cves": len(new_host_cves),
            "new_container_cves": len(new_container_cves),
            "workflow_changes": len(workflow_changes),
        },
        "new_nodes": new_nodes,
        "new_packages": new_packages,
        "new_containers": new_containers,
        "new_host_cves": new_host_cves,
        "new_container_cves": new_container_cves,
        "workflow_changes": workflow_changes,
    }
