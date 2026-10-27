# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""SBOM CycloneDX import — ingest Software Bill of Materials."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import require_collect_token, require_permission
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sbom", tags=["sbom"])


@router.post("/import")
async def import_sbom(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_collect_token),
):
    """Import a CycloneDX SBOM (JSON format).

    Expects standard CycloneDX 1.4+ JSON with:
    - metadata.component.name (image or host identifier)
    - components[] array

    Trivy generates this with: trivy image -f cyclonedx <image>
    Or: trivy rootfs -f cyclonedx /
    """
    hostname = payload.get("hostname", "")
    image_name = payload.get("image_name")

    # Support raw CycloneDX JSON (bomFormat + components)
    if payload.get("bomFormat") == "CycloneDX":
        meta = payload.get("metadata", {})
        comp = meta.get("component", {})
        if not hostname:
            hostname = comp.get("name", "")
        if not image_name and comp.get("type") == "container":
            image_name = comp.get("name")

    # CycloneDX format — components at top level or nested
    components = payload.get("components", [])

    if not hostname:
        raise HTTPException(400, "hostname or metadata.component.name required")

    # Resolve node
    row = await db.execute(
        text("SELECT id FROM nodes WHERE hostname = :h"),
        {"h": hostname},
    )
    node_id = row.scalar_one_or_none()
    if not node_id:
        raise HTTPException(404, f"Node '{hostname}' not found")

    node_id = str(node_id)
    imported = 0

    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version", "")
        if not name:
            continue

        purl = comp.get("purl", "")
        comp_type = comp.get("type", "library")
        bom_ref = comp.get("bom-ref", "")
        licenses_raw = comp.get("licenses", [])
        licenses = [
            lic.get("license", {}).get("id", "")
            or lic.get("license", {}).get("name", "")
            for lic in licenses_raw
            if lic.get("license")
        ]
        supplier = ""
        if comp.get("supplier"):
            supplier = comp["supplier"].get("name", "")

        await db.execute(
            text("""
            INSERT INTO sbom_components
                (node_id, image_name, bom_ref, comp_type, name, version,
                 purl, licenses, supplier)
            VALUES
                (CAST(:nid AS uuid), :img, :ref, :type, :name, :ver,
                 :purl, CAST(:lic AS jsonb), :supplier)
            ON CONFLICT (node_id, name, version, COALESCE(image_name, ''))
            DO UPDATE SET
                purl = EXCLUDED.purl,
                licenses = EXCLUDED.licenses,
                supplier = EXCLUDED.supplier,
                comp_type = EXCLUDED.comp_type,
                imported_at = NOW()
            """),
            {
                "nid": node_id,
                "img": image_name,
                "ref": bom_ref,
                "type": comp_type,
                "name": name,
                "ver": version,
                "purl": purl,
                "lic": json.dumps(licenses),
                "supplier": supplier,
            },
        )
        imported += 1

    await log_action(
        db,
        actor=actor,
        action="import_sbom",
        target_type="sbom",
        detail={
            "hostname": hostname,
            "image": image_name,
            "components": imported,
        },
    )
    await db.commit()

    logger.info(
        "[sbom] Imported %d components for %s%s",
        imported,
        hostname,
        f" ({image_name})" if image_name else "",
    )
    return {"status": "ok", "imported": imported, "hostname": hostname}


@router.get("")
async def list_sbom(
    node: str = Query("", description="Filter by hostname"),
    image: str = Query("", description="Filter by image name"),
    search: str = Query("", description="Search component name"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """List SBOM components with filters."""
    conditions = []
    params: dict = {}

    if node:
        conditions.append("n.hostname = :node")
        params["node"] = node
    if image:
        conditions.append("s.image_name ILIKE :img")
        params["img"] = f"%{image}%"
    if search:
        conditions.append("s.name ILIKE :search")
        params["search"] = f"%{search}%"

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    # Count
    count_q = (
        f"SELECT COUNT(*) FROM sbom_components s"
        f" JOIN nodes n ON s.node_id = n.id {where}"
    )
    row = await db.execute(text(count_q), params)
    total = row.scalar_one()

    # Results
    params["limit"] = per_page
    params["offset"] = (page - 1) * per_page
    rows = await db.execute(
        text(f"""
        SELECT s.id, s.name, s.version, s.comp_type, s.purl,
               s.licenses, s.supplier, s.image_name, s.imported_at,
               n.hostname
        FROM sbom_components s JOIN nodes n ON s.node_id = n.id
        {where}
        ORDER BY s.name, s.version
        LIMIT :limit OFFSET :offset
        """),
        params,
    )
    items = [dict(r._mapping) for r in rows]

    return {"items": items, "total": total, "page": page}


@router.get("/stats")
async def sbom_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """SBOM summary statistics."""
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) AS total_components,
            COUNT(DISTINCT name) AS unique_packages,
            COUNT(DISTINCT node_id) AS nodes_with_sbom,
            COUNT(DISTINCT image_name) FILTER (WHERE image_name IS NOT NULL) AS images
        FROM sbom_components
        """)
    )
    stats = dict(row.mappings().first())

    # Cross-reference: components that match CVE package names
    row = await db.execute(
        text("""
        SELECT COUNT(DISTINCT s.name) AS vulnerable_packages
        FROM sbom_components s
        WHERE EXISTS (
            SELECT 1 FROM cve_host_packages h
            WHERE h.pkg_name = s.name AND h.node_id = s.node_id
        )
        """)
    )
    stats["vulnerable_packages"] = row.scalar_one()

    return stats
