# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Manual cleanup endpoints for container images.

DELETE /container-images/{id} lets an operator clear a ghost image
(container + image removed from the host but CVEs still listed because
Trivy only reports on running images). Same effect as the daily
retention pass but on demand.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/container-images", tags=["container-images"])


@router.delete("/{image_id}")
async def delete_container_image(
    image_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("findings", "w")),
):
    """Remove a container image and resolve every CVE/secret attached to it.

    Used when the operator knows the image is gone (container stopped +
    docker image rm) and the scanner won't produce fresh reports to clean
    it up. Writes `cve_status` entries so a stray re-scan can't re-open
    the findings.

    Refuses if at least one container still references the image — in
    that case the image is live, not a ghost.
    """
    img_uuid = validate_uuid(image_id)

    row = (
        (
            await db.execute(
                text("""
            SELECT ci.image, ci.tag, (ci.image || ':' || ci.tag) AS full_name,
                   (SELECT COUNT(*) FROM containers c WHERE c.image_id = ci.id)
                       AS container_count
            FROM container_images ci
            WHERE ci.id = CAST(:id AS uuid)
            """),
                {"id": img_uuid},
            )
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(404, "Image not found")
    if row["container_count"] > 0:
        raise HTTPException(
            409,
            f"{row['container_count']} container(s) still use this image — "
            "stop and remove them first",
        )

    full = row["full_name"]
    justification = f"image_removed_manual_by_{actor}"

    await db.execute(
        text("""
        INSERT INTO cve_status (node_id, cve_id, status, justification)
        SELECT DISTINCT cc.node_id, cc.cve_id, 'resolved', :jst
        FROM cve_containers cc
        WHERE cc.image = :img
        ON CONFLICT (node_id, cve_id) DO UPDATE SET
            status = 'resolved',
            justification = EXCLUDED.justification,
            updated_at = NOW()
        """),
        {"img": full, "jst": justification},
    )
    cves = await db.execute(
        text("""
        UPDATE cve_containers SET status = 'resolved'
        WHERE image = :img AND status = 'open'
        """),
        {"img": full},
    )
    secrets = await db.execute(
        text("""
        UPDATE secrets_detected SET status = 'resolved'
        WHERE image = :img AND status = 'open'
        """),
        {"img": full},
    )
    await db.execute(
        text("DELETE FROM container_images WHERE id = CAST(:id AS uuid)"),
        {"id": img_uuid},
    )

    cves_resolved = cves.rowcount or 0
    secrets_resolved = secrets.rowcount or 0

    await log_action(
        db,
        actor=actor,
        action="container_image_manual_cleanup",
        target_type="container_image",
        target_id=img_uuid,
        detail={
            "image": full,
            "cves_resolved": cves_resolved,
            "secrets_resolved": secrets_resolved,
        },
    )
    await db.commit()

    from .read import _cache

    _cache.clear()

    return {
        "status": "ok",
        "image": full,
        "cves_resolved": cves_resolved,
        "secrets_resolved": secrets_resolved,
    }
