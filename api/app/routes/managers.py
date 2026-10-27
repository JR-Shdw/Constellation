# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Container managers — Portainer CRUD, test, image pull."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..crypto import decrypt_setting, encrypt_setting
from ..database import get_db
from ..models.schemas import ImagePull, ManagerCreate, ManagerPatch
from ..utils.portainer import PortainerClient

# Sentinels returned in place of the real token by the read endpoints.
# A PUT echoing one of these must not overwrite the stored token.
_TOKEN_MASKS = ("***", "********")

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/managers", tags=["managers"])


async def _get_client(
    db: AsyncSession,
    manager_id: str,
) -> tuple[dict, PortainerClient]:
    """Load a manager row and build a PortainerClient."""
    validate_uuid(manager_id)
    row = await db.execute(
        text("SELECT * FROM container_managers WHERE id = CAST(:mid AS uuid)"),
        {"mid": manager_id},
    )
    mgr = row.mappings().first()
    if not mgr:
        raise HTTPException(404, "Manager not found")
    client = PortainerClient(
        url=mgr["url"],
        token=decrypt_setting(mgr["token"] or ""),
        endpoint_id=mgr["endpoint_id"] or 1,
        tls_skip_verify=mgr["tls_skip_verify"] or False,
    )
    return dict(mgr), client


# CRUD


@router.post("")
async def create_manager(
    payload: ManagerCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("managers", "w")),
):
    """Register a container manager (Portainer)."""
    row = await db.execute(
        text("""
        INSERT INTO container_managers
            (name, manager_type, url, token, endpoint_id,
             tls_skip_verify, node_id, status)
        VALUES
            (:name, :mtype, :url, :token, :endpoint_id,
             :tls_skip, CAST(:node_id AS uuid), 'offline')
        RETURNING id
        """),
        {
            "name": payload.name,
            "mtype": payload.manager_type,
            "url": payload.url,
            "token": encrypt_setting(payload.token) if payload.token else "",
            "endpoint_id": payload.endpoint_id,
            "tls_skip": payload.tls_skip_verify,
            "node_id": payload.node_id,
        },
    )
    mgr_id = row.scalar()
    await log_action(
        db,
        actor=actor,
        action="create",
        target_type="manager",
        target_id=str(mgr_id),
        detail={"name": payload.name},
    )
    await db.commit()
    return {"status": "ok", "id": str(mgr_id)}


@router.get("")
async def list_managers(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("managers", "r")),
):
    """List all container managers."""
    rows = await db.execute(text("SELECT * FROM container_managers ORDER BY name"))
    items = []
    for r in rows.mappings():
        d = dict(r)
        # Never leak the Portainer API token — mask like get_manager does.
        if d.get("token"):
            d["token"] = "***"
        items.append(d)
    return {"items": items}


@router.get("/{manager_id}")
async def get_manager(
    manager_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("managers", "r")),
):
    """Single manager detail."""
    validate_uuid(manager_id)
    row = await db.execute(
        text("SELECT * FROM container_managers WHERE id = CAST(:mid AS uuid)"),
        {"mid": manager_id},
    )
    mgr = row.mappings().first()
    if not mgr:
        raise HTTPException(404, "Manager not found")
    result = dict(mgr)
    # Mask token in response
    if result.get("token"):
        result["token"] = "***"
    return result


@router.put("/{manager_id}")
async def update_manager(
    manager_id: str,
    payload: ManagerPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("managers", "w")),
):
    """Update a container manager."""
    validate_uuid(manager_id)
    updates = {}
    if payload.name is not None:
        updates["name"] = payload.name
    if payload.url is not None:
        updates["url"] = payload.url
    # Skip the masked sentinel echoed back by GET — only encrypt a real token.
    if payload.token is not None and payload.token not in _TOKEN_MASKS:
        updates["token"] = encrypt_setting(payload.token)
    if payload.endpoint_id is not None:
        updates["endpoint_id"] = payload.endpoint_id
    if payload.tls_skip_verify is not None:
        updates["tls_skip_verify"] = payload.tls_skip_verify
    if payload.node_id is not None:
        updates["node_id"] = payload.node_id

    if not updates:
        return {"status": "ok", "changed": False}

    set_clauses = []
    for k in updates:
        if k == "node_id":
            set_clauses.append(f"{k} = CAST(:{k} AS uuid)")
        else:
            set_clauses.append(f"{k} = :{k}")
    set_clauses.append("updated_at = NOW()")
    set_sql = ", ".join(set_clauses)

    updates["mid"] = manager_id
    await db.execute(
        text(f"UPDATE container_managers SET {set_sql} WHERE id = CAST(:mid AS uuid)"),
        updates,
    )
    await log_action(
        db,
        actor=actor,
        action="update",
        target_type="manager",
        target_id=manager_id,
    )
    await db.commit()
    return {"status": "ok", "changed": True}


@router.delete("/{manager_id}")
async def delete_manager(
    manager_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("managers", "w")),
):
    """Delete a container manager."""
    validate_uuid(manager_id)
    result = await db.execute(
        text("DELETE FROM container_managers WHERE id = CAST(:mid AS uuid)"),
        {"mid": manager_id},
    )
    if result.rowcount == 0:
        raise HTTPException(404, "Manager not found")
    await log_action(
        db,
        actor=actor,
        action="delete",
        target_type="manager",
        target_id=manager_id,
    )
    await db.commit()
    return {"status": "ok"}


# Test connection


@router.post("/{manager_id}/test")
async def test_manager(
    manager_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("managers", "w")),
):
    """Test connectivity to a Portainer instance."""
    mgr, client = await _get_client(db, manager_id)
    try:
        info = await client.test_connection()
        await db.execute(
            text("""
            UPDATE container_managers
            SET status = 'connected', last_check = NOW(),
                updated_at = NOW()
            WHERE id = CAST(:mid AS uuid)
            """),
            {"mid": manager_id},
        )
        await db.commit()
        return {"status": "ok", "detail": info}
    except Exception as e:
        await db.execute(
            text("""
            UPDATE container_managers
            SET status = 'error', last_check = NOW(),
                updated_at = NOW()
            WHERE id = CAST(:mid AS uuid)
            """),
            {"mid": manager_id},
        )
        await db.commit()
        raise HTTPException(502, f"Connection failed: {e}") from e


# Images


@router.get("/{manager_id}/images")
async def list_images(
    manager_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("managers", "r")),
):
    """List Docker images on a Portainer endpoint."""
    mgr, client = await _get_client(db, manager_id)
    try:
        images = await client.list_images()
    except Exception as e:
        raise HTTPException(502, f"Portainer API error: {e}") from e

    result = []
    for img in images:
        tags = img.get("RepoTags") or []
        result.append(
            {
                "id": img.get("Id", "")[:19],
                "tags": tags,
                "size": img.get("Size", 0),
                "created": img.get("Created"),
            }
        )
    return {"items": result}


@router.post("/{manager_id}/pull")
async def pull_image(
    manager_id: str,
    payload: ImagePull,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("managers", "w")),
):
    """Pull an image from a registry to the Portainer endpoint."""
    from ..utils.image_verify import SignatureError

    mgr, client = await _get_client(db, manager_id)
    try:
        result = await client.pull_image(
            payload.image,
            payload.tag,
        )
    except SignatureError as e:
        # 403 — the image is in a trusted namespace and didn't verify.
        # Operator must investigate (rotated key? wrong tag? compromise?).
        raise HTTPException(403, f"Signature verification failed: {e}") from e
    except Exception as e:
        raise HTTPException(502, f"Pull failed: {e}") from e

    await log_action(
        db,
        actor=actor,
        action="pull_image",
        target_type="manager",
        target_id=manager_id,
        detail={
            "image": payload.image,
            "tag": payload.tag,
        },
    )
    await db.commit()
    return result
