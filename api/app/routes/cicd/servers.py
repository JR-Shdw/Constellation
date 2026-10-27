# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CI/CD servers CRUD + test connection."""

import httpx
from fastapi import Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...audit import log_action, validate_uuid
from ...auth import require_permission
from ...connectors import get_ci, get_forge
from ...crypto import decrypt_setting, encrypt_setting
from ...database import get_db
from . import router


@router.get("/servers")
async def list_servers(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "r")),
):
    """List all CI/CD server connections."""
    rows = await db.execute(
        text("SELECT * FROM cicd_servers ORDER BY server_type, name")
    )
    items = []
    for r in rows:
        d = dict(r._mapping)
        if d.get("token"):
            d["token"] = "***"
        items.append(d)
    return {"items": items}


@router.post("/servers")
async def add_server(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("cicd", "w")),
):
    """Register a new CI/CD server (Woodpecker or Gitea)."""
    name = (payload.get("name") or "").strip()
    url = (payload.get("url") or "").strip().rstrip("/")
    server_type = payload.get("server_type", "woodpecker")
    token = payload.get("token", "")

    if not name or not url:
        raise HTTPException(400, "name and url are required")
    if server_type not in ("woodpecker", "gitea", "gitlab", "forgejo"):
        raise HTTPException(
            400, "server_type must be woodpecker, gitea, gitlab, or forgejo"
        )

    try:
        result = await db.execute(
            text("""
            INSERT INTO cicd_servers (name, server_type, url, token)
            VALUES (:name, :type, :url, :token)
            RETURNING id
            """),
            # Encrypt at rest (Fernet) like the Settings-managed forge/CI tokens —
            # a DB dump must not expose CI/CD credentials in plaintext.
            {
                "name": name,
                "type": server_type,
                "url": url,
                "token": encrypt_setting(token),
            },
        )
        server_id = str(result.scalar_one())
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(409, f"Server '{name}' already exists") from e
        raise

    await log_action(
        db,
        actor=actor,
        action="add_cicd_server",
        target_type="cicd_server",
        target_id=server_id,
        detail={"name": name, "type": server_type, "url": url},
    )
    await db.commit()
    return {"status": "ok", "id": server_id}


@router.post("/servers/{server_id}/test")
async def test_server(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "w")),
):
    """Test connection to a CI/CD server."""
    validate_uuid(server_id, "server_id")
    row = await db.execute(
        text("SELECT * FROM cicd_servers WHERE id = CAST(:id AS uuid)"),
        {"id": server_id},
    )
    srv = row.mappings().first()
    if not srv:
        raise HTTPException(404, "Server not found")

    url = srv["url"].rstrip("/")
    token = decrypt_setting(srv["token"] or "")
    stype = srv["server_type"]
    status = "error"
    detail = ""

    try:
        if stype in ("gitea", "forgejo", "gitlab"):
            connector = get_forge(stype, url, token)
        elif stype == "woodpecker":
            connector = get_ci(stype, url, token)
        else:
            raise ValueError(f"Unknown server type: {stype}")
        result = await connector.test_connection()
        detail = f"Connected as {result.get('username', '?')}"
        status = "connected"
    except httpx.HTTPStatusError as e:
        detail = f"HTTP {e.response.status_code}"
        status = "error"
    except Exception as e:
        detail = str(e)[:200]
        status = "error"

    await db.execute(
        text("""
        UPDATE cicd_servers
        SET status = :status, last_check = NOW(), updated_at = NOW()
        WHERE id = CAST(:id AS uuid)
        """),
        {"status": status, "id": server_id},
    )
    await db.commit()
    return {"status": status, "detail": detail}


@router.delete("/servers/{server_id}")
async def delete_server(
    server_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("cicd", "w")),
):
    """Delete a CI/CD server connection."""
    validate_uuid(server_id, "server_id")
    row = await db.execute(
        text("SELECT name FROM cicd_servers WHERE id = CAST(:id AS uuid)"),
        {"id": server_id},
    )
    name = row.scalar_one_or_none()
    if not name:
        raise HTTPException(404, "Server not found")

    await db.execute(
        text("DELETE FROM cicd_servers WHERE id = CAST(:id AS uuid)"),
        {"id": server_id},
    )
    await log_action(
        db,
        actor=actor,
        action="delete_cicd_server",
        target_type="cicd_server",
        target_id=server_id,
        detail={"name": name},
    )
    await db.commit()
    return {"status": "ok"}
