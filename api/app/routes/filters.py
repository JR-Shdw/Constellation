# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Saved filters — persist named filter configurations per view."""

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..database import get_db

router = APIRouter(prefix="/api/v1/filters", tags=["filters"])


@router.get("")
async def list_filters(
    view: str = Query("", description="Filter by view name"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """List saved filters, optionally filtered by view."""
    if view:
        rows = await db.execute(
            text("""
            SELECT id, name, view, filters, created_by, created_at
            FROM saved_filters
            WHERE view = :view
            ORDER BY name
            """),
            {"view": view},
        )
    else:
        rows = await db.execute(
            text("""
            SELECT id, name, view, filters, created_by, created_at
            FROM saved_filters
            ORDER BY view, name
            """)
        )
    return {"items": [dict(r._mapping) for r in rows]}


@router.post("")
async def create_filter(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Save a named filter configuration.

    Body:
        name: unique name for this filter preset
        view: which view it applies to (e.g. cves, nodes, containers)
        filters: JSON object with filter key/value pairs
    """
    name = payload.get("name", "").strip()
    view = payload.get("view", "").strip()
    filters = payload.get("filters", {})

    if not name or not view:
        raise HTTPException(400, "name and view are required")

    try:
        result = await db.execute(
            text("""
            INSERT INTO saved_filters (name, view, filters, created_by)
            VALUES (:name, :view, CAST(:filters AS jsonb), :actor)
            RETURNING id
            """),
            {
                "name": name,
                "view": view,
                "filters": json.dumps(filters),
                "actor": actor,
            },
        )
        filter_id = str(result.scalar_one())
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(409, f"Filter '{name}' already exists") from e
        raise

    await log_action(
        db,
        actor=actor,
        action="create_filter",
        target_type="saved_filter",
        target_id=filter_id,
        detail={"name": name, "view": view},
    )
    await db.commit()
    return {"status": "ok", "id": filter_id, "name": name}


@router.put("/{filter_id}")
async def update_filter(
    filter_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Update a saved filter's name or filters."""
    validate_uuid(filter_id, "filter_id")

    sets = []
    params: dict = {"id": filter_id}

    if "name" in payload:
        sets.append("name = :name")
        params["name"] = payload["name"].strip()
    if "filters" in payload:
        sets.append("filters = CAST(:filters AS jsonb)")
        params["filters"] = json.dumps(payload["filters"])

    if not sets:
        return {"status": "ok", "changed": False}

    await db.execute(
        text(
            f"UPDATE saved_filters SET {', '.join(sets)} WHERE id = CAST(:id AS uuid)"
        ),
        params,
    )
    await db.commit()
    return {"status": "ok", "changed": True}


@router.delete("/{filter_id}")
async def delete_filter(
    filter_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Delete a saved filter."""
    validate_uuid(filter_id, "filter_id")

    row = await db.execute(
        text("SELECT name FROM saved_filters WHERE id = CAST(:id AS uuid)"),
        {"id": filter_id},
    )
    name = row.scalar_one_or_none()
    if not name:
        raise HTTPException(404, "Filter not found")

    await db.execute(
        text("DELETE FROM saved_filters WHERE id = CAST(:id AS uuid)"),
        {"id": filter_id},
    )
    await log_action(
        db,
        actor=actor,
        action="delete_filter",
        target_type="saved_filter",
        target_id=filter_id,
        detail={"name": name},
    )
    await db.commit()
    return {"status": "ok"}
