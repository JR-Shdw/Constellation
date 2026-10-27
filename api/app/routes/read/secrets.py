# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...audit import log_action, validate_uuid
from ...auth import require_permission
from ...database import get_db
from ...utils.sql import where_clause
from . import router

_VALID_SECRET_STATUSES = ("open", "false_positive", "resolved", "accepted_risk")


@router.get("/secrets")
async def list_secrets(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: str | None = None,
    severity: str | None = None,
    node_id: str | None = None,
    hostname: str | None = None,
    search: str | None = None,
    sort_by: str | None = None,
    sort_dir: str = Query("asc"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if status:
        clauses.append("s.status = :status")
        params["status"] = status
    if severity:
        clauses.append("sr.severity = :sev")
        params["sev"] = severity
    if node_id:
        clauses.append("s.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if hostname:
        clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    if search:
        clauses.append(
            "(n.hostname ILIKE :search OR s.target_type ILIKE :search"
            " OR s.file_path ILIKE :search OR s.secret_type ILIKE :search)"
        )
        params["search"] = f"%{search}%"
    where = where_clause(clauses)

    _SORT_MAP = {
        "severity": (
            "CASE sr.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
            " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        ),
        "detected_at": "s.detected_at",
        "target": "s.target_type",
        "status": "s.status",
        "hostname": "n.hostname",
    }
    direction = "DESC" if sort_dir == "desc" else "ASC"
    order = (
        f"{_SORT_MAP[sort_by]} {direction} NULLS LAST, s.detected_at DESC"
        if sort_by in _SORT_MAP
        else "CASE s.status WHEN 'open' THEN 0 ELSE 1 END, s.detected_at DESC"
    )

    _sec_joins = (
        "FROM secrets_detected s"
        " JOIN secret_rules sr ON sr.secret_type = s.secret_type"
        " JOIN nodes n ON n.id = s.node_id"
    )

    count_result = await db.execute(
        text(f"SELECT COUNT(*) {_sec_joins} {where}"),
        params,
    )
    total = count_result.scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT s.id, s.node_id, s.secret_type, s.file_path,
               s.match, s.image, s.target_type, s.status, s.detected_at,
               sr.title, sr.severity, sr.source,
               n.hostname
        {_sec_joins}
        {where}
        ORDER BY {order}
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


@router.patch("/secrets/{secret_id}")
async def patch_secret(
    secret_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("read", "w")),
):
    """Update secret status (open, false_positive, resolved, accepted_risk)."""
    validate_uuid(secret_id)
    new_status = body.get("status", "")
    if new_status not in _VALID_SECRET_STATUSES:
        raise HTTPException(400, f"status must be one of {_VALID_SECRET_STATUSES}")
    await db.execute(
        text("UPDATE secrets_detected SET status = :st WHERE id = CAST(:sid AS uuid)"),
        {"sid": secret_id, "st": new_status},
    )
    await log_action(
        db,
        actor=actor,
        action="patch_secret",
        target_type="secret",
        target_id=secret_id,
        detail={"status": new_status},
    )
    await db.commit()
    return {"status": "ok"}
