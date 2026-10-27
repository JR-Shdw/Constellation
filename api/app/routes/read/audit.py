# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_permission
from ...database import get_db
from ...utils.sql import where_clause
from . import router


@router.get("/audit")
async def get_audit_log(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    target_type: str | None = None,
    actor: str | None = None,
    hostname: str | None = Query(None, max_length=200),
    search: str | None = Query(None, max_length=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Audit log of all manual actions (findings, settings, policies)."""
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if target_type:
        clauses.append("target_type = :tt")
        params["tt"] = target_type
    if actor:
        clauses.append("actor = :actor")
        params["actor"] = actor
    if hostname:
        clauses.append(
            "(actor ILIKE :host OR target_id ILIKE :host OR detail::text ILIKE :host)"
        )
        params["host"] = f"%{hostname}%"
    if search:
        clauses.append(
            "(actor ILIKE :q OR action ILIKE :q OR target_type ILIKE :q "
            "OR target_id ILIKE :q OR detail::text ILIKE :q)"
        )
        params["q"] = f"%{search}%"
    where = where_clause(clauses)

    total = (
        await db.execute(text(f"SELECT COUNT(*) FROM audit_log {where}"), params)
    ).scalar_one()
    rows = await db.execute(
        text(f"""
        SELECT * FROM audit_log {where}
        ORDER BY created_at DESC LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }
