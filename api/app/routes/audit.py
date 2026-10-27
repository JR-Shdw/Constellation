# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Audit trail — live log + compressed archives."""

import gzip
import json
import logging
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import require_permission
from ..database import get_db
from ..utils.sql import set_statement_timeout

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


# Archives


@router.get("/archives")
async def list_archives(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """List all compressed audit archives."""
    rows = await db.execute(
        text("""
        SELECT id, archive_date, entries_count, size_bytes,
               compressed, created_at
        FROM audit_archives
        ORDER BY archive_date DESC
        """)
    )
    items = [dict(r._mapping) for r in rows]
    return {"archives": items, "total": len(items)}


@router.get("/archives/{archive_date}")
async def view_archive(
    archive_date: date,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """View entries from a compressed audit archive."""
    row = await db.execute(
        text("""
        SELECT data, compressed, entries_count
        FROM audit_archives WHERE archive_date = :d
        """),
        {"d": archive_date},
    )
    archive = row.first()
    if not archive:
        raise HTTPException(404, "Archive not found")

    raw = bytes(archive.data)
    if archive.compressed:
        raw = gzip.decompress(raw)
    entries = json.loads(raw)

    return {
        "date": str(archive_date),
        "entries": entries,
        "total": archive.entries_count,
    }


@router.delete("/archives/{archive_date}")
async def delete_archive(
    archive_date: date,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Delete an audit archive (admin only, keep at least 1)."""
    count = (await db.execute(text("SELECT COUNT(*) FROM audit_archives"))).scalar_one()
    if count <= 1:
        raise HTTPException(400, "Cannot delete last archive — minimum 1 must be kept")

    exists = (
        await db.execute(
            text("SELECT id FROM audit_archives WHERE archive_date = :d"),
            {"d": archive_date},
        )
    ).scalar_one_or_none()
    if not exists:
        raise HTTPException(404, "Archive not found")

    await db.execute(
        text("DELETE FROM audit_archives WHERE archive_date = :d"),
        {"d": archive_date},
    )
    await log_action(
        db,
        actor=actor,
        action="delete_audit_archive",
        target_type="audit",
        detail={"date": str(archive_date)},
    )
    await db.commit()
    logger.info("[audit] Deleted archive %s", archive_date)
    return {"status": "ok", "deleted": str(archive_date)}


# Compact


async def _compact_entries(db: AsyncSession, days: int, actor: str) -> dict:
    """Move audit entries older than N days to compressed archives.

    Shared implementation between the manual POST /compact route and
    the background archiver loop. Caller commits.
    """
    rows = await db.execute(
        text("""
        SELECT created_at::date AS d, COUNT(*) AS cnt
        FROM audit_log
        WHERE created_at < NOW() - make_interval(days => :days)
        GROUP BY d ORDER BY d
        """),
        {"days": days},
    )
    dates = [(r.d, r.cnt) for r in rows]

    if not dates:
        return {"archived": 0, "entries": 0, "dates": []}

    archived_dates: list[str] = []
    total_entries = 0

    for archive_date, _ in dates:
        entries_rows = await db.execute(
            text("""
            SELECT actor, action, target_type, target_id,
                   detail, created_at
            FROM audit_log
            WHERE created_at::date = :d
            ORDER BY created_at
            """),
            {"d": archive_date},
        )
        entries = [dict(r._mapping) for r in entries_rows]
        for e in entries:
            e["created_at"] = str(e["created_at"])

        raw = json.dumps(entries, default=str).encode()
        compressed = gzip.compress(raw, compresslevel=6)

        await db.execute(
            text("""
            INSERT INTO audit_archives
                (archive_date, entries_count, size_bytes, compressed, data)
            VALUES (:d, :cnt, :size, true, :data)
            ON CONFLICT (archive_date) DO UPDATE SET
                entries_count = EXCLUDED.entries_count,
                size_bytes = EXCLUDED.size_bytes,
                data = EXCLUDED.data,
                created_at = NOW()
            """),
            {
                "d": archive_date,
                "cnt": len(entries),
                "size": len(compressed),
                "data": compressed,
            },
        )

        await db.execute(
            text("DELETE FROM audit_log WHERE created_at::date = :d"),
            {"d": archive_date},
        )
        archived_dates.append(str(archive_date))
        total_entries += len(entries)

    await log_action(
        db,
        actor=actor,
        action="compact_audit",
        target_type="audit",
        detail={"dates": len(archived_dates), "entries": total_entries},
    )

    return {
        "archived": len(archived_dates),
        "entries": total_entries,
        "dates": archived_dates,
    }


async def _prune_old_archives(db: AsyncSession, retention_days: int) -> int:
    """Drop archives older than retention_days. Keeps at least one row."""
    count = (await db.execute(text("SELECT COUNT(*) FROM audit_archives"))).scalar_one()
    if count <= 1:
        return 0
    result = await db.execute(
        text("""
        DELETE FROM audit_archives
        WHERE archive_date < (CURRENT_DATE - make_interval(days => :d))
        """),
        {"d": retention_days},
    )
    return result.rowcount or 0


@router.post("/compact")
async def compact_audit(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Archive audit entries older than N days into compressed archives."""
    await set_statement_timeout(db, "long")
    result = await _compact_entries(db, days, actor)
    await db.commit()

    logger.info(
        "[audit] Compacted %d days (%d entries) into archives",
        result["archived"],
        result["entries"],
    )
    return {"status": "ok", **result}
