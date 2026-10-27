# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_permission
from ..database import get_db
from .automation import run_evaluation

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/scan", tags=["scan"])


@router.get("/status")
async def scan_status(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Fraicheur des scans par node (Wazuh, Trivy host, Trivy image)."""
    rows = await db.execute(text("SELECT * FROM v_scan_status ORDER BY hostname"))
    items = [dict(r._mapping) for r in rows]

    # Fire scan_stale events for nodes not scanned in 7+ days.
    # v_scan_status exposes last_*_scan TIMESTAMPS (not ages) — the previous
    # code read non-existent *_age columns, so item.get() was always None and
    # scan_stale never fired. Compute the age from the timestamps instead.
    # A NULL timestamp (never scanned) is left as-is here to avoid alerting on
    # freshly-added nodes; genuine staleness is the 7-day-since-last-scan case.
    now = datetime.now(timezone.utc)
    for item in items:
        stale = False
        for key in ("last_trivy_host_scan", "last_trivy_image_scan", "last_wazuh_scan"):
            ts = item.get(key)
            if not isinstance(ts, datetime):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if (now - ts).total_seconds() > 7 * 86400:
                stale = True
                break
        if stale:
            try:
                await run_evaluation(
                    {
                        "trigger_type": "scan_stale",
                        "hostname": item.get("hostname", ""),
                    },
                    db,
                )
            except Exception as e:
                logger.warning("[scan] automation eval failed: %s", e)
    await db.commit()

    return {"items": items}
