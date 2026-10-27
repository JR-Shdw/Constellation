# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Resync — trigger external sync containers on demand."""

import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import require_permission
from ..database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/resync", tags=["resync"])

TRIGGER_DIR = Path("/triggers")


def _ensure_trigger_dir():
    """Ensure trigger directory exists and is writable."""
    try:
        TRIGGER_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def _write_trigger(name: str, args: str = "") -> bool:
    """Write a trigger file for a sync container."""
    _ensure_trigger_dir()
    trigger = TRIGGER_DIR / f"{name}.trigger"
    try:
        trigger.write_text(args)
        return True
    except OSError as e:
        logger.error("[resync] cannot write %s: %s", trigger, e)
        return False


def _read_result(name: str) -> str | None:
    """Read and remove result file left by sync container."""
    result = TRIGGER_DIR / f"{name}.result"
    try:
        if result.exists():
            val = result.read_text().strip()
            result.unlink(missing_ok=True)
            return val
    except OSError:
        pass
    return None


async def _wait_for_result(name: str, timeout: int = 120) -> str | None:
    """Poll for result file (sync container writes it on completion)."""
    for _ in range(timeout // 2):
        val = _read_result(name)
        if val is not None:
            return val
        await asyncio.sleep(2)
    return None


@router.post("/wazuh")
async def resync_wazuh(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "w")),
):
    """Trigger Wazuh CVE resync via sync-wazuh container."""
    from .settings import feature_enabled

    if not await feature_enabled("cve", db):
        return {"status": "error", "detail": "CVE module disabled"}

    # Clear any stale result
    _read_result("sync_wazuh")

    if not _write_trigger("sync_wazuh"):
        return {"status": "error", "detail": "Cannot write trigger file"}

    logger.info("[resync] Wazuh sync triggered")

    result = await _wait_for_result("sync_wazuh", timeout=300)
    if result is None:
        return {"status": "ok", "detail": "Sync triggered (still running)"}
    if result.startswith("error"):
        return {"status": "warning", "detail": f"Sync completed with {result}"}
    return {"status": "ok", "detail": "Sync completed successfully"}


@router.post("/opencve")
async def resync_opencve(
    body: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "w")),
):
    """Trigger OpenCVE resync via sync-opencve container."""
    from .settings import feature_enabled

    if not await feature_enabled("cve", db):
        return {"status": "error", "detail": "CVE module disabled"}

    hours = body.get("hours", 168)
    # Extra args appended to default command (argparse last-value-wins)
    args = f"--hours {hours}"

    _read_result("sync_opencve")

    if not _write_trigger("sync_opencve", args):
        return {"status": "error", "detail": "Cannot write trigger file"}

    logger.info("[resync] OpenCVE sync triggered (last %dh)", hours)

    result = await _wait_for_result("sync_opencve", timeout=300)
    if result is None:
        return {
            "status": "ok",
            "detail": f"Sync triggered for last {hours}h (still running)",
        }
    if result.startswith("error"):
        return {"status": "warning", "detail": f"Sync completed with {result}"}
    return {
        "status": "ok",
        "detail": f"Sync completed ({hours}h window)",
    }


_RESET_TABLES = [
    "cve_host_packages",
    "cve_containers",
    "cve_status",
]


@router.post("/reset-cve")
async def reset_cve(
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Truncate CVE scan data. Requires typed confirmation."""
    from .settings import feature_enabled

    if not await feature_enabled("cve", db):
        return {"status": "error", "detail": "CVE module disabled"}

    confirm = (body.get("confirm") or "").strip()
    if confirm != "RESET CVE":
        raise HTTPException(400, "Type 'RESET CVE' to confirm")

    for table in _RESET_TABLES:
        await db.execute(text(f"TRUNCATE {table} CASCADE"))

    await log_action(
        db,
        actor=actor,
        action="reset_cve",
        target_type="cve",
        detail={"tables": _RESET_TABLES},
    )
    await db.commit()

    logger.warning(
        "[resync] CVE data reset by %s — %d tables truncated",
        actor,
        len(_RESET_TABLES),
    )

    # Auto-trigger resyncs if requested
    triggered = []
    if body.get("resync_wazuh"):
        _read_result("sync_wazuh")
        if _write_trigger("sync_wazuh"):
            triggered.append("wazuh")
    if body.get("resync_opencve"):
        hours = body.get("opencve_hours", 168)
        _read_result("sync_opencve")
        if _write_trigger("sync_opencve", f"--hours {hours}"):
            triggered.append("opencve")

    detail = f"{len(_RESET_TABLES)} tables truncated"
    if triggered:
        detail += f" — resync triggered: {', '.join(triggered)}"

    return {"status": "ok", "detail": detail}
