# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Plugins catalogue — capabilities × providers snapshot for the UI."""

import logging
import time

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_permission
from ..database import get_db
from ..utils.plugins import catalogue, count_query, summary

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/plugins", tags=["plugins"])

_CACHE_TTL = 30.0
_cache: dict = {"at": 0.0, "data": None}


async def _fetch_count(db: AsyncSession, sql: str, params: dict) -> int:
    try:
        row = await db.execute(text(sql), params)
        val = row.scalar()
        return int(val or 0)
    except Exception as e:
        logger.debug("plugins count query failed: %s", e)
        return 0


@router.get("")
async def list_plugins(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Return the static catalogue enriched with live instance counts."""
    now = time.monotonic()
    if _cache["data"] is not None and (now - _cache["at"]) < _CACHE_TTL:
        return _cache["data"]

    cats = catalogue()
    for cat in cats:
        for provider in cat["providers"]:
            q = count_query(cat["id"], provider["id"])
            if q is not None:
                provider["configured_count"] = await _fetch_count(db, *q)
            else:
                provider["configured_count"] = 0

    payload = {"summary": summary(cats), "categories": cats}
    _cache["data"] = payload
    _cache["at"] = now
    return payload
