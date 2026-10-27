# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CI/CD routes — repos, pipelines, workers, servers, stats, full sync."""

import logging
import time

from fastapi import APIRouter
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import settings as app_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cicd", tags=["cicd"])

_cache: dict = {}
_CACHE_TTL = {"cicd_stats": 30}


def _get_cache(key: str):
    entry = _cache.get(key)
    if entry and (time.monotonic() - entry["ts"]) < _CACHE_TTL.get(key, 30):
        return entry["data"]
    return None


def _set_cache(key: str, data):
    _cache[key] = {"data": data, "ts": time.monotonic()}


async def _resolve_ci_credentials(ci_system: str, db: AsyncSession) -> tuple[str, str]:
    """Resolve URL+token for a CI system from cicd_servers or app settings."""
    row = await db.execute(
        text("""
        SELECT url, token FROM cicd_servers
        WHERE server_type = :st AND status != 'offline'
        ORDER BY last_check DESC NULLS LAST LIMIT 1
        """),
        {"st": ci_system},
    )
    srv = row.mappings().first()
    if srv and srv["url"] and srv["token"]:
        from ...crypto import decrypt_setting

        return srv["url"], decrypt_setting(srv["token"])
    url = getattr(app_settings, f"{ci_system}_url", "")
    token = getattr(app_settings, f"{ci_system}_token", "")
    return url, token


from . import (  # noqa: E402, F401
    pipelines,
    repos,
    servers,
    stats,
    workers,
)
from . import sync as _sync  # noqa: E402, F401
