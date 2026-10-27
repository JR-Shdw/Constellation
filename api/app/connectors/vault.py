# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""rhorizon connector — check vault status + fetch secrets at runtime.

Uses /dev/shm for shared-memory cache so all uvicorn workers share the
same vault status without DB round-trips.
"""

import asyncio
import json
import logging
import time

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# Shared-memory cache (cross-worker via /dev/shm)
_SHM_PATH = "/dev/shm/cmdb_vault.json"
_CACHE_TTL_UNSEALED = 300  # 5 min
_CACHE_TTL_SEALED = 15  # re-check soon
_STALE_MAX = 600  # serve stale unsealed on network failure
_RETRIES = 2
_RETRY_DELAY = 0.5

# DB config reload cache (multi-worker sync)
_db_config_ts: float = 0
_DB_CONFIG_TTL = 30


def _shm_read() -> dict | None:
    """Read cached vault status from shared memory."""
    try:
        with open(_SHM_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _shm_write(data: dict, ts: float):
    """Write vault status to shared memory (atomic via tmp + rename)."""
    try:
        tmp = _SHM_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"data": data, "ts": ts}, f)
        import os

        os.replace(tmp, _SHM_PATH)
    except OSError as e:
        logger.debug("shm write failed: %s", e)


async def _ensure_vault_config():
    """Reload vault_url/vault_token from DB if missing in this worker."""
    global _db_config_ts
    if settings.vault_url and settings.vault_token:
        return
    now = time.monotonic()
    if (now - _db_config_ts) < _DB_CONFIG_TTL:
        return
    _db_config_ts = now
    try:
        import asyncpg

        dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
        conn = await asyncpg.connect(dsn)
        try:
            rows = await conn.fetch(
                "SELECT key, value FROM alert_settings"
                " WHERE key IN ('vault_url', 'vault_token')"
            )
            from ..crypto import decrypt_setting

            for row in rows:
                val = decrypt_setting(row["value"]) if row["value"] else ""
                if val and val != "********":
                    setattr(settings, row["key"], val)
                    logger.info("vault config reloaded from DB: %s", row["key"])
        finally:
            await conn.close()
    except Exception:
        logger.debug("[vault] DB config reload skipped (table not ready)")


async def _vault_status() -> dict | None:
    """Fetch vault status with shared-memory cache and retry."""
    await _ensure_vault_config()
    if not settings.vault_url:
        return None

    now = time.monotonic()
    cached = _shm_read()

    if cached:
        age = now - cached["ts"]
        is_unsealed = not cached["data"].get("sealed", True)
        ttl = _CACHE_TTL_UNSEALED if is_unsealed else _CACHE_TTL_SEALED
        if age < ttl:
            return cached["data"]

    last_err = None
    for attempt in range(_RETRIES):
        try:
            async with httpx.AsyncClient(
                base_url=settings.vault_url, timeout=5
            ) as client:
                r = await client.get("/api/v1/vault/status")
                if r.status_code == 200:
                    data = r.json()
                    _shm_write(data, now)
                    return data
                last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        if attempt < _RETRIES - 1:
            await asyncio.sleep(_RETRY_DELAY)

    logger.debug("vault check failed (%d attempts): %s", _RETRIES, last_err)

    # On failure, return stale cache if last known state was unsealed
    if cached and (now - cached["ts"]) < _STALE_MAX:
        is_unsealed = not cached["data"].get("sealed", True)
        if is_unsealed:
            logger.debug("vault unreachable, returning stale unsealed cache")
            return cached["data"]

    return None


def invalidate_cache():
    """Clear cached vault status (called after config changes)."""
    global _db_config_ts
    _db_config_ts = 0
    try:
        import os

        os.remove(_SHM_PATH)
    except FileNotFoundError:
        pass


# Public API


def vault_configured() -> bool:
    """Return True if vault URL and token are set."""
    return bool(settings.vault_url and settings.vault_token)


async def vault_is_unsealed() -> bool:
    """Check if vault is unsealed. Returns True if vault not configured."""
    await _ensure_vault_config()
    if not vault_configured():
        return True
    status = await _vault_status()
    if status is None:
        return False
    return not status.get("sealed", True)


async def vault_status_detail() -> dict:
    """Full vault status for API/frontend consumption."""
    await _ensure_vault_config()
    if not vault_configured():
        return {
            "configured": False,
            "sealed": None,
            "url": "",
            "version": None,
        }

    status = await _vault_status()
    if status is None:
        return {
            "configured": True,
            "sealed": None,
            "url": settings.vault_url,
            "version": None,
            "error": "unreachable",
        }

    return {
        "configured": True,
        "sealed": status.get("sealed", True),
        "url": settings.vault_url,
        "version": status.get("version"),
        "second_factor": status.get("second_factor"),
    }


async def require_vault_unsealed():
    """Guard -- raises RuntimeError if vault is configured but sealed."""
    if not vault_configured():
        return
    if not await vault_is_unsealed():
        url = settings.vault_url or "(from DB)"
        logger.warning(
            "Vault guard blocked operation: vault at %s is sealed or unreachable",
            url,
        )
        raise VaultSealedError(
            f"Vault is sealed or unreachable ({url}) — "
            f"unlock rhorizon or remove VAULT_URL/VAULT_TOKEN from .env to disable"
        )


class VaultSealedError(RuntimeError):
    """Raised when an operation requires an unsealed vault."""

    pass
