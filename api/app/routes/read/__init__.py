# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Read-path routes — nodes, packages, containers, CVEs, secrets, stats, audit."""

import hashlib
import time

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["read"])

_cache: dict = {}
# Hard cap on cache entries (per worker). Each distinct (filters, page) makes
# its own entry and they only expire lazily on read, so without a cap the dict
# grows unbounded across filter/page permutations until the process restarts.
_CACHE_MAX = 1024
_CACHE_TTL = {
    "stats": 30,
    "nodes_list": 60,
    "exposure": 45,
    "compliance": 45,
    "trends": 30,
    "cves": 300,
    "search": 60,
}


def _ttl(key: str) -> int:
    return _CACHE_TTL.get(key.split(":", 1)[0], 30)


def _get_cache(key: str):
    entry = _cache.get(key)
    if entry and (time.monotonic() - entry["ts"]) < _ttl(key):
        return entry["data"]
    return None


def _evict() -> None:
    """Reclaim space at the cap: drop expired entries, then oldest-first."""
    now = time.monotonic()
    for k in [k for k, e in _cache.items() if (now - e["ts"]) >= _ttl(k)]:
        del _cache[k]
    if len(_cache) >= _CACHE_MAX:
        # Oldest by timestamp first; trim back under the cap.
        victims = sorted(_cache, key=lambda k: _cache[k]["ts"])
        for k in victims[: len(_cache) - _CACHE_MAX + 1]:
            del _cache[k]


def _set_cache(key: str, data):
    if key not in _cache and len(_cache) >= _CACHE_MAX:
        _evict()
    _cache[key] = {"data": data, "ts": time.monotonic()}


def _composite_key(ns: str, **parts) -> str:
    """Stable cache key for parameterized endpoints.

    Uses a content hash (not the process-salted builtin hash()) so keys are
    stable across workers and never collide across restarts.
    """
    items = "|".join(f"{k}={parts[k]}" for k in sorted(parts))
    digest = hashlib.blake2b(items.encode(), digest_size=12).hexdigest()
    return f"{ns}:{digest}"


from . import (  # noqa: E402, F401
    audit,
    containers,
    cves,
    nodes,
    packages,
    search,
    secrets,
    stats,
)
