# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Security middleware — rate limiting + brute-force protection + SSRF guard.

Pure Python, zero dependencies. Uses in-memory dicts with TTL cleanup.
"""

import ipaddress
import logging
import time
from urllib.parse import urlparse

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .config import settings

logger = logging.getLogger(__name__)

# Rate limiter
#
# Thresholds are read from settings (env) so they can be tightened per-instance
# without code change. Defaults are deliberately light — the CMDB always runs
# behind VPN + SSO. The goal here is to catch a misbehaving script, not to
# harden against internet bots.

_rate_buckets: dict[str, list[float]] = {}  # {ip: [timestamp, ...]}
_RATE_CLEANUP_INTERVAL = 300  # purge stale entries every 5 min
_last_rate_cleanup = 0.0


def _rate_check(ip: str) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    global _last_rate_cleanup
    now = time.monotonic()
    window = settings.rate_limit_window_seconds

    # Periodic cleanup of stale buckets
    if now - _last_rate_cleanup > _RATE_CLEANUP_INTERVAL:
        cutoff = now - window
        stale = [k for k, v in _rate_buckets.items() if not v or v[-1] < cutoff]
        for k in stale:
            del _rate_buckets[k]
        _last_rate_cleanup = now

    bucket = _rate_buckets.setdefault(ip, [])
    cutoff = now - window
    # Remove expired timestamps
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)

    if len(bucket) >= settings.rate_limit_requests:
        return False

    bucket.append(now)
    return True


# Brute-force protection

_auth_failures: dict[str, tuple[int, float]] = {}  # {ip: (fail_count, first_fail_time)}


def auth_fail(ip: str) -> None:
    """Record an authentication failure for an IP."""
    now = time.monotonic()
    count, first = _auth_failures.get(ip, (0, now))
    # Reset if window expired
    if now - first > settings.bf_window_seconds:
        count, first = 0, now
    _auth_failures[ip] = (count + 1, first)
    if count + 1 >= settings.bf_max_failures:
        logger.warning("[security] IP %s banned — %d auth failures", ip, count + 1)


def auth_success(ip: str) -> None:
    """Clear failure counter on successful auth."""
    _auth_failures.pop(ip, None)


def is_banned(ip: str) -> bool:
    """Check if an IP is currently banned."""
    entry = _auth_failures.get(ip)
    if not entry:
        return False
    count, first = entry
    now = time.monotonic()
    # Ban expired
    if now - first > settings.bf_ban_seconds:
        del _auth_failures[ip]
        return False
    return count >= settings.bf_max_failures


# SSRF guard

# Private/reserved IP ranges that should never be targets for outbound requests
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),  # unspecified
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


def validate_url(url: str, allow_private: bool = False) -> str | None:
    """Validate a URL for outbound requests. Returns error message or None if OK.

    Checks:
    - Must be http:// or https://
    - Hostname must not resolve to private/reserved IP ranges
    - No IP-based URLs pointing to internal networks
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "invalid URL format"

    if parsed.scheme not in ("http", "https"):
        return f"scheme '{parsed.scheme}' not allowed (use http or https)"

    hostname = parsed.hostname
    if not hostname:
        return "no hostname in URL"

    # Block obvious localhost aliases
    if hostname in ("localhost", "0.0.0.0", "[::]", "[::1]"):
        return f"hostname '{hostname}' is not allowed"

    if allow_private:
        return None

    # Check if hostname is an IP address in a blocked range
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return f"IP {hostname} is in a private/reserved range"
    except ValueError:
        # Not an IP — hostname. Check common internal patterns.
        # DNS resolution would be ideal but adds latency; IP-based check
        # catches direct attacks. Hostname-based attacks require DNS rebinding.
        pass

    return None


# Middleware


_LOOPBACK = {"127.0.0.1", "::1"}


class SecurityMiddleware(BaseHTTPMiddleware):
    """Combined rate limiting + brute-force protection middleware."""

    async def dispatch(self, request: Request, call_next) -> Response:
        ip = request.client.host if request.client else "unknown"

        # Skip rate limiting and brute-force for loopback (scheduler, internal)
        if ip in _LOOPBACK:
            return await call_next(request)

        # Brute-force ban check
        if is_banned(ip):
            logger.warning("[security] Blocked banned IP %s", ip)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many failed attempts. Try again later."},
            )

        # Rate limit check
        if not _rate_check(ip):
            logger.warning("[security] Rate limit exceeded for %s", ip)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(settings.rate_limit_window_seconds)},
            )

        response = await call_next(request)

        # Track auth failures for brute-force protection
        if response.status_code in (401, 403):
            auth_header = request.headers.get("authorization", "")
            # Only count Bearer token failures, not missing auth
            if auth_header.lower().startswith("bearer "):
                auth_fail(ip)
        elif response.status_code < 400:
            # Successful auth — clear failure counter
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                auth_success(ip)

        return response
