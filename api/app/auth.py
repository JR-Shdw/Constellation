# DO NOT REMOVE: SPDX header + copyright are part of the Apache-2.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Constellation · Author: shdw · License: Apache-2.0
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Authentication — Authelia SSO + Bearer tokens (env + DB).

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
See: NOTICE, LICENSE

Permission model:
  - .env tokens (collect_token, secret_key) keep working as before
  - DB tokens (api_tokens table) have granular permissions per scope
  - Scopes: collect, read, backup, cicd, deployments, managers,
            automation, repositories, findings, settings, tokens
  - Modes: "r" (read), "w" (write), "rw" (both)

Token storage:
  - Tokens are hashed with HMAC-SHA512 using a per-instance key
  - DB dump alone is useless without TOKEN_HMAC_KEY from .env
  - Raw token shown ONCE at creation, never recoverable
  - Only truncated hash displayed in listings
"""

import hmac
import logging
from hashlib import sha512

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .database import get_db

logger = logging.getLogger(__name__)


def _const_eq(a: str, b: str) -> bool:
    """Constant-time string compare. Guards token checks against timing attacks."""
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


bearer_scheme = HTTPBearer(auto_error=False)

# Traefik networks that are trusted to set Remote-User
_TRUSTED_PROXIES = {"172.16.", "172.17.", "172.18.", "172.19.", "172.20."}

# SSO group → role mapping
# Groups come from Authelia (Remote-Groups), Authentik, or Keycloak headers
# Higher priority role wins when user has multiple groups
# Builtins — always present, DB mappings are merged on top
_BUILTIN_GROUP_MAP = {
    "admin": "admin",
    "admins": "admin",
    "secops": "admin",
    "ops": "ops",
    "viewer": "viewer",
}
_ROLE_PRIORITY = {"admin": 3, "ops": 2, "viewer": 1}

# Live mapping: builtins + DB overrides (loaded at startup + on save)
_GROUP_ROLE_MAP: dict[str, str] = dict(_BUILTIN_GROUP_MAP)


async def get_group_mappings(db) -> dict[str, str]:
    """Return current group→role mappings (DB merged over builtins)."""
    import json

    from sqlalchemy import text

    merged = dict(_BUILTIN_GROUP_MAP)
    row = await db.execute(
        text("SELECT value FROM alert_settings WHERE key = 'sso_group_mappings'")
    )
    val = row.scalar_one_or_none()
    if val:
        try:
            db_map = json.loads(val)
            merged.update(db_map)
        except (json.JSONDecodeError, TypeError):
            pass
    return merged


async def reload_group_mappings(db) -> None:
    """Reload group mappings from DB into memory."""
    global _GROUP_ROLE_MAP
    _GROUP_ROLE_MAP = await get_group_mappings(db)
    logger.info("[auth] reloaded SSO group mappings: %d entries", len(_GROUP_ROLE_MAP))


def _resolve_sso_role(request: Request) -> str:
    """Extract highest-priority role from SSO group headers.

    Reads Remote-Groups (Authelia), X-Auth-Groups (Authentik),
    or X-Forwarded-Groups (Keycloak). Returns role string.
    """
    raw = (
        request.headers.get("Remote-Groups")
        or request.headers.get("X-Auth-Groups")
        or request.headers.get("X-Forwarded-Groups")
        or ""
    )
    if not raw:
        return "viewer"  # SSO user with no groups = read-only (least privilege)
    groups = [g.strip().lower() for g in raw.split(",") if g.strip()]
    best_role = "viewer"
    best_prio = 0
    for g in groups:
        role = _GROUP_ROLE_MAP.get(g)
        if role and _ROLE_PRIORITY.get(role, 0) > best_prio:
            best_role = role
            best_prio = _ROLE_PRIORITY[role]
    return best_role


# All valid permission scopes
SCOPES = (
    "collect",
    "read",
    "backup",
    "cicd",
    "deployments",
    "managers",
    "automation",
    "repositories",
    "findings",
    "misconf",
    "settings",
    "tokens",
    "scheduler",
    "incidents",
    "itsm",
)


def hash_token(token: str) -> str:
    """HMAC-SHA512 hash of a token using the per-instance key.

    128-char hex digest (512 bits). Even with a full DB dump,
    tokens cannot be reversed or brute-forced without
    TOKEN_HMAC_KEY from the instance's .env file.
    """
    return hmac.new(
        settings.token_hmac_key.encode(),
        token.encode(),
        sha512,
    ).hexdigest()


def mask_hash(token_hash: str) -> str:
    """Return first 12 chars of hash for display (identification only)."""
    return token_hash[:12] + "..."


def _is_trusted_proxy(request: Request) -> bool:
    """Check if request comes from a trusted reverse proxy (Traefik)."""
    client = request.client
    if not client:
        return False
    ip = client.host or ""
    return any(ip.startswith(p) for p in _TRUSTED_PROXIES)


async def _resolve_db_token(token: str, db: AsyncSession) -> dict | None:
    """Look up a Bearer token in api_tokens. Returns row dict or None.

    The returned dict carries an `is_honey` flag (defaulting to False on
    pre-migration schemas). Callers that have request context should fire
    `honey.alert_honey_token` when this is true — auth itself completes
    normally so the attacker doesn't notice.
    """
    token_h = hash_token(token)
    result = await db.execute(
        text("""
        SELECT id, name, permissions, active, expires_at,
               COALESCE(is_honey, FALSE) AS is_honey
        FROM api_tokens
        WHERE token_hash = :h
        LIMIT 1
        """),
        {"h": token_h},
    )
    row = result.mappings().first()
    if not row:
        return None
    if not row["active"]:
        return None
    if row["expires_at"]:
        from datetime import datetime, timezone

        if row["expires_at"] < datetime.now(timezone.utc):
            return None
    # Update last_used_at, but at most once per minute per token. Every
    # write request (collect/heartbeat/cves reports from thousands of nodes,
    # all sharing the collect_token) would otherwise rewrite this row on each
    # call — WAL churn and row-lock contention on one hot row. The guard makes
    # repeat calls within the window a no-op (0 rows, no new row version);
    # 60s granularity is plenty for a "last seen" indicator.
    await db.execute(
        text("""
        UPDATE api_tokens SET last_used_at = NOW()
        WHERE id = :id
          AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '60 seconds')
        """),
        {"id": row["id"]},
    )
    return dict(row)


def _check_permission(permissions: dict, scope: str, mode: str) -> bool:
    """Check if a permissions dict grants the requested scope+mode."""
    if permissions.get("admin") in ("rw", True, "true"):
        return True
    perm = permissions.get(scope, "")
    if mode == "r":
        return "r" in perm
    if mode == "w":
        return "w" in perm
    return False


# Legacy guards (backward compat — keep working with .env tokens)


async def require_collect_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> str:
    """Authenticate write access for collection endpoints.

    Accepts:
    1. .env COLLECT_TOKEN (legacy)
    2. .env SECRET_KEY (admin)
    3. DB token with 'collect: w' permission
    """
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")

    token = credentials.credentials

    # Legacy .env tokens (deprecated — migrate to DB tokens)
    if _const_eq(token, settings.collect_token):
        logger.warning("[auth] legacy .env COLLECT_TOKEN used — migrate to DB tokens")
        return "collect"
    if _const_eq(token, settings.secret_key):
        logger.warning("[auth] legacy .env SECRET_KEY used — migrate to DB tokens")
        return "admin"

    # DB token
    row = await _resolve_db_token(token, db)
    if row and _check_permission(row["permissions"], "collect", "w"):
        if row.get("is_honey"):
            from .honey import alert_honey_token

            await alert_honey_token(db, row["name"], request)
        return row["name"]

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Constellation/Apache-2.0: Invalid or insufficient token",
    )


async def require_auth(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> str:
    """Authenticate read/admin access.

    Accepts:
    1. Authelia Remote-User header (trusted proxy only)
    2. .env SECRET_KEY (admin)
    3. DB token with 'read: r' permission

    Stores SSO role in request.state.sso_role for downstream use.
    """
    # Authelia forwardauth headers — only trust from Traefik network
    if _is_trusted_proxy(request):
        remote_user = request.headers.get("Remote-User")
        if remote_user:
            request.state.sso_role = _resolve_sso_role(request)
            request.state.sso_groups = (
                request.headers.get("Remote-Groups")
                or request.headers.get("X-Auth-Groups")
                or request.headers.get("X-Forwarded-Groups")
                or ""
            )
            request.state.sso_name = (
                request.headers.get("Remote-Name")
                or request.headers.get("X-Auth-Name")
                or remote_user
            )
            return remote_user

    # Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

        # Legacy .env admin token (deprecated — migrate to DB tokens)
        if _const_eq(token, settings.secret_key):
            logger.warning("[auth] legacy .env SECRET_KEY used — migrate to DB tokens")
            return "admin"

        # DB token — require at least read scope
        row = await _resolve_db_token(token, db)
        if row and _check_permission(row["permissions"], "read", "r"):
            if row.get("is_honey"):
                from .honey import alert_honey_token

                await alert_honey_token(db, row["name"], request)
            return row["name"]

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Authentication required (Authelia or Bearer token)",
    )


# Granular permission guard — for new endpoints


def require_permission(scope: str, mode: str = "r"):
    """FastAPI dependency factory for granular permission checks.

    Usage:
        @router.get("/something")
        async def get_something(
            actor=Depends(require_permission("read", "r")),
        ): ...

        @router.post("/something")
        async def create_something(
            actor=Depends(require_permission("automation", "w")),
        ): ...
    """

    async def _guard(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ) -> str:
        # Authelia SSO — role-based access from group headers
        if _is_trusted_proxy(request):
            remote_user = request.headers.get("Remote-User")
            if remote_user:
                sso_role = _resolve_sso_role(request)
                # admin = full, ops = read-only, viewer = read-only
                if mode == "w" and sso_role not in ("admin",):
                    raise HTTPException(
                        status.HTTP_403_FORBIDDEN,
                        f"SSO role '{sso_role}' cannot write to {scope}",
                    )
                request.state.sso_role = sso_role
                return remote_user

        # Bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")

        token = auth_header[7:]

        # Legacy .env tokens (deprecated — migrate to DB tokens)
        if _const_eq(token, settings.secret_key):
            logger.warning("[auth] legacy .env SECRET_KEY used — migrate to DB tokens")
            return "admin"
        if _const_eq(token, settings.collect_token):
            # collect_token only has collect:w
            if scope == "collect" and mode == "w":
                logger.warning(
                    "[auth] legacy .env COLLECT_TOKEN used — migrate to DB tokens"
                )
                return "collect"
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")

        # DB token
        row = await _resolve_db_token(token, db)
        if not row:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
        if not _check_permission(row["permissions"], scope, mode):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Token '{row['name']}' lacks {scope}:{mode} permission",
            )
        if row.get("is_honey"):
            from .honey import alert_honey_token

            await alert_honey_token(db, row["name"], request)
        return row["name"]

    return _guard
