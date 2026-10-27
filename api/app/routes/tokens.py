# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""API Token management — CRUD with granular permissions.

Security model:
  - Tokens hashed with HMAC-SHA512 (per-instance key from TOKEN_HMAC_KEY)
  - Raw token shown ONCE at creation — never recoverable
  - DB dump alone is useless without the HMAC key
  - Listings show only truncated hash for identification
  - Lost token? Regenerate (new value, same permissions) or delete
"""

import json
import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import SCOPES, hash_token, mask_hash, require_permission
from ..database import get_db
from ..utils.sql import where_clause

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])


def _validate_permissions(permissions: dict) -> dict:
    """Validate and normalize a permissions dict."""
    cleaned = {}
    for key, val in permissions.items():
        if key == "admin":
            if val in ("rw", True, "true"):
                cleaned["admin"] = "rw"
            continue
        if key not in SCOPES:
            raise HTTPException(
                400, f"Unknown scope: {key}. Valid: {', '.join(SCOPES)}"
            )
        val = str(val).lower()
        if val not in ("r", "w", "rw", ""):
            raise HTTPException(400, f"Invalid mode for {key}: {val}. Use r, w, or rw")
        if val:
            cleaned[key] = val
    return cleaned


def _safe_token_row(row) -> dict:
    """Convert a token DB row to a safe dict (hash masked, no raw token)."""
    d = dict(row)
    d["token_hint"] = mask_hash(d.pop("token_hash", ""))
    return d


@router.get("")
async def list_tokens(
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "r")),
):
    """List all API tokens. Hash truncated, raw token never shown."""
    rows = await db.execute(
        text("""
        SELECT id, name, token_hash, permissions, active, description,
               created_by, created_at, last_used_at, expires_at
        FROM api_tokens
        ORDER BY active DESC, name
        """)
    )
    return {"items": [_safe_token_row(r._mapping) for r in rows]}


@router.post("")
async def create_token(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "w")),
):
    """Create a new API token.

    The raw token is returned ONCE. It is hashed with HMAC-SHA512
    and cannot be recovered. If lost, use /regenerate.

    Body:
        name: unique name for the token
        permissions: {"scope": "r|w|rw", ...}
        description: optional description
        expires_at: optional ISO datetime
    """
    name = payload.get("name", "").strip()
    if not name:
        raise HTTPException(400, "name is required")

    permissions = _validate_permissions(payload.get("permissions", {}))
    if not permissions:
        raise HTTPException(400, "At least one permission scope is required")

    raw_token = f"cmdb_{secrets.token_urlsafe(32)}"
    token_h = hash_token(raw_token)
    is_honey = bool(payload.get("is_honey", False))

    try:
        result = await db.execute(
            text("""
            INSERT INTO api_tokens
                (name, token_hash, permissions, description,
                 created_by, expires_at, is_honey)
            VALUES
                (:name, :hash, CAST(:perms AS jsonb), :desc,
                 :actor, :expires, :is_honey)
            RETURNING id
            """),
            {
                "name": name,
                "hash": token_h,
                "perms": json.dumps(permissions),
                "desc": payload.get("description"),
                "actor": actor,
                "expires": payload.get("expires_at"),
                "is_honey": is_honey,
            },
        )
        token_id = str(result.scalar_one())
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(409, f"Token name '{name}' already exists") from e
        raise

    await log_action(
        db,
        actor=actor,
        action="create_token",
        target_type="api_token",
        target_id=token_id,
        detail={"name": name, "permissions": permissions},
    )
    await db.commit()

    return {
        "status": "ok",
        "id": token_id,
        "name": name,
        "token": raw_token,
        "token_hint": mask_hash(token_h),
        "permissions": permissions,
        "warning": "Ce token ne sera plus jamais affiché. Notez-le maintenant.",
    }


@router.get("/{token_id}")
async def get_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "r")),
):
    """Get token details. Raw token never shown — only truncated hash."""
    validate_uuid(token_id, "token_id")
    row = await db.execute(
        text("""
        SELECT id, name, token_hash, permissions, active, description,
               created_by, created_at, last_used_at, expires_at
        FROM api_tokens WHERE id = CAST(:id AS uuid)
        """),
        {"id": token_id},
    )
    token = row.mappings().first()
    if not token:
        raise HTTPException(404, "Token not found")
    return _safe_token_row(token)


@router.put("/{token_id}")
async def update_token(
    token_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "w")),
):
    """Update token permissions, active status, or description.

    Cannot change the token value — use /regenerate for that.

    Body (all optional):
        permissions: {"scope": "r|w|rw", ...} — replaces existing
        active: true/false
        description: text
        expires_at: ISO datetime or null
    """
    validate_uuid(token_id, "token_id")

    sets = []
    params: dict = {"id": token_id}
    changes = {}

    if "permissions" in payload:
        perms = _validate_permissions(payload["permissions"])
        sets.append("permissions = CAST(:perms AS jsonb)")
        params["perms"] = json.dumps(perms)
        changes["permissions"] = perms

    if "active" in payload:
        sets.append("active = :active")
        params["active"] = bool(payload["active"])
        changes["active"] = payload["active"]

    if "description" in payload:
        sets.append("description = :desc")
        params["desc"] = payload["description"]
        changes["description"] = payload["description"]

    if "expires_at" in payload:
        sets.append("expires_at = :expires")
        params["expires"] = payload["expires_at"]

    if not sets:
        return {"status": "ok", "changed": False}

    await db.execute(
        text(f"UPDATE api_tokens SET {', '.join(sets)} WHERE id = CAST(:id AS uuid)"),
        params,
    )
    await log_action(
        db,
        actor=actor,
        action="update_token",
        target_type="api_token",
        target_id=token_id,
        detail=changes,
    )
    await db.commit()
    return {"status": "ok", "changed": True}


@router.post("/{token_id}/regenerate")
async def regenerate_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "w")),
):
    """Generate a new token value. Old token is immediately invalidated.

    Use this when a token is compromised or lost.
    Permissions, name, and description are preserved.
    The new token is shown ONCE — store it securely.
    """
    validate_uuid(token_id, "token_id")

    row = await db.execute(
        text("SELECT id, name FROM api_tokens WHERE id = CAST(:id AS uuid)"),
        {"id": token_id},
    )
    existing = row.mappings().first()
    if not existing:
        raise HTTPException(404, "Token not found")

    raw_token = f"cmdb_{secrets.token_urlsafe(32)}"
    token_h = hash_token(raw_token)

    await db.execute(
        text("""
        UPDATE api_tokens
        SET token_hash = :hash, last_used_at = NULL
        WHERE id = CAST(:id AS uuid)
        """),
        {"hash": token_h, "id": token_id},
    )
    await log_action(
        db,
        actor=actor,
        action="regenerate_token",
        target_type="api_token",
        target_id=token_id,
        detail={"name": existing["name"]},
    )
    await db.commit()

    return {
        "status": "ok",
        "id": token_id,
        "name": existing["name"],
        "token": raw_token,
        "token_hint": mask_hash(token_h),
        "warning": "Ancien token invalidé. Notez le nouveau maintenant.",
    }


@router.post("/bulk/revoke")
async def bulk_revoke_tokens(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "w")),
):
    """Bulk revoke tokens by name prefix or expiration status.

    Body:
        prefix: str — revoke all tokens whose name starts with this (e.g. "node-")
        expired: bool — revoke all expired tokens
        delete: bool — permanently delete instead of soft revoke (default: false)
    """
    prefix = payload.get("prefix", "")
    expired_only = payload.get("expired", False)
    hard_delete = payload.get("delete", False)

    if not prefix and not expired_only:
        raise HTTPException(400, "Provide 'prefix' or 'expired: true'")

    conditions = ["active = true"]
    params: dict = {}

    if prefix:
        conditions.append("name LIKE :prefix")
        params["prefix"] = prefix + "%"

    if expired_only:
        conditions.append("expires_at IS NOT NULL")
        conditions.append("expires_at < NOW()")

    where = where_clause(conditions)

    # Fetch matching tokens for audit
    rows = await db.execute(
        text(f"SELECT id, name FROM api_tokens {where}"),
        params,
    )
    matched = [dict(r._mapping) for r in rows]

    if not matched:
        return {"status": "ok", "count": 0, "tokens": []}

    if hard_delete:
        await db.execute(
            text(f"DELETE FROM api_tokens {where}"),
            params,
        )
        action = "bulk_delete_tokens"
    else:
        await db.execute(
            text(f"UPDATE api_tokens SET active = false {where}"),
            params,
        )
        action = "bulk_revoke_tokens"

    await log_action(
        db,
        actor=actor,
        action=action,
        target_type="api_token",
        detail={
            "count": len(matched),
            "prefix": prefix or None,
            "expired_only": expired_only,
            "names": [m["name"] for m in matched],
        },
    )
    await db.commit()

    return {
        "status": "ok",
        "action": "deleted" if hard_delete else "revoked",
        "count": len(matched),
        "tokens": [{"id": m["id"], "name": m["name"]} for m in matched],
    }


@router.post("/{token_id}/revoke")
async def revoke_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "w")),
):
    """Revoke a token (set active=false). Can be re-activated later."""
    validate_uuid(token_id, "token_id")
    await db.execute(
        text("UPDATE api_tokens SET active = false WHERE id = CAST(:id AS uuid)"),
        {"id": token_id},
    )
    await log_action(
        db,
        actor=actor,
        action="revoke_token",
        target_type="api_token",
        target_id=token_id,
    )
    await db.commit()
    return {"status": "ok", "active": False}


@router.post("/{token_id}/activate")
async def activate_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "w")),
):
    """Re-activate a revoked token."""
    validate_uuid(token_id, "token_id")
    await db.execute(
        text("UPDATE api_tokens SET active = true WHERE id = CAST(:id AS uuid)"),
        {"id": token_id},
    )
    await log_action(
        db,
        actor=actor,
        action="activate_token",
        target_type="api_token",
        target_id=token_id,
    )
    await db.commit()
    return {"status": "ok", "active": True}


@router.delete("/{token_id}")
async def delete_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "w")),
):
    """Permanently delete a token. Irreversible."""
    validate_uuid(token_id, "token_id")
    row = await db.execute(
        text("SELECT name FROM api_tokens WHERE id = CAST(:id AS uuid)"),
        {"id": token_id},
    )
    name = row.scalar_one_or_none()
    if not name:
        raise HTTPException(404, "Token not found")

    await db.execute(
        text("DELETE FROM api_tokens WHERE id = CAST(:id AS uuid)"),
        {"id": token_id},
    )
    await log_action(
        db,
        actor=actor,
        action="delete_token",
        target_type="api_token",
        target_id=token_id,
        detail={"name": name},
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/check-expiry")
async def check_token_expiry(
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("tokens", "r")),
):
    """Check for tokens expiring soon and send notifications.

    Callable by the scheduler. Looks for active tokens expiring
    within `token_expiry_warning_days` (default 7 days from alert_settings).
    """
    from ..notify import get_alert_settings, send_automation_notification

    settings = await get_alert_settings(db)
    warn_days = int(settings.get("token_expiry_warning_days", "7"))

    rows = await db.execute(
        text("""
        SELECT id, name, expires_at, created_by,
               EXTRACT(DAY FROM expires_at - NOW())::integer AS days_left
        FROM api_tokens
        WHERE active = true
          AND expires_at IS NOT NULL
          AND expires_at > NOW()
          AND expires_at < NOW() + make_interval(days => :days)
        ORDER BY expires_at
        """),
        {"days": warn_days},
    )
    expiring = [dict(r._mapping) for r in rows]

    for tok in expiring:
        msg = (
            f"[TOKEN EXPIRY] Token '{tok['name']}' expires in "
            f"{tok['days_left']} day(s) ({tok['expires_at'].strftime('%Y-%m-%d')})\n"
            f"Created by: {tok['created_by']}"
        )
        await send_automation_notification("node_offline", msg, db)

    await db.commit()
    return {
        "status": "ok",
        "checked": True,
        "warn_days": warn_days,
        "expiring": [
            {
                "name": t["name"],
                "days_left": t["days_left"],
                "expires_at": str(t["expires_at"]),
            }
            for t in expiring
        ],
    }
