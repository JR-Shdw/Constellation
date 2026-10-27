# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..config import settings
from ..crypto import encrypt_setting
from ..database import get_db
from ..models.schemas import (
    FeatureTogglePayload,
    SsoGroupsPayload,
    VaultBootstrapPayload,
    VaultCheckPayload,
    WebhookCreate,
    WebhookPatch,
)
from ..notify import _send_webhook, send_automation_notification

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


async def feature_enabled(feature: str, db: AsyncSession) -> bool:
    """Check if a feature module is enabled (cve, backup)."""
    key = f"feature_{feature}_enabled"
    row = await db.execute(
        text("SELECT value FROM alert_settings WHERE key = :k"),
        {"k": key},
    )
    val = row.scalar_one_or_none()
    return val != "false"


_ALLOWED_KEYS = {
    "cve_severity_threshold",
    "matrix_enabled",
    "matrix_url",
    "matrix_token",
    "matrix_room_cve",
    "matrix_room_security",
    "matrix_room_cicd",
    "matrix_room_backup",
    "matrix_room_cmdb",
    "email_enabled",
    "alert_email",
    "smtp_host",
    "smtp_port",
    "smtp_use_starttls",
    "smtp_use_ssl",
    "smtp_user",
    "smtp_password",
    "smtp_from",
    "smtp_from_name",
    "woodpecker_url",
    "woodpecker_token",
    "gitea_url",
    "gitea_token",
    "gitlab_url",
    "gitlab_token",
    "forgejo_url",
    "forgejo_token",
    "opencve_web_url",
    "opencve_url",
    "opencve_user",
    "opencve_password",
    "cve_count_exclude_medium",
    "cve_count_exclude_low",
    "retention_resolved_cve_days",
    "feature_cve_enabled",
    "feature_backup_enabled",
    "sso_group_mappings",
    "vault_url",
    "vault_token",
}

# Keys that map to config.py Settings (DB overrides env vars)
_CONFIG_KEYS = {
    "woodpecker_url",
    "woodpecker_token",
    "gitea_url",
    "gitea_token",
    "gitlab_url",
    "gitlab_token",
    "forgejo_url",
    "forgejo_token",
    "opencve_web_url",
    "opencve_url",
    "opencve_user",
    "opencve_password",
    "vault_url",
    "vault_token",
}


# Keys that contain secrets — masked in GET responses
_SECRET_KEYS = {
    "matrix_token",
    "woodpecker_token",
    "gitea_token",
    "gitlab_token",
    "forgejo_token",
    "opencve_password",
    "vault_token",
    "smtp_password",
}


@router.get("/alerts")
async def get_alert_settings(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "r")),
):
    rows = await db.execute(text("SELECT key, value FROM alert_settings"))
    result = {}
    for r in rows:
        if r.key in _SECRET_KEYS and r.value:
            # Mask secrets: show only that a value is set
            result[r.key] = "********"
        else:
            result[r.key] = r.value

    # Fill in config values not yet persisted in DB
    # (e.g. vault_url set by auto-discovery or env vars)
    for key in _CONFIG_KEYS:
        if key not in result or not result[key]:
            mem_val = getattr(settings, key, "")
            if mem_val:
                if key in _SECRET_KEYS:
                    result[key] = "********"
                else:
                    result[key] = mem_val

    return result


@router.put("/alerts")
async def update_alert_settings(
    payload: dict[str, str | int | float | bool | None],
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    from .retention import (
        RETENTION_RESOLVED_CVE_MAX,
        RETENTION_RESOLVED_CVE_MIN,
    )

    updated = 0
    changes = {}
    for key, value in payload.items():
        if key not in _ALLOWED_KEYS:
            continue
        # Skip masked secrets (user didn't change the value)
        if key in _SECRET_KEYS and value == "********":
            continue
        # Clamp the slider to its allowed range — UI is authoritative for
        # the bounds but a stray API caller shouldn't be able to set 0 or
        # 99999 days.
        if key == "retention_resolved_cve_days":
            try:
                n = int(value)
            except (TypeError, ValueError):
                continue
            value = max(
                RETENTION_RESOLVED_CVE_MIN,
                min(RETENTION_RESOLVED_CVE_MAX, n),
            )
        # Encrypt secrets before storing
        store_value = encrypt_setting(str(value)) if key in _SECRET_KEYS else str(value)
        await db.execute(
            text("""
            INSERT INTO alert_settings (key, value, updated_at)
            VALUES (:key, :value, NOW())
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                updated_at = NOW()
        """),
            {"key": key, "value": store_value},
        )
        # Don't log token values
        changes[key] = "***" if "token" in key else str(value)
        updated += 1

    # Apply config overrides in memory (DB takes priority over env vars)
    for key in _CONFIG_KEYS:
        if key in payload and payload[key]:
            # Don't overwrite in-memory secrets with masked placeholder
            if key in _SECRET_KEYS and payload[key] == "********":
                continue
            setattr(settings, key, str(payload[key]))

    # Invalidate vault cache when vault settings change
    if "vault_url" in payload or "vault_token" in payload:
        from ..connectors.vault import invalidate_cache

        invalidate_cache()

    if changes:
        await log_action(
            db,
            actor=actor,
            action="update_settings",
            target_type="alert_settings",
            detail=changes,
        )
    await db.commit()
    return {"status": "ok", "updated": updated}


# SSO Group Mappings (O.U.)

_VALID_ROLES = ("admin", "ops", "viewer")


@router.get("/sso-groups")
async def get_sso_groups(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "r")),
):
    """Return SSO group→role mappings (DB overrides + builtins)."""
    from ..auth import get_group_mappings

    mappings = await get_group_mappings(db)
    return {"mappings": mappings, "roles": list(_VALID_ROLES)}


@router.put("/sso-groups")
async def update_sso_groups(
    payload: SsoGroupsPayload,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Save SSO group→role mappings. Format: {"mappings": {"group": "role"}}."""
    import json

    mappings = payload.mappings
    # Validate roles
    clean = {}
    for group, role in mappings.items():
        group = group.strip().lower()
        role = role.strip().lower()
        if not group:
            continue
        if role not in _VALID_ROLES:
            raise HTTPException(400, f"Invalid role '{role}' for group '{group}'")
        clean[group] = role

    await db.execute(
        text("""
        INSERT INTO alert_settings (key, value, updated_at)
        VALUES ('sso_group_mappings', :val, NOW())
        ON CONFLICT (key) DO UPDATE SET
            value = EXCLUDED.value,
            updated_at = NOW()
        """),
        {"val": json.dumps(clean)},
    )
    await log_action(
        db,
        actor=actor,
        action="update_sso_groups",
        target_type="alert_settings",
        detail={"groups": len(clean)},
    )
    await db.commit()

    # Reload in-memory cache
    from ..auth import reload_group_mappings

    await reload_group_mappings(db)

    return {"status": "ok", "mappings": clean}


# Notification Webhooks CRUD


@router.get("/webhooks")
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "r")),
):
    rows = await db.execute(text("SELECT * FROM notification_webhooks ORDER BY name"))
    items = []
    for r in rows.mappings():
        item = dict(r)
        if item.get("webhook_url"):
            item["webhook_url"] = "********"
        items.append(item)
    return {"items": items}


@router.post("/webhooks")
async def create_webhook(
    payload: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    row = await db.execute(
        text("""
        INSERT INTO notification_webhooks
            (name, platform, webhook_url, enabled,
             route_cve, route_security, route_cicd, route_backup,
             default_channel, channel_cve, channel_security,
             channel_cicd, channel_backup)
        VALUES
            (:name, :platform, :url, :enabled,
             :r_cve, :r_sec, :r_cicd, :r_backup,
             :ch_default, :ch_cve, :ch_sec, :ch_cicd, :ch_backup)
        RETURNING id
        """),
        {
            "name": payload.name,
            "platform": payload.platform,
            "url": payload.webhook_url,
            "enabled": payload.enabled,
            "r_cve": payload.route_cve,
            "r_sec": payload.route_security,
            "r_cicd": payload.route_cicd,
            "r_backup": payload.route_backup,
            "ch_default": payload.default_channel,
            "ch_cve": payload.channel_cve,
            "ch_sec": payload.channel_security,
            "ch_cicd": payload.channel_cicd,
            "ch_backup": payload.channel_backup,
        },
    )
    wh_id = str(row.scalar_one())
    await log_action(
        db,
        actor=actor,
        action="create_webhook",
        target_type="webhook",
        target_id=wh_id,
        detail={"name": payload.name, "platform": payload.platform},
    )
    await db.commit()
    return {"status": "ok", "id": wh_id}


@router.put("/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    payload: WebhookPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    validate_uuid(webhook_id)
    fields = payload.model_dump(exclude_none=True)
    if not fields:
        return {"status": "ok", "changed": False}

    # Explicit column whitelist — keep this injection-safe locally rather than
    # relying on the Pydantic model dropping unknown fields.
    allowed = {
        "name",
        "platform",
        "webhook_url",
        "enabled",
        "route_cve",
        "route_security",
        "route_cicd",
        "route_backup",
        "default_channel",
        "channel_cve",
        "channel_security",
        "channel_cicd",
        "channel_backup",
    }
    sets = []
    params: dict = {"wid": webhook_id}
    for k, v in fields.items():
        if k not in allowed:
            continue
        sets.append(f"{k} = :{k}")
        params[k] = v
    sets.append("updated_at = NOW()")

    await db.execute(
        text(
            f"UPDATE notification_webhooks SET {', '.join(sets)} "
            f"WHERE id = CAST(:wid AS uuid)"
        ),
        params,
    )
    await log_action(
        db,
        actor=actor,
        action="update_webhook",
        target_type="webhook",
        target_id=webhook_id,
    )
    await db.commit()
    return {"status": "ok", "changed": True}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    validate_uuid(webhook_id)
    result = await db.execute(
        text("DELETE FROM notification_webhooks WHERE id = CAST(:wid AS uuid)"),
        {"wid": webhook_id},
    )
    if result.rowcount == 0:
        raise HTTPException(404, "Webhook not found")
    await log_action(
        db,
        actor=actor,
        action="delete_webhook",
        target_type="webhook",
        target_id=webhook_id,
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "w")),
):
    validate_uuid(webhook_id)
    row = await db.execute(
        text(
            "SELECT webhook_url, platform, default_channel "
            "FROM notification_webhooks "
            "WHERE id = CAST(:wid AS uuid)"
        ),
        {"wid": webhook_id},
    )
    wh = row.mappings().first()
    if not wh:
        raise HTTPException(404, "Webhook not found")
    await _send_webhook(
        wh["webhook_url"],
        "[CMDB] Test notification — webhook is working.",
        wh["platform"],
        wh["default_channel"],
    )
    return {"status": "ok", "detail": "Test message sent"}


# Feature Flags

_FEATURE_TABLES = {
    "cve": [
        "cve_host_packages",
        "cve_containers",
        "cve_status",
        "opencve_alerts",
        "opencve_subscriptions",
        "alert_sent",
        # CVE intelligence feeds (RSS/Atom advisories) belong to the CVE
        # feature — wipe them too so DISABLE CVE actually disables ingestion.
        "cve_advisories",
        "cve_feeds",
    ],
    "backup": [
        "backup_runs",
        "backup_repositories",
    ],
}


@router.post("/features/toggle")
async def toggle_feature(
    payload: FeatureTogglePayload,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Enable or disable a feature module (cve, backup).

    Disabling truncates all related tables. Requires typed confirmation.
    """
    feature = payload.feature
    enabled = payload.enabled
    confirm = payload.confirm

    if feature not in ("cve", "backup"):
        raise HTTPException(400, "feature must be 'cve' or 'backup'")
    if enabled is None:
        raise HTTPException(400, "enabled (true/false) required")

    key = f"feature_{feature}_enabled"
    label = feature.upper()

    # Check current state
    current = await feature_enabled(feature, db)
    if current == enabled:
        state = "enabled" if enabled else "disabled"
        return {"status": "ok", "detail": f"{label} already {state}"}

    # Validate confirmation
    expected = f"ENABLE {label}" if enabled else f"DISABLE {label}"
    if confirm != expected:
        raise HTTPException(400, f"Confirmation required: type '{expected}' to confirm")

    # Disable → TRUNCATE tables
    if not enabled:
        tables = _FEATURE_TABLES.get(feature, [])
        for table in tables:
            await db.execute(text(f"TRUNCATE {table} CASCADE"))
        # Drop feature-owned scheduler jobs so they stop ticking.
        # scheduler_jobs is a shared table — can't add it to _FEATURE_TABLES.
        if feature == "cve":
            await db.execute(
                text("DELETE FROM scheduler_jobs WHERE job_type = 'cve_feeds_fetch'")
            )
        logger.warning(
            "[features] %s DISABLED by %s — truncated %d tables",
            label,
            actor,
            len(tables),
        )

    # Update flag
    await db.execute(
        text("""
        INSERT INTO alert_settings (key, value, updated_at)
        VALUES (:k, :v, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        """),
        {"k": key, "v": "true" if enabled else "false"},
    )

    await log_action(
        db,
        actor=actor,
        action=f"feature_{'enable' if enabled else 'disable'}",
        target_type="feature",
        detail={"feature": feature, "enabled": enabled},
    )
    await db.commit()

    # Notify
    action_word = "enabled" if enabled else "disabled"
    msg = f"[CMDB] {label} module {action_word} by {actor}"
    if not enabled:
        msg += f" — {len(_FEATURE_TABLES.get(feature, []))} tables truncated"
    try:
        await send_automation_notification("feature_toggle", msg, db)
        await db.commit()
    except Exception:
        logger.warning("[features] notification failed")

    return {
        "status": "ok",
        "feature": feature,
        "enabled": enabled,
        "detail": msg,
    }


# Vault Check


@router.get("/vault/status")
async def vault_status(
    _: str = Depends(require_permission("settings", "r")),
):
    """Vault status for frontend — uses configured vault URL."""
    from ..connectors.vault import vault_status_detail

    return await vault_status_detail()


@router.post("/vault-check")
async def vault_check(
    payload: VaultCheckPayload,
    _: str = Depends(require_permission("settings", "r")),
):
    """Check if rhorizon is reachable and unsealed (test with custom URL)."""
    import httpx

    vault_url = payload.vault_url.rstrip("/")
    if not vault_url:
        raise HTTPException(400, "vault_url required")

    last_err = None
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{vault_url}/api/v1/vault/status")
            if r.status_code == 200:
                data = r.json()
                return {"status": "ok", "sealed": data.get("sealed", True)}
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)[:200]
        if attempt < 2:
            import asyncio

            await asyncio.sleep(1)

    return {"status": "error", "detail": last_err or "unreachable"}


_DISCOVER_URLS = [
    "http://rhorizon_api:8200",
    "http://rhorizon-api:8200",
    "http://rhorizon:8200",
    "http://vault:8200",
]


@router.post("/vault/discover")
async def vault_discover(
    _: str = Depends(require_permission("settings", "r")),
):
    """Probe Docker-internal URLs to find rhorizon."""
    import httpx

    for url in _DISCOVER_URLS:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{url}/api/v1/vault/status")
            if r.status_code == 200:
                data = r.json()
                return {
                    "status": "found",
                    "url": url,
                    "sealed": data.get("sealed", True),
                }
        except Exception:
            continue

    return {"status": "not_found"}


_VAULT_SECRET_MAP = {
    "cmdb-secret-key": "secret_key",
    "cmdb-collect-token": "collect_token",
    "cmdb-token-hmac-key": "token_hmac_key",
    "cmdb-woodpecker-token": "woodpecker_token",
    "cmdb-gitea-token": "gitea_token",
    "cmdb-gitlab-token": "gitlab_token",
    "cmdb-forgejo-token": "forgejo_token",
    "cmdb-opencve-password": "opencve_password",
}


@router.get("/vault/secrets")
async def vault_secrets_status(
    _: str = Depends(require_permission("settings", "r")),
):
    """Check which mapped secrets exist in vault (no values returned)."""
    import httpx

    from ..config import settings as cfg
    from ..connectors.vault import vault_configured

    if not vault_configured():
        return {
            "configured": False,
            "secrets": [
                {"vault_name": k, "setting": v, "status": "not_configured"}
                for k, v in _VAULT_SECRET_MAP.items()
            ],
        }

    secrets = []
    try:
        headers = {"Authorization": f"Bearer {cfg.vault_token}"}
        async with httpx.AsyncClient(base_url=cfg.vault_url, timeout=5) as client:
            for vault_name, setting in _VAULT_SECRET_MAP.items():
                try:
                    r = await client.get(
                        f"/api/v1/vault/secrets/{vault_name}",
                        headers=headers,
                    )
                    if r.status_code == 200:
                        loaded = bool(getattr(cfg, setting, ""))
                        secrets.append(
                            {
                                "vault_name": vault_name,
                                "setting": setting,
                                "status": "loaded" if loaded else "exists",
                            }
                        )
                    elif r.status_code == 404:
                        secrets.append(
                            {
                                "vault_name": vault_name,
                                "setting": setting,
                                "status": "missing",
                            }
                        )
                    else:
                        secrets.append(
                            {
                                "vault_name": vault_name,
                                "setting": setting,
                                "status": "error",
                            }
                        )
                except Exception:
                    secrets.append(
                        {
                            "vault_name": vault_name,
                            "setting": setting,
                            "status": "error",
                        }
                    )
    except Exception as e:
        return {
            "configured": True,
            "error": str(e)[:200],
            "secrets": [
                {"vault_name": k, "setting": v, "status": "unreachable"}
                for k, v in _VAULT_SECRET_MAP.items()
            ],
        }

    return {"configured": True, "secrets": secrets}


@router.post("/rotation-check")
async def rotation_check(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "w")),
):
    """Scan vault secrets for age >= 330d and alert/clear via Matrix.

    Triggered daily by the `secret-rotation-check` scheduler job.
    """
    from ..utils.rotation import check_rotations

    return await check_rotations(db)


# Secrets that can be auto-generated (random base64)
_BOOTSTRAP_SECRETS = {
    "cmdb-secret-key": "secret_key",
    "cmdb-collect-token": "collect_token",
    "cmdb-token-hmac-key": "token_hmac_key",
}


@router.post("/vault/bootstrap")
async def vault_bootstrap(
    payload: VaultBootstrapPayload,
    db: AsyncSession = Depends(get_db),
    token_info: str = Depends(require_permission("settings", "w")),
):
    """Auto-generate required CMDB secrets in rhorizon.

    Creates random base64 secrets for secret_key, collect_token, and
    token_hmac_key.  Skips secrets that already exist.  Requires a vault
    token with ``secrets:rw`` scope on the ``cmdb`` namespace.
    """
    import secrets as _secrets

    import httpx

    from ..config import settings as cfg

    vault_url = (payload.vault_url or cfg.vault_url or "").rstrip("/")
    vault_token = payload.vault_token or cfg.vault_token or ""

    if not vault_url:
        raise HTTPException(400, "vault_url required (not configured)")
    if not vault_token:
        raise HTTPException(400, "vault_token required (not configured)")

    namespace = payload.namespace
    results = []

    try:
        headers = {"Authorization": f"Bearer {vault_token}"}
        async with httpx.AsyncClient(
            base_url=vault_url,
            timeout=10,
            headers=headers,
            follow_redirects=True,
        ) as client:
            # Verify vault is unsealed
            r = await client.get("/api/v1/vault/status")
            if r.status_code != 200 or r.json().get("sealed"):
                raise HTTPException(503, "Vault is sealed or unreachable")

            for vault_name, setting in _BOOTSTRAP_SECRETS.items():
                # Check if secret already exists
                r = await client.get(f"/api/v1/vault/secrets/{vault_name}")
                if r.status_code == 200:
                    results.append(
                        {
                            "vault_name": vault_name,
                            "setting": setting,
                            "status": "exists",
                        }
                    )
                    continue

                # Generate and create
                value = _secrets.token_urlsafe(32)
                r = await client.post(
                    "/api/v1/vault/secrets",
                    json={
                        "name": vault_name,
                        "value": value,
                        "namespace": namespace,
                    },
                )
                if r.status_code in (200, 201):
                    results.append(
                        {
                            "vault_name": vault_name,
                            "setting": setting,
                            "status": "created",
                        }
                    )
                else:
                    detail = ""
                    try:
                        detail = r.json().get("detail", "")
                    except Exception:
                        pass
                    results.append(
                        {
                            "vault_name": vault_name,
                            "setting": setting,
                            "status": "error",
                            "detail": f"HTTP {r.status_code}: {detail}"[:200],
                        }
                    )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"Vault unreachable: {str(e)[:200]}")

    created = sum(1 for r in results if r["status"] == "created")

    await log_action(
        db,
        actor=token_info,
        action="vault_bootstrap",
        target_type="vault",
        detail={"created": created, "results": results},
    )
    await db.commit()

    return {"results": results, "created": created}
