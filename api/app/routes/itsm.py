# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""ITSM integrations — CRUD + test connection + incident tickets."""

import json
import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..connectors import get_itsm
from ..crypto import decrypt_auth_config, encrypt_auth_config, encrypt_setting
from ..database import get_db
from ..models.schemas import ITSMIntegrationCreate, ITSMIntegrationPatch

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/itsm", tags=["itsm"])

_PLATFORMS = {"glpi", "zammad", "jira"}


def _row_to_dict(row) -> dict:
    d = dict(row)
    for k in ("auth_config", "status_map"):
        if isinstance(d.get(k), str):
            try:
                d[k] = json.loads(d[k])
            except Exception:
                d[k] = {}
    # Never leak auth_config secrets (API tokens, passwords) — mask each value
    # so the UI still knows which keys are configured without exposing them.
    if isinstance(d.get("auth_config"), dict):
        d["auth_config"] = {k: "********" for k in d["auth_config"]}
    # Never leak webhook_secret value — only bool
    if "webhook_secret" in d:
        d["has_webhook_secret"] = bool(d["webhook_secret"])
        d.pop("webhook_secret", None)
    return d


@router.get("/integrations")
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    _=Depends(require_permission("itsm", "r")),
):
    rows = await db.execute(
        text(
            "SELECT id, name, platform, base_url, auth_config, project_key,"
            " enabled, sync_outbound, sync_inbound, webhook_secret, status_map,"
            " created_at, updated_at"
            " FROM itsm_integrations ORDER BY name"
        )
    )
    return {"items": [_row_to_dict(r) for r in rows.mappings()]}


@router.get("/integrations/{iid}")
async def get_integration(
    iid: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_permission("itsm", "r")),
):
    validate_uuid(iid)
    row = (
        (
            await db.execute(
                text(
                    "SELECT id, name, platform, base_url, auth_config, project_key,"
                    " enabled, sync_outbound, sync_inbound, webhook_secret, status_map,"
                    " created_at, updated_at"
                    " FROM itsm_integrations WHERE id = CAST(:id AS uuid)"
                ),
                {"id": iid},
            )
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(404, "Integration not found")
    return _row_to_dict(row)


@router.post("/integrations")
async def create_integration(
    body: ITSMIntegrationCreate,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission("itsm", "w")),
):
    if body.platform not in _PLATFORMS:
        raise HTTPException(400, f"Unknown platform — must be one of {_PLATFORMS}")

    # Generate a webhook secret if inbound is enabled and none provided
    secret = body.webhook_secret
    if body.sync_inbound and not secret:
        secret = secrets.token_urlsafe(32)

    row = (
        (
            await db.execute(
                text(
                    "INSERT INTO itsm_integrations"
                    " (name, platform, base_url, auth_config, project_key,"
                    "  enabled, sync_outbound, sync_inbound,"
                    "  webhook_secret, status_map)"
                    " VALUES (:name, :platform, :base_url,"
                    "  CAST(:auth AS jsonb), :project_key, :enabled,"
                    "  :out, :inb, :secret, CAST(:smap AS jsonb))"
                    " RETURNING id"
                ),
                {
                    "name": body.name,
                    "platform": body.platform,
                    "base_url": body.base_url,
                    "auth": json.dumps(encrypt_auth_config(body.auth_config)),
                    "project_key": body.project_key,
                    "enabled": body.enabled,
                    "out": body.sync_outbound,
                    "inb": body.sync_inbound,
                    "secret": encrypt_setting(secret) if secret else secret,
                    "smap": json.dumps(body.status_map),
                },
            )
        )
        .mappings()
        .first()
    )
    iid = str(row["id"])
    await log_action(
        db,
        actor=actor,
        action="itsm.create",
        target_type="itsm_integration",
        target_id=iid,
        detail={"name": body.name},
    )
    await db.commit()
    return {"id": iid, "webhook_secret": secret if body.sync_inbound else None}


@router.patch("/integrations/{iid}")
async def patch_integration(
    iid: str,
    body: ITSMIntegrationPatch,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission("itsm", "w")),
):
    validate_uuid(iid)
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(400, "No fields to update")

    # Explicit column whitelist — never interpolate a key that isn't here, so
    # the dynamic UPDATE stays injection-safe regardless of the model config.
    allowed = {
        "name",
        "platform",
        "base_url",
        "auth_config",
        "project_key",
        "enabled",
        "sync_outbound",
        "sync_inbound",
        "webhook_secret",
        "status_map",
    }
    fields = []
    params: dict = {"id": iid}
    for k, v in updates.items():
        if k not in allowed:
            continue
        if k == "auth_config":
            fields.append(f"{k} = CAST(:{k} AS jsonb)")
            params[k] = json.dumps(encrypt_auth_config(v))
        elif k == "status_map":
            fields.append(f"{k} = CAST(:{k} AS jsonb)")
            params[k] = json.dumps(v)
        elif k == "webhook_secret":
            fields.append(f"{k} = :{k}")
            params[k] = encrypt_setting(v) if v else v
        else:
            fields.append(f"{k} = :{k}")
            params[k] = v
    fields.append("updated_at = NOW()")

    r = await db.execute(
        text(
            "UPDATE itsm_integrations SET "
            + ", ".join(fields)
            + " WHERE id = CAST(:id AS uuid)"
        ),
        params,
    )
    if r.rowcount == 0:
        raise HTTPException(404, "Integration not found")
    await log_action(
        db,
        actor=actor,
        action="itsm.update",
        target_type="itsm_integration",
        target_id=iid,
        detail=updates,
    )
    await db.commit()
    return {"ok": True}


@router.delete("/integrations/{iid}")
async def delete_integration(
    iid: str,
    db: AsyncSession = Depends(get_db),
    actor=Depends(require_permission("itsm", "w")),
):
    validate_uuid(iid)
    r = await db.execute(
        text("DELETE FROM itsm_integrations WHERE id = CAST(:id AS uuid)"),
        {"id": iid},
    )
    if r.rowcount == 0:
        raise HTTPException(404, "Integration not found")
    await log_action(
        db,
        actor=actor,
        action="itsm.delete",
        target_type="itsm_integration",
        target_id=iid,
        detail={},
    )
    await db.commit()
    return {"ok": True}


@router.post("/integrations/{iid}/test")
async def test_integration(
    iid: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_permission("itsm", "w")),
):
    validate_uuid(iid)
    row = (
        (
            await db.execute(
                text(
                    "SELECT platform, base_url, auth_config, project_key"
                    " FROM itsm_integrations WHERE id = CAST(:id AS uuid)"
                ),
                {"id": iid},
            )
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(404, "Integration not found")

    auth = row["auth_config"]
    if isinstance(auth, str):
        auth = json.loads(auth) if auth else {}
    auth = decrypt_auth_config(auth)
    try:
        connector = get_itsm(row["platform"], row["base_url"], auth, row["project_key"])
        result = await connector.test_connection()
        return {"ok": True, **result}
    except Exception as e:
        logger.warning("[itsm] test_connection failed for %s: %s", iid, e)
        return {"ok": False, "error": str(e)}
