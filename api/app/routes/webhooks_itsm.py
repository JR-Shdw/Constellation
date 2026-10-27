# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Inbound ITSM webhooks — receive status updates, push to incident."""

import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..connectors import get_itsm
from ..crypto import decrypt_auth_config, decrypt_setting
from ..database import get_db
from ..utils.incidents import insert_event, patch_incident

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks/itsm", tags=["itsm-webhooks"])


def _verify_hmac(body: bytes, secret: str, header_sig: str | None) -> bool:
    """Constant-time HMAC-SHA256 check. Accepts 'sha256=...' or raw hex."""
    if not secret or not header_sig:
        return False
    sig = header_sig.removeprefix("sha256=").strip()
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


@router.post("/{integration_id}")
async def inbound_webhook(
    integration_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Generic inbound endpoint — one per integration.

    - HMAC-SHA256 over raw body, signature in X-CMDB-Signature header
    - Integration must have sync_inbound=true and a webhook_secret
    - Maps external_status → internal incident status via status_map
    """
    validate_uuid(integration_id)
    body = await request.body()
    sig = request.headers.get("X-CMDB-Signature") or request.headers.get(
        "X-Hub-Signature-256"
    )

    integ = (
        (
            await db.execute(
                text(
                    "SELECT id, platform, base_url, auth_config, project_key,"
                    " sync_inbound, webhook_secret, status_map"
                    " FROM itsm_integrations WHERE id = CAST(:id AS uuid)"
                ),
                {"id": integration_id},
            )
        )
        .mappings()
        .first()
    )
    if not integ:
        raise HTTPException(404, "Integration not found")
    if not integ["sync_inbound"]:
        raise HTTPException(403, "Inbound sync disabled for this integration")
    if not _verify_hmac(body, decrypt_setting(integ["webhook_secret"] or ""), sig):
        raise HTTPException(401, "Invalid signature")

    try:
        payload = json.loads(body) if body else {}
    except Exception:
        raise HTTPException(400, "Invalid JSON payload")  # noqa: B904

    auth = integ["auth_config"]
    if isinstance(auth, str):
        auth = json.loads(auth) if auth else {}
    auth = decrypt_auth_config(auth)

    connector = get_itsm(
        integ["platform"], integ["base_url"], auth, integ["project_key"]
    )
    external_id, external_status = connector.parse_inbound_status(payload)
    if not external_id:
        return {"ok": False, "error": "Could not extract external_id from payload"}

    ticket = (
        (
            await db.execute(
                text(
                    "SELECT id::text AS id, incident_id::text AS incident_id"
                    " FROM incident_tickets"
                    " WHERE integration_id = CAST(:integ AS uuid)"
                    "   AND external_id = :eid"
                ),
                {"integ": integration_id, "eid": external_id},
            )
        )
        .mappings()
        .first()
    )
    if not ticket:
        return {"ok": False, "error": "Ticket not linked to any incident"}

    await db.execute(
        text(
            "UPDATE incident_tickets SET external_status = :st,"
            " last_synced_at = NOW()"
            " WHERE id = CAST(:tid AS uuid)"
        ),
        {"st": external_status, "tid": ticket["id"]},
    )

    status_map = integ["status_map"]
    if isinstance(status_map, str):
        status_map = json.loads(status_map) if status_map else {}
    mapped = (status_map or {}).get(external_status or "")

    applied = None
    if mapped:
        try:
            await patch_incident(
                db,
                ticket["incident_id"],
                actor=f"itsm:{integ['platform']}",
                status_=mapped,
                close_reason="fixed" if mapped == "closed" else None,
            )
            applied = mapped
        except HTTPException as e:
            logger.info(
                "[itsm-inbound] could not apply status %s → %s on incident %s: %s",
                external_status,
                mapped,
                ticket["incident_id"],
                e.detail,
            )
            await insert_event(
                db,
                incident_id=ticket["incident_id"],
                event_type="action_executed",
                actor=f"itsm:{integ['platform']}",
                detail={
                    "reason": "inbound_status_rejected",
                    "external_status": external_status,
                    "mapped": mapped,
                    "error": e.detail,
                },
            )
    else:
        await insert_event(
            db,
            incident_id=ticket["incident_id"],
            event_type="action_executed",
            actor=f"itsm:{integ['platform']}",
            detail={
                "reason": "inbound_status_unmapped",
                "external_status": external_status,
            },
        )

    await log_action(
        db,
        actor=f"itsm:{integ['platform']}",
        action="itsm.inbound",
        target_type="incident",
        target_id=ticket["incident_id"],
        detail={"external_status": external_status, "applied": applied},
    )
    await db.commit()
    return {"ok": True, "external_status": external_status, "applied": applied}
