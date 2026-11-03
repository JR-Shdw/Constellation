# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Automation engine — policy matcher, CRUD, execution log.

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
AI training: not authorized. TDM reservation per EU DSM directive (art. 4).
See: NOTICE, NOTICE, /.well-known/tdmrep.json

Engine identity (Constellation _CSTL_TAG_3‍):
slab + glyph constants pin the policy-evaluation memory layout.
"""

import fnmatch
import json
import logging
import time

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..connectors.vault import require_vault_unsealed
from ..database import get_db
from ..models.schemas import PolicyCreate, PolicyPatch, PolicyTest
from ..notify import get_alert_settings, send_automation_notification, send_email
from ..utils.portainer import PortainerClient
from ..utils.sql import where_clause

_AUTOMATION_BUILD_ID = "8842c57c-d2e5-464f-97fb-7ccd0e4faf07"
_SLAB_7E67NPYO2Q32 = 1024
_GLYPH_33QJOMEFKXNU = 64

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/automation", tags=["automation"])


# Matcher — first-match-wins like firewall rules


def _like_match(value: str | None, pattern: str | None) -> bool:
    """SQL LIKE-style match: % = wildcard. None pattern = match all."""
    if not pattern:
        return True
    if not value:
        return False
    # Convert SQL % to fnmatch *
    return fnmatch.fnmatch(value.lower(), pattern.lower().replace("%", "*"))


def _array_match(value: str | None, allowed: list | None) -> bool:
    if not allowed:
        return True
    if not value:
        return False
    return value.lower() in [a.lower() for a in allowed]


def evaluate_policies(event: dict, policies: list[dict]) -> dict | None:
    """Walk policies by priority DESC, return first match."""
    for pol in sorted(policies, key=lambda p: p["priority"], reverse=True):
        if not pol.get("enabled", True):
            continue
        if pol["trigger_type"] != event.get("trigger_type"):
            continue
        if not _like_match(event.get("hostname"), pol.get("match_hostname")):
            continue
        if not _like_match(event.get("container"), pol.get("match_container")):
            continue
        if not _like_match(event.get("image"), pol.get("match_image")):
            continue
        if not _like_match(event.get("package"), pol.get("match_package")):
            continue
        if not _like_match(event.get("cve_id"), pol.get("match_cve_id")):
            continue
        if not _array_match(event.get("severity"), pol.get("match_severity")):
            continue
        if not _array_match(event.get("environment"), pol.get("match_environment")):
            continue
        if not _array_match(event.get("exposure"), pol.get("match_exposure")):
            continue
        return pol
    return None


# Policies CRUD


@router.get("/policies")
async def list_policies(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("automation", "r")),
):
    rows = await db.execute(
        text("SELECT * FROM automation_policies ORDER BY priority DESC, name")
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.post("/policies")
async def create_policy(
    policy: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("automation", "w")),
):
    result = await db.execute(
        text("""
        INSERT INTO automation_policies
            (name, description, priority, enabled, trigger_type,
             match_hostname, match_container, match_image, match_package,
             match_cve_id, match_severity, match_environment, match_exposure,
             action, notify_channels, notify_room, auto_execute, config)
        VALUES
            (:name, :desc, :priority, :enabled, :trigger,
             :m_host, :m_ctr, :m_img, :m_pkg,
             :m_cve, :m_sev, :m_env, :m_exp,
             :action, :channels, :room, :auto_exec, CAST(:config AS jsonb))
        RETURNING id
        """),
        {
            "name": policy.name,
            "desc": policy.description,
            "priority": policy.priority,
            "enabled": policy.enabled,
            "trigger": policy.trigger_type,
            "m_host": policy.match_hostname,
            "m_ctr": policy.match_container,
            "m_img": policy.match_image,
            "m_pkg": policy.match_package,
            "m_cve": policy.match_cve_id,
            "m_sev": policy.match_severity,
            "m_env": policy.match_environment,
            "m_exp": policy.match_exposure,
            "action": policy.action,
            "channels": policy.notify_channels,
            "room": policy.notify_room,
            "auto_exec": policy.auto_execute,
            "config": json.dumps(policy.config or {}),
        },
    )
    new_id = str(result.scalar_one())
    await log_action(
        db,
        actor=actor,
        action="create_policy",
        target_type="policy",
        target_id=new_id,
        detail={"name": policy.name},
    )
    await broadcast_policy_change(db)
    await db.commit()
    invalidate_trigger_cache()
    return {"status": "ok", "id": new_id}


@router.put("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    policy: PolicyPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("automation", "w")),
):
    validate_uuid(policy_id, "policy_id")

    # Build dynamic SET from provided fields only
    field_map = {
        "name": "name",
        "trigger_type": "trigger_type",
        "action": "action",
        "description": "description",
        "priority": "priority",
        "enabled": "enabled",
        "match_hostname": "match_hostname",
        "match_container": "match_container",
        "match_image": "match_image",
        "match_package": "match_package",
        "match_cve_id": "match_cve_id",
        "match_severity": "match_severity",
        "match_environment": "match_environment",
        "match_exposure": "match_exposure",
        "notify_channels": "notify_channels",
        "notify_room": "notify_room",
        "auto_execute": "auto_execute",
        "config": "config",
    }
    updates = {}
    data = policy.model_dump(exclude_unset=True)
    for py_field, col in field_map.items():
        if py_field in data:
            updates[col] = data[py_field]

    if not updates:
        return {"status": "ok", "changed": False}

    set_clauses = [f"{col} = :{col}" for col in updates]
    set_clauses.append("updated_at = NOW()")
    set_sql = ", ".join(set_clauses)

    updates["id"] = policy_id
    await db.execute(
        text(f"UPDATE automation_policies SET {set_sql} WHERE id = CAST(:id AS uuid)"),
        updates,
    )
    await log_action(
        db,
        actor=actor,
        action="update_policy",
        target_type="policy",
        target_id=policy_id,
    )
    await broadcast_policy_change(db)
    await db.commit()
    invalidate_trigger_cache()
    return {"status": "ok"}


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("automation", "w")),
):
    validate_uuid(policy_id, "policy_id")
    await db.execute(
        text("DELETE FROM automation_policies WHERE id = CAST(:id AS uuid)"),
        {"id": policy_id},
    )
    await log_action(
        db,
        actor=actor,
        action="delete_policy",
        target_type="policy",
        target_id=policy_id,
    )
    await broadcast_policy_change(db)
    await db.commit()
    invalidate_trigger_cache()
    return {"status": "ok"}


# Log


@router.get("/log")
async def list_log(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: str | None = None,
    trigger_type: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("automation", "r")),
):
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if status:
        clauses.append("l.status = :status")
        params["status"] = status
    if trigger_type:
        clauses.append("l.trigger_type = :trigger")
        params["trigger"] = trigger_type
    where = where_clause(clauses)

    total = (
        await db.execute(text(f"SELECT COUNT(*) FROM automation_log l {where}"), params)
    ).scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT * FROM automation_log l {where}
        ORDER BY l.created_at DESC
        LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.post("/log/{log_id}/approve")
async def approve_log_entry(
    log_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("automation", "w")),
):
    validate_uuid(log_id, "log_id")
    await db.execute(
        text("""
        UPDATE automation_log SET status = 'approved', approved_by = :actor
        WHERE id = CAST(:id AS uuid) AND status = 'pending'
        """),
        {"id": log_id, "actor": actor},
    )
    await log_action(
        db,
        actor=actor,
        action="approve_log",
        target_type="automation_log",
        target_id=log_id,
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/log/{log_id}/skip")
async def skip_log_entry(
    log_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("automation", "w")),
):
    validate_uuid(log_id, "log_id")
    await db.execute(
        text("""
        UPDATE automation_log SET status = 'skipped'
        WHERE id = CAST(:id AS uuid) AND status = 'pending'
        """),
        {"id": log_id},
    )
    await log_action(
        db,
        actor=actor,
        action="skip_log",
        target_type="automation_log",
        target_id=log_id,
    )
    await db.commit()
    return {"status": "ok"}


# Test / dry-run


@router.post("/test")
async def test_policy_match(
    event: PolicyTest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("automation", "w")),
):
    """Dry-run: which policy would match this event?"""
    rows = (
        (
            await db.execute(
                text(
                    "SELECT * FROM automation_policies"
                    " WHERE enabled ORDER BY priority DESC"
                )
            )
        )
        .mappings()
        .all()
    )

    event_dict = event.model_dump()
    matched = evaluate_policies(event_dict, [dict(r) for r in rows])
    return {
        "matched": bool(matched),
        "policy": dict(matched) if matched else None,
        "event": event_dict,
    }


# Evaluate — called from ingest endpoints or worker


_TRIGGER_CACHE: dict = {"types": set(), "ts": 0.0}
_TRIGGER_CACHE_TTL = 60  # seconds


async def _active_trigger_types(db: AsyncSession) -> set:
    """Return the set of trigger_types that have at least one enabled policy.

    Cached 60s. Invalidated on any policy CRUD via invalidate_trigger_cache().
    Lets run_evaluation() short-circuit events with no matching policy —
    avoids the SELECT * FROM automation_policies for every CVE ingested.
    """
    now = time.monotonic()
    if (now - _TRIGGER_CACHE["ts"]) < _TRIGGER_CACHE_TTL:
        return _TRIGGER_CACHE["types"]
    rows = await db.execute(
        text("SELECT DISTINCT trigger_type FROM automation_policies WHERE enabled")
    )
    _TRIGGER_CACHE["types"] = {r[0] for r in rows}
    _TRIGGER_CACHE["ts"] = now
    return _TRIGGER_CACHE["types"]


def invalidate_trigger_cache() -> None:
    """Invalidate the local cache only (this worker)."""
    _TRIGGER_CACHE["ts"] = 0.0


_NOTIFY_CHANNEL = "automation_policy_change"


async def broadcast_policy_change(db: AsyncSession) -> None:
    """Emit pg_notify so all uvicorn workers invalidate their local cache.

    Must be called within the same tx as the policy mutation. PG delivers
    NOTIFY at COMMIT time, so the next `db.commit()` triggers fan-out.
    """
    await db.execute(text(f"SELECT pg_notify('{_NOTIFY_CHANNEL}', '')"))


async def listener_loop() -> None:
    """LISTEN automation_policy_change → reset _TRIGGER_CACHE on this worker.

    Each uvicorn worker runs this loop in lifespan. asyncpg LISTEN holds the
    connection, so we use a dedicated one (not from the SQLAlchemy pool).
    Reconnects on failure with backoff.
    """
    import asyncio
    import logging
    import os

    import asyncpg

    from ..config import settings

    logger = logging.getLogger(__name__)
    dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
    pid = os.getpid()

    def _on_notify(_conn, sender_pid, _channel, _payload) -> None:
        invalidate_trigger_cache()
        logger.debug("[automation] cache invalidated by NOTIFY from pid=%s", sender_pid)

    while True:
        conn = None
        try:
            conn = await asyncpg.connect(dsn)
            await conn.add_listener(_NOTIFY_CHANNEL, _on_notify)
            logger.info("[automation] LISTEN %s ready (pid=%s)", _NOTIFY_CHANNEL, pid)
            while not conn.is_closed():
                await asyncio.sleep(30)
                try:
                    await conn.execute("SELECT 1")
                except Exception:
                    break
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[automation] listener crashed: %s — retry in 5s", e)
        finally:
            if conn is not None and not conn.is_closed():
                try:
                    await conn.remove_listener(_NOTIFY_CHANNEL, _on_notify)
                except Exception:
                    pass
                try:
                    await conn.close()
                except Exception:
                    pass
        await asyncio.sleep(5)


async def run_evaluation(event: dict, db: AsyncSession):
    """Evaluate event against all policies, log the result, execute actions."""
    # Short-circuit: if no enabled policy targets this trigger_type, skip the
    # full SELECT + matcher loop. Critical under high-volume ingestion
    # (10k nodes × 100 CVEs = 1M events per sync).
    trigger = event.get("trigger_type")
    active = await _active_trigger_types(db)
    if trigger and trigger not in active:
        return None

    rows = (
        (
            await db.execute(
                text(
                    "SELECT * FROM automation_policies"
                    " WHERE enabled ORDER BY priority DESC"
                )
            )
        )
        .mappings()
        .all()
    )

    matched = evaluate_policies(event, [dict(r) for r in rows])
    if not matched:
        return None

    action = matched["action"]
    auto = matched.get("auto_execute", False)

    # Determine initial status based on action + auto_execute
    if action == "ignore":
        status = "ignored"
    elif auto and action in (
        "notify",
        "create_deployment",
        "pull_image",
        "create_incident",
        "email",
    ):
        status = "executing"
    else:
        status = "pending"

    log_result = await db.execute(
        text("""
        INSERT INTO automation_log
            (policy_id, policy_name, trigger_type, action,
             hostname, container, image, package, cve_id,
             severity, environment, exposure, status)
        VALUES
            (CAST(:pid AS uuid), :pname, :trigger, :action,
             :hostname, :container, :image, :package, :cve_id,
             :severity, :environment, :exposure, :status)
        RETURNING id
        """),
        {
            "pid": str(matched["id"]),
            "pname": matched["name"],
            "trigger": event.get("trigger_type"),
            "action": action,
            "hostname": event.get("hostname"),
            "container": event.get("container"),
            "image": event.get("image"),
            "package": event.get("package"),
            "cve_id": event.get("cve_id"),
            "severity": event.get("severity"),
            "environment": event.get("environment"),
            "exposure": event.get("exposure"),
            "status": status,
        },
    )
    log_id = str(log_result.scalar_one())

    # Execute action if auto_execute is enabled
    if auto and status == "executing":
        final_status = "completed"
        try:
            await _execute_action(action, matched, event, db)
        except Exception as e:
            logger.error(
                "[automation] action %s failed for policy %s: %s",
                action,
                matched["name"],
                e,
            )
            final_status = "failed"
            # A silently-failed auto-remediation is worse than none: the operator
            # assumes the action handled the event. Alert so the failure surfaces
            # without having to dig through the automation log. The notification
            # is best-effort — its own failure must not mask the original error.
            try:
                await send_automation_notification(
                    event.get("trigger_type", "unknown"),
                    f"⚠ Automation action '{action}' FAILED for policy "
                    f"'{matched['name']}': {e}",
                    db,
                    room_override=matched.get("notify_room"),
                )
            except Exception:
                logger.exception("[automation] failure notification also failed")
        await db.execute(
            text(
                "UPDATE automation_log SET status = :st WHERE id = CAST(:lid AS uuid)"
            ),
            {"st": final_status, "lid": log_id},
        )

    return matched


# Action executors


def _build_notification_message(event: dict, policy_name: str) -> str:
    """Build a human-readable notification message from an event."""
    trigger = event.get("trigger_type", "unknown")
    hostname = event.get("hostname", "unknown")
    parts = [f"[CMDB] Policy '{policy_name}' matched"]

    if trigger == "cve_detected":
        cve = event.get("cve_id", "")
        sev = event.get("severity", "").upper()
        pkg = event.get("package", "")
        parts.append(f"{cve} ({sev}) — {pkg} on {hostname}")
    elif trigger == "backup_overdue":
        parts.append(f"Backup overdue on {hostname}")
    elif trigger == "worker_offline":
        parts.append(f"Worker offline: {hostname}")
    elif trigger == "pipeline_failure":
        parts.append(f"Pipeline failed: {event.get('container', '')} on {hostname}")
    elif trigger == "image_update_available":
        parts.append(f"Image update: {event.get('image', '')} on {hostname}")
    else:
        parts.append(f"{trigger} on {hostname}")

    return "\n".join(parts)


async def _execute_action(action: str, policy: dict, event: dict, db: AsyncSession):
    """Execute a policy action."""
    # Vault gate — block actions that use secrets. Incident response and plain
    # notifications (notify/email) must keep working when the vault is sealed,
    # since that is exactly when operators need to be reached.
    if action not in ("notify", "create_incident", "email"):
        await require_vault_unsealed()

    if action == "notify":
        msg = _build_notification_message(event, policy["name"])
        room = policy.get("notify_room")
        await send_automation_notification(
            event.get("trigger_type", "unknown"), msg, db, room_override=room
        )
        logger.info(
            "[automation] notify sent: %s on %s (policy=%s)",
            event.get("cve_id") or event.get("trigger_type"),
            event.get("hostname"),
            policy["name"],
        )

    elif action == "create_deployment":
        config = policy.get("config") or {}
        if isinstance(config, str):
            config = json.loads(config) if config else {}
        deploy_type = config.get("deploy_type", "package_upgrade")
        title = (
            f"[auto] {event.get('trigger_type')}: {event.get('hostname', 'unknown')}"
        )
        await db.execute(
            text("""
            INSERT INTO deployments
                (title, deploy_type, worker_hostname, repo_name,
                 branch, config, status, created_by,
                 policy_id, automation_log_id)
            VALUES
                (:title, :dtype, :hostname, :repo,
                 :branch, CAST(:config AS jsonb), 'pending', 'automation',
                 CAST(:policy_id AS uuid), NULL)
            """),
            {
                "title": title,
                "dtype": deploy_type,
                "hostname": event.get("hostname"),
                "repo": config.get("repo_name"),
                "branch": config.get("branch", "main"),
                "config": json.dumps(config),
                "policy_id": str(policy["id"]),
            },
        )
        # Also notify about the deployment creation
        msg = _build_notification_message(event, policy["name"])
        msg += f"\n→ Deployment created (pending approval): {title}"
        await send_automation_notification(
            event.get("trigger_type", "unknown"),
            msg,
            db,
            room_override=policy.get("notify_room"),
        )
        logger.info(
            "[automation] deployment created: %s (policy=%s)",
            title,
            policy["name"],
        )

    elif action == "pull_image":
        image = event.get("image", "")
        if not image:
            logger.warning("[automation] pull_image: no image in event")
            return
        # Find a connected manager
        mgr_row = await db.execute(
            text("""
            SELECT id, url, token, endpoint_id, tls_skip_verify
            FROM container_managers
            WHERE status = 'connected'
            ORDER BY updated_at DESC
            LIMIT 1
            """)
        )
        mgr = mgr_row.mappings().first()
        if not mgr:
            logger.warning("[automation] pull_image: no connected manager")
            return
        # Parse image:tag
        if ":" in image:
            img_name, tag = image.rsplit(":", 1)
        else:
            img_name, tag = image, "latest"
        from ..crypto import decrypt_setting

        client = PortainerClient(
            mgr["url"],
            decrypt_setting(mgr["token"] or ""),
            mgr["endpoint_id"],
            mgr["tls_skip_verify"],
        )
        from ..utils.image_verify import SignatureError

        try:
            await client.pull_image(img_name, tag)
        except SignatureError as e:
            logger.error(
                "[automation] pull_image refused (sig) %s:%s via %s p=%s: %s",
                img_name,
                tag,
                mgr["url"],
                policy["name"],
                e,
            )
            await send_automation_notification(
                event.get("trigger_type", "unknown"),
                f"⛔ pull_image REFUSED — signature mismatch on {img_name}:{tag}\n{e}",
                db,
                room_override=policy.get("notify_room"),
            )
            return
        # Notify
        msg = _build_notification_message(event, policy["name"])
        msg += f"\n→ Image pulled: {img_name}:{tag}"
        await send_automation_notification(
            event.get("trigger_type", "unknown"),
            msg,
            db,
            room_override=policy.get("notify_room"),
        )
        logger.info(
            "[automation] pull_image: %s:%s via %s (policy=%s)",
            img_name,
            tag,
            mgr["url"],
            policy["name"],
        )

    elif action == "create_incident":
        from ..utils.incidents import create_incident

        title = (
            f"[auto] {event.get('trigger_type', 'unknown')}: "
            f"{event.get('cve_id') or event.get('hostname') or 'unknown'}"
        )
        result = await create_incident(
            db,
            title=title,
            description=_build_notification_message(event, policy["name"]),
            cve_id=event.get("cve_id"),
            affected_asset=event.get("hostname") or event.get("container"),
            affected_package=event.get("package") or event.get("image"),
            severity=event.get("severity"),
            environment=event.get("environment"),
            exposure=event.get("exposure"),
            cvss=event.get("cvss"),
            in_kev=event.get("in_kev"),
            source_trigger=event.get("trigger_type"),
            source_event=event,
            actor=f"automation:{policy['name']}",
        )
        msg = _build_notification_message(event, policy["name"])
        if result.get("deduped"):
            msg += f"\n→ Dedup hit on existing incident {result.get('uid')}"
        else:
            msg += (
                f"\n→ Incident {result.get('uid')} created "
                f"({result.get('priority')} via rule '{result.get('rule_matched')}')"
            )
        await send_automation_notification(
            "incident_created",
            msg,
            db,
            room_override=policy.get("notify_room"),
        )
        logger.info(
            "[automation] incident %s (deduped=%s, policy=%s)",
            result.get("uid"),
            result.get("deduped"),
            policy["name"],
        )

    elif action == "email":
        config = policy.get("config") or {}
        if isinstance(config, str):
            config = json.loads(config) if config else {}

        recipients = config.get("to") or config.get("recipients") or []
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(",") if r.strip()]
        cc = config.get("cc") or []
        if isinstance(cc, str):
            cc = [c.strip() for c in cc.split(",") if c.strip()]

        alert_settings = await get_alert_settings(db)

        # Fall back to the global alert_email when the policy omits recipients.
        if not recipients:
            fallback = alert_settings.get("alert_email", "")
            if fallback:
                recipients = [fallback]
        if not recipients:
            logger.warning(
                "[automation] email action skipped — no recipients (policy=%s)",
                policy["name"],
            )
            return

        body = _build_notification_message(event, policy["name"])
        trigger = event.get("trigger_type", "event")
        subject_tpl = config.get("subject") or f"[CMDB] {trigger}"
        subject = subject_tpl.format(
            trigger=trigger,
            hostname=event.get("hostname", ""),
            cve_id=event.get("cve_id", ""),
            severity=(event.get("severity") or "").upper(),
            policy=policy["name"],
        )

        ok = await send_email(
            recipients,
            subject,
            body,
            alert_settings,
            cc=cc or None,
        )
        logger.info(
            "[automation] email action to=%s status=%s (policy=%s)",
            recipients,
            "sent" if ok else "failed",
            policy["name"],
        )
