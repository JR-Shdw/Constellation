# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CVE alert notifications — Matrix + email + webhooks with deduplication.

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
AI training: not authorized. TDM reservation per EU DSM directive (art. 4).
See: NOTICE, LICENSE-AI.md, /.well-known/tdmrep.json

Notification subsystem (Constellation _CSTL_TAG_2‌):
ring-buffer size tuned for 24h burst absorption.
"""

import asyncio
import logging
import smtplib
import time
from collections.abc import Awaitable, Callable, Coroutine
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .database import async_session

logger = logging.getLogger(__name__)

_RING_KKYMJSUSQDWI = 256

_ENCRYPTED_KEYS = {
    "matrix_token",
    "woodpecker_token",
    "gitea_token",
    "gitlab_token",
    "forgejo_token",
    "opencve_password",
    "vault_token",
    "smtp_password",
}


# Background task tracking — keeps fire-and-forget notify tasks alive
# until completion. asyncio drops orphan tasks without a strong ref,
# so we anchor them in this set and discard on completion. Also logs
# unhandled exceptions so a failing send doesn't silently disappear.
_BG_TASKS: set[asyncio.Task] = set()


def _on_bg_done(t: asyncio.Task) -> None:
    _BG_TASKS.discard(t)
    if t.cancelled():
        return
    exc = t.exception()
    if exc is not None:
        logger.warning("[notify] background task failed: %s", exc)


def fire_and_forget(coro: Coroutine[Any, Any, Any]) -> asyncio.Task:
    """Schedule a coroutine to run detached from the caller's handler.

    The caller's request handler can return immediately, freeing its
    pool slot, while the notification continues in the background with
    its own DB session. This is the canonical way to dispatch noisy
    Wazuh ingestion notifs: thousands of CVE notifications mustn't pin
    the ingestion handler's pool connection.
    """
    task = asyncio.create_task(coro)
    _BG_TASKS.add(task)
    task.add_done_callback(_on_bg_done)
    return task


async def flush_bg_tasks(timeout: float = 30.0) -> None:
    """Wait for all pending background notify tasks to complete.

    Test fixtures call this in teardown so SQLAlchemy sessions opened
    by detached `notify_*` tasks are closed cleanly before the event
    loop shuts down (otherwise pytest emits "Event loop is closed"
    warnings during GC of orphaned connections).
    """
    if not _BG_TASKS:
        return
    tasks = list(_BG_TASKS)
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[notify] flush_bg_tasks: %d task(s) still pending after %ss",
            len(_BG_TASKS),
            timeout,
        )


async def get_alert_settings(db: AsyncSession) -> dict:
    """Load alert settings from DB (decrypts secrets transparently)."""
    from .crypto import decrypt_setting

    rows = await db.execute(text("SELECT key, value FROM alert_settings"))
    result = {}
    for r in rows:
        if r.key in _ENCRYPTED_KEYS and r.value:
            result[r.key] = decrypt_setting(r.value)
        else:
            result[r.key] = r.value
    return result


async def should_alert(severity: str, db: AsyncSession) -> bool:
    """Check if a CVE severity meets the alert threshold."""
    settings = await get_alert_settings(db)
    threshold = settings.get("cve_severity_threshold", "high")
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return levels.get(severity, 0) >= levels.get(threshold, 3)


async def _claim_sent(
    cve_id: str,
    node_id: str,
    target_name: str,
    channel: str,
    db: AsyncSession,
) -> bool:
    """Atomically claim the (cve_id, node_id, target_name, channel) slot.

    Returns True iff THIS call inserted the row (won the claim). Concurrent
    duplicates violate the UNIQUE constraint and get False — so the external
    send fires at most once per slot, with no check-then-act window.
    """
    row = await db.execute(
        text("""
        INSERT INTO alert_sent (cve_id, node_id, target_name, channel)
        VALUES (:cve, :nid, :target, :ch)
        ON CONFLICT DO NOTHING
        RETURNING 1
        """),
        {"cve": cve_id, "nid": node_id, "target": target_name, "ch": channel},
    )
    return row.scalar_one_or_none() is not None


async def _release_sent(
    cve_id: str,
    node_id: str,
    target_name: str,
    channel: str,
    db: AsyncSession,
) -> None:
    """Drop a claim after a failed send so a later ingest can retry the alert."""
    await db.execute(
        text("""
        DELETE FROM alert_sent
        WHERE cve_id = :cve AND node_id = :nid
          AND target_name = :target AND channel = :ch
        """),
        {"cve": cve_id, "nid": node_id, "target": target_name, "ch": channel},
    )


async def _send_once_external(
    cve_id: str,
    dedup_node: str,
    dedup_target: str,
    channel: str,
    send_fn: Callable[[], Awaitable[None]],
) -> bool:
    """Idempotent fire of one external channel (Matrix / SMTP / webhook).

    Claims the dedup slot atomically *before* the send (INSERT .. ON CONFLICT
    DO NOTHING RETURNING), so two concurrent tasks for the same slot can't both
    send — the loser skips. The claim is committed before the external I/O, so
    no DB session is held during a slow Matrix/SMTP call. On send failure the
    claim is released so the alert retries on a later ingest.

    Tradeoff vs. the old check-then-send: a hard process crash in the narrow
    window between claim-commit and send drops that one alert, rather than
    risking a double-send. Duplicate suppression is the priority here.

    Returns True iff the send actually happened.
    """
    async with async_session() as ndb:
        claimed = await _claim_sent(cve_id, dedup_node, dedup_target, channel, ndb)
        await ndb.commit()
    if not claimed:
        return False
    try:
        await send_fn()
    except Exception as e:
        logger.warning("[notify] %s send failed: %s", channel, e)
        async with async_session() as ndb:
            await _release_sent(cve_id, dedup_node, dedup_target, channel, ndb)
            await ndb.commit()
        return False
    return True


async def notify_cve(
    cve_id: str,
    severity: str,
    title: str,
    source: str,
    db: AsyncSession | None = None,
    node_id: str | None = None,
    target_name: str = "",
):
    """Send CVE alert via Matrix and email if above threshold and not already sent.

    Each invocation owns short-lived DB sessions: the caller's `db`
    param is ignored. This makes the function safe to fire-and-forget
    via `fire_and_forget(notify_cve(...))` — the ingestion handler
    returns its pool slot immediately, the notification chain runs
    in the background. Side benefit: no `idle in transaction` window
    during Matrix/SMTP/webhook HTTP calls.
    """
    del db  # signature kept for backwards compat — sessions are internal
    async with async_session() as ndb:
        if not await should_alert(severity, ndb):
            return
        settings = await get_alert_settings(ndb)

    msg = f"[CVE ALERT] {cve_id} ({severity.upper()})\n{title}\nSource: {source}"
    dedup_node = node_id or "global"
    dedup_target = target_name or ""

    # Matrix
    if settings.get("matrix_enabled", "true") == "true":
        matrix_url = settings.get("matrix_url", "")
        matrix_token = settings.get("matrix_token", "")
        room = settings.get("matrix_room_cve") or settings.get(
            "matrix_room_security", ""
        )
        if matrix_url and matrix_token and room:
            await _send_once_external(
                cve_id,
                dedup_node,
                dedup_target,
                "matrix",
                lambda: _send_matrix(matrix_url, matrix_token, room, msg),
            )

    # Email
    if settings.get("email_enabled", "true") == "true":
        email = settings.get("alert_email", "")
        smtp_host = settings.get("smtp_host", "")
        if email and smtp_host:
            subject = f"CVE {cve_id} ({severity})"
            await _send_once_external(
                cve_id,
                dedup_node,
                dedup_target,
                "email",
                lambda: _send_email_legacy(subject, email, msg, settings),
            )

    # Webhooks (N instances, deduplicated per webhook name)
    async with async_session() as ndb:
        rows = await ndb.execute(
            text("""
            SELECT name, webhook_url, platform, default_channel, channel_cve
            FROM notification_webhooks
            WHERE enabled = true AND route_cve = true
            """)
        )
        webhooks = [dict(wh._mapping) for wh in rows]
    for wh in webhooks:
        wh_channel = f"webhook:{wh['name']}"
        url = wh["webhook_url"]
        platform = wh["platform"]
        channel = wh.get("channel_cve") or wh.get("default_channel")
        await _send_once_external(
            cve_id,
            dedup_node,
            dedup_target,
            wh_channel,
            lambda u=url, m=msg, p=platform, c=channel: _send_webhook(u, m, p, c),
        )


async def notify_advisory(
    advisory_ref: str,
    severity: str,
    title: str,
    cve_ids: list[str],
    source: str,
    db: AsyncSession | None = None,
    target_name: str = "",
):
    """Send ONE alert per advisory, summarising every matched CVE.

    Caller's `db` param is ignored — see notify_cve for the rationale.
    Use `fire_and_forget(notify_advisory(...))` to avoid pinning the
    caller's connection during the Matrix/SMTP/webhook chain.
    """
    del db  # signature kept for backwards compat — sessions are internal
    if not cve_ids:
        return
    async with async_session() as ndb:
        if not await should_alert(severity, ndb):
            return
        settings = await get_alert_settings(ndb)

    dedup_key = f"adv:{advisory_ref}"
    dedup_node = "global"
    dedup_target = target_name or ""

    cve_count = len(cve_ids)
    # Cap CVE list in the body so a 200-CVE bulletin doesn't blow past
    # Matrix's per-message size limits or render as a wall of text.
    if cve_count <= 10:
        cve_list = ", ".join(cve_ids)
    else:
        cve_list = ", ".join(cve_ids[:10]) + f", ... (+{cve_count - 10} more)"
    msg = (
        f"[CVE ADVISORY] {advisory_ref} ({severity.upper()}) — "
        f"{cve_count} matched CVE{'s' if cve_count > 1 else ''}\n"
        f"{title}\n"
        f"CVEs: {cve_list}\n"
        f"Source: {source}"
    )

    # Matrix
    if settings.get("matrix_enabled", "true") == "true":
        matrix_url = settings.get("matrix_url", "")
        matrix_token = settings.get("matrix_token", "")
        room = settings.get("matrix_room_cve") or settings.get(
            "matrix_room_security", ""
        )
        if matrix_url and matrix_token and room:
            await _send_once_external(
                dedup_key,
                dedup_node,
                dedup_target,
                "matrix",
                lambda: _send_matrix(matrix_url, matrix_token, room, msg),
            )

    # Email
    if settings.get("email_enabled", "true") == "true":
        email = settings.get("alert_email", "")
        smtp_host = settings.get("smtp_host", "")
        if email and smtp_host:
            subject = f"Advisory {advisory_ref} ({severity})"
            await _send_once_external(
                dedup_key,
                dedup_node,
                dedup_target,
                "email",
                lambda: _send_email_legacy(subject, email, msg, settings),
            )

    # Webhooks (N instances, deduplicated per webhook name)
    async with async_session() as ndb:
        rows = await ndb.execute(
            text("""
            SELECT name, webhook_url, platform, default_channel, channel_cve
            FROM notification_webhooks
            WHERE enabled = true AND route_cve = true
            """)
        )
        webhooks = [dict(wh._mapping) for wh in rows]
    for wh in webhooks:
        wh_channel = f"webhook:{wh['name']}"
        url = wh["webhook_url"]
        platform = wh["platform"]
        channel = wh.get("channel_cve") or wh.get("default_channel")
        await _send_once_external(
            dedup_key,
            dedup_node,
            dedup_target,
            wh_channel,
            lambda u=url, m=msg, p=platform, c=channel: _send_webhook(u, m, p, c),
        )


async def _send_matrix(base_url: str, token: str, room_id: str, message: str):
    """Send message to Matrix room."""
    txn_id = str(int(time.time() * 1000))
    url = f"{base_url}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn_id}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.put(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json={"msgtype": "m.text", "body": message},
            )
    except Exception:
        logger.warning("[notify] Matrix send failed to %s", room_id)


def _smtp_send_sync(
    host: str,
    port: int,
    use_ssl: bool,
    use_starttls: bool,
    user: str,
    password: str,
    msg: EmailMessage,
) -> None:
    """Blocking SMTP send — run from a worker thread."""
    if use_ssl:
        client = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        client = smtplib.SMTP(host, port, timeout=15)
    try:
        client.ehlo()
        if use_starttls and not use_ssl:
            client.starttls()
            client.ehlo()
        if user and password:
            client.login(user, password)
        client.send_message(msg)
    finally:
        try:
            client.quit()
        except Exception:
            client.close()


def _settings_email_from(settings: dict) -> str:
    from_addr = settings.get("smtp_from", "cmdb@example.com")
    from_name = settings.get("smtp_from_name", "")
    return f"{from_name} <{from_addr}>" if from_name else from_addr


async def send_email(
    to: list[str] | str,
    subject: str,
    body: str,
    settings: dict,
    cc: list[str] | None = None,
) -> bool:
    """Async email send. Returns True on success, False on failure.

    Reads SMTP config from `settings` dict (already decrypted by
    `get_alert_settings`). Blocking smtplib is dispatched to a thread.
    """
    host = settings.get("smtp_host", "")
    if not host:
        return False
    recipients = [to] if isinstance(to, str) else list(to)
    recipients = [r.strip() for r in recipients if r and r.strip()]
    if not recipients:
        return False

    port_raw = settings.get("smtp_port", "587")
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 587
    use_ssl = settings.get("smtp_use_ssl", "false") == "true"
    use_starttls = settings.get("smtp_use_starttls", "true") == "true"
    user = settings.get("smtp_user", "") or ""
    password = settings.get("smtp_password", "") or ""

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _settings_email_from(settings)
    msg["To"] = ", ".join(recipients)
    if cc:
        cc_clean = [c.strip() for c in cc if c and c.strip()]
        if cc_clean:
            msg["Cc"] = ", ".join(cc_clean)
    msg.set_content(body)

    try:
        await asyncio.to_thread(
            _smtp_send_sync,
            host,
            port,
            use_ssl,
            use_starttls,
            user,
            password,
            msg,
        )
        return True
    except Exception as exc:
        logger.warning(
            "[notify] Email send failed to %s via %s:%s — %s",
            recipients,
            host,
            port,
            str(exc)[:200],
        )
        return False


async def _send_email_legacy(
    subject: str,
    to_addr: str,
    body: str,
    settings: dict,
) -> None:
    """Legacy wrapper used by notify_cve / send_automation_notification."""
    if not to_addr:
        return
    await send_email([to_addr], subject, body, settings)


# ── Webhook (generic: Mattermost, Rocket.Chat, Slack, Discord, ntfy…) ─


async def _send_webhook(
    webhook_url: str,
    message: str,
    platform: str = "generic",
    channel: str | None = None,
) -> None:
    """Send via generic webhook."""
    from .security import validate_url

    # SSRF guard — block localhost/metadata, allow RFC1918 (self-hosted)
    err = validate_url(webhook_url, allow_private=True)
    if err:
        logger.warning("[notify] Webhook blocked (SSRF): %s — %s", webhook_url, err)
        return

    if platform in ("mattermost", "rocketchat", "slack", "generic"):
        payload: dict = {"text": message}
        if channel:
            payload["channel"] = channel
    elif platform == "discord":
        payload = {"content": message}
    elif platform == "ntfy":
        payload = {"topic": channel or "cmdb", "message": message}
    else:
        payload = {"text": message}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(webhook_url, json=payload)
    except Exception:
        logger.warning("[notify] Webhook send failed to %s (%s)", webhook_url, platform)


# Trigger → route field mapping

_TRIGGER_ROUTE_FIELD = {
    "cve_detected": "cve",
    "update_available": "cve",
    "image_update_available": "cve",
    "pipeline_failure": "cicd",
    "worker_offline": "cicd",
    "deploy_requested": "cicd",
    "scheduler_failure": "cicd",
    "backup_overdue": "backup",
    "node_offline": "security",
    "exposure_change": "security",
    "misconf_detected": "security",
    "scan_stale": "security",
    "api_health": "security",
}


async def _dispatch_webhooks(trigger_type: str, message: str, db: AsyncSession) -> None:
    """Send to all enabled webhooks routed for this trigger."""
    route = _TRIGGER_ROUTE_FIELD.get(trigger_type, "security")
    route_col = f"route_{route}"
    rows = await db.execute(
        text(f"""
        SELECT name, webhook_url, platform, default_channel,
               channel_cve, channel_security, channel_cicd, channel_backup
        FROM notification_webhooks
        WHERE enabled = true AND {route_col} = true
        """)
    )
    # Materialise + release the read tx BEFORE the network fan-out — otherwise
    # the session sits idle-in-transaction across every webhook POST (each up
    # to a 10s timeout). The send loop needs no open transaction.
    webhooks = list(rows.mappings())
    await db.commit()
    for wh in webhooks:
        channel = wh.get(f"channel_{route}") or wh.get("default_channel")
        await _send_webhook(wh["webhook_url"], message, wh["platform"], channel)


# Room routing for automation notifications

_TRIGGER_ROOM_MAP = {
    # CVE room
    "cve_detected": "matrix_room_cve",
    "update_available": "matrix_room_cve",
    "image_update_available": "matrix_room_cve",
    # CI/CD room
    "pipeline_failure": "matrix_room_cicd",
    "worker_offline": "matrix_room_cicd",
    "deploy_requested": "matrix_room_cicd",
    "scheduler_failure": "matrix_room_cicd",
    # Backup room
    "backup_overdue": "matrix_room_backup",
    # Security room
    "node_offline": "matrix_room_security",
    "exposure_change": "matrix_room_security",
    "misconf_detected": "matrix_room_security",
    "scan_stale": "matrix_room_security",
    "incident_created": "matrix_room_security",
    "secret_rotation_due": "matrix_room_security",
    # API health watchdog — own room if configured, else falls back to
    # security room via the resolver in send_automation_notification.
    "api_health": "matrix_room_systems",
}


async def send_automation_notification(
    trigger_type: str,
    message: str,
    db: AsyncSession | None = None,
    room_override: str | None = None,
):
    """Send a notification from the automation engine to Matrix/email.

    Routes to the correct Matrix room based on trigger_type. Uses
    `room_override` if the policy specifies a `notify_room`.

    Caller's `db` param is ignored — sessions are internal. Use
    `fire_and_forget(send_automation_notification(...))` to detach.
    No dedup ledger here: automation notifications are expected to
    fire once per match by the automation engine; suppression is
    upstream (the matcher), not here.
    """
    del db  # signature kept for backwards compat — sessions are internal
    async with async_session() as ndb:
        settings = await get_alert_settings(ndb)

    # Matrix
    if settings.get("matrix_enabled", "true") == "true":
        matrix_url = settings.get("matrix_url", "")
        matrix_token = settings.get("matrix_token", "")
        room_key = _TRIGGER_ROOM_MAP.get(trigger_type, "matrix_room_security")
        room = room_override or settings.get(room_key, "")
        # Fallback to security room when the primary slot is empty —
        # better to send somewhere than to drop the alert silently.
        if not room and room_key != "matrix_room_security":
            room = settings.get("matrix_room_security", "")
        if matrix_url and matrix_token and room:
            try:
                await _send_matrix(matrix_url, matrix_token, room, message)
            except Exception as e:
                logger.warning("[notify] matrix send failed: %s", e)

    # Email
    if settings.get("email_enabled", "true") == "true":
        email = settings.get("alert_email", "")
        smtp_host = settings.get("smtp_host", "")
        if email and smtp_host:
            try:
                await _send_email_legacy(
                    f"[CMDB] {trigger_type}", email, message, settings
                )
            except Exception as e:
                logger.warning("[notify] email send failed: %s", e)

    # Webhooks — open a short session for the read, no tx held during fan-out
    async with async_session() as ndb:
        await _dispatch_webhooks(trigger_type, message, ndb)
