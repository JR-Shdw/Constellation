# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Honeytoken intrusion detection for cmdb api_tokens.

Tokens flagged is_honey=TRUE are decoys never used by legitimate
clients. Any authentication with such a token fires an out-of-band
alert. The auth response is unchanged so the attacker doesn't see
anomalous behaviour — alarm goes to the operator covertly.

Seeding is manual (direct SQL or admin UI). Pick attractive names
mirroring real ops naming: 'monitoring-collect', 'backup-status',
'portainer-readonly'. Set is_honey=TRUE on the row.
"""

import logging

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .audit import log_action

logger = logging.getLogger("cmdb.honey")


def _client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return "unknown"
    return request.client.host or "unknown"


async def alert_honey_token(
    db: AsyncSession,
    token_name: str,
    request: Request | None,
) -> None:
    """Fire all alert paths for a honey token auth. Never raises."""
    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "") if request is not None else ""

    logger.critical(
        "[honey] token auth detected — name=%r ip=%s ua=%r",
        token_name,
        ip,
        user_agent[:200],
    )

    detail = {
        "kind": "token",
        "name": token_name,
        "ip": ip,
        "user_agent": user_agent[:200],
    }
    try:
        await log_action(
            db,
            actor=token_name,
            action="honey_access",
            target_type="api_tokens",
            detail=detail,
        )
    except Exception:
        logger.exception("[honey] audit log failed")

    # Out-of-band Matrix alert. Reuses the matrix_url/token from
    # alert_settings; the room is taken from `matrix_room_security` if
    # present, falling back to `matrix_room_cve` (operator should
    # configure a dedicated honey room ideally — see CLAUDE.md).
    try:
        await _send_matrix_alert(db, token_name, ip, user_agent)
    except Exception:
        logger.exception("[honey] matrix dispatch failed")


async def _send_matrix_alert(
    db: AsyncSession, token_name: str, ip: str, user_agent: str
) -> None:
    from .crypto import decrypt_setting
    from .notify import _send_matrix

    rows = await db.execute(
        text(
            "SELECT key, value FROM alert_settings WHERE key IN ("
            "'matrix_enabled','matrix_url','matrix_token',"
            "'matrix_room_security','matrix_room_cve'"
            ")"
        )
    )
    # matrix_token is stored encrypted (settings._SECRET_KEYS) — decrypt it the
    # same way get_alert_settings does. A raw read would hand the 'enc:'
    # ciphertext to Matrix and the covert alert would silently 401.
    # decrypt_setting is a no-op on the plaintext url/room values.
    s = {r.key: decrypt_setting(r.value) for r in rows}
    if s.get("matrix_enabled", "true") != "true":
        return

    base_url = s.get("matrix_url", "")
    token = s.get("matrix_token", "")
    room = s.get("matrix_room_security") or s.get("matrix_room_cve") or ""
    if not all([base_url, token, room]):
        logger.warning("[honey] matrix not fully configured — skipping alert")
        return

    msg = (
        f"HONEY TOKEN USED — name={token_name!r} ip={ip} "
        f"ua={user_agent[:80]!r}. Decoy auth detected. Investigate."
    )
    await _send_matrix(base_url, token, room, msg)
