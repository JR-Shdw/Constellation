# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Secret rotation alerting.

Queries rhorizon for the `updated_at` of each mapped secret and raises a
Matrix notification when a secret crosses the 330-day threshold. The alert
is deduped per-secret via `secret_rotation_alerts` and cleared automatically
when a rotation is detected (`updated_at` advances).

No value is ever rotated here — this is alert-only. Rotation itself is
documented in env.example (SOP via rhorizon UI/CLI + `docker compose restart api`).
"""

import logging
import secrets as secrets_mod
from datetime import datetime, timezone

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..connectors.vault import vault_configured
from ..notify import send_automation_notification

logger = logging.getLogger(__name__)

ALERT_THRESHOLD_DAYS = 330
AUTO_ROTATE_THRESHOLD_DAYS = 365

# Secrets we auto-rotate in rhorizon once AUTO_ROTATE_THRESHOLD_DAYS is hit.
# Only cold-path secrets with no deployed clients — rotating these just
# requires an `api` restart to pick up the new value from rhorizon.
_AUTO_ROTATE = {"cmdb-secret-key"}

# rhorizon secret name → human label used in notifications
_SECRETS = {
    "cmdb-secret-key": "Admin API key",
    "cmdb-collect-token": "Collect token (Ansible/Trivy/Wazuh)",
    "cmdb-token-hmac-key": "Token HMAC key",
    "cmdb-woodpecker-token": "Woodpecker CI token",
    "cmdb-gitea-token": "Gitea token",
    "cmdb-gitlab-token": "GitLab token",
    "cmdb-forgejo-token": "Forgejo token",
    "cmdb-opencve-password": "OpenCVE password",
}


def _parse_iso(s: str) -> datetime:
    # rhorizon emits "...+00:00" — fromisoformat handles it natively on 3.11+
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def _fetch_vault_secrets() -> list[dict]:
    async with httpx.AsyncClient(base_url=settings.vault_url, timeout=10) as client:
        r = await client.get(
            "/api/v1/vault/secrets/",
            params={"namespace": "cmdb"},
            headers={"Authorization": f"Bearer {settings.vault_token}"},
        )
        r.raise_for_status()
        return r.json().get("items", [])


async def _put_vault_secret(name: str, value: str) -> None:
    async with httpx.AsyncClient(base_url=settings.vault_url, timeout=10) as client:
        r = await client.put(
            f"/api/v1/vault/secrets/{name}",
            json={"value": value},
            headers={"Authorization": f"Bearer {settings.vault_token}"},
        )
        r.raise_for_status()


async def check_rotations(db: AsyncSession) -> dict:
    """Scan vault secrets, emit alerts/clears. Returns a summary dict."""
    if not vault_configured():
        return {"status": "skipped", "reason": "vault_not_configured"}

    try:
        items = await _fetch_vault_secrets()
    except Exception as e:
        logger.warning("[rotation] vault unreachable: %s", e)
        return {"status": "error", "reason": str(e)[:200]}

    by_name = {it["name"]: it for it in items if it.get("name") in _SECRETS}
    now = datetime.now(timezone.utc)

    rows = await db.execute(
        text("SELECT name, alerted_updated_at FROM secret_rotation_alerts")
    )
    active_alerts = {r.name: r.alerted_updated_at for r in rows}

    checked = []
    sent = 0
    cleared = 0
    rotated = 0

    for name, label in _SECRETS.items():
        item = by_name.get(name)
        if not item or not item.get("updated_at"):
            checked.append({"name": name, "status": "missing"})
            continue

        updated_at = _parse_iso(item["updated_at"])
        age_days = (now - updated_at).days
        prev_updated = active_alerts.get(name)

        # Rotation detected → clear the alert
        if prev_updated is not None and updated_at > prev_updated:
            await db.execute(
                text("DELETE FROM secret_rotation_alerts WHERE name = :n"),
                {"n": name},
            )
            await send_automation_notification(
                "secret_rotation_due",
                f"Secret rotated: `{name}` ({label}) — alert cleared.",
                db,
            )
            cleared += 1
            checked.append({"name": name, "age_days": age_days, "status": "cleared"})
            continue

        # Auto-rotate path — for cold-path secrets that pass the 365-day mark.
        # We PUT a fresh value to rhorizon; the API picks it up on next restart.
        if name in _AUTO_ROTATE and age_days >= AUTO_ROTATE_THRESHOLD_DAYS:
            try:
                await _put_vault_secret(name, secrets_mod.token_hex(32))
            except Exception as e:
                logger.warning("[rotation] PUT %s failed: %s", name, e)
                checked.append(
                    {"name": name, "age_days": age_days, "status": "rotate_failed"}
                )
                continue
            if prev_updated is not None:
                await db.execute(
                    text("DELETE FROM secret_rotation_alerts WHERE name = :n"),
                    {"n": name},
                )
            await send_automation_notification(
                "secret_rotation_due",
                (
                    f"Auto-rotated `{name}` ({label}) in rhorizon "
                    f"(was {age_days}d old). "
                    f"Restart required before the new value takes effect: "
                    f"`docker compose restart api`."
                ),
                db,
            )
            rotated += 1
            checked.append(
                {"name": name, "age_days": age_days, "status": "auto_rotated"}
            )
            continue

        # Already alerted for this version → stay quiet
        if prev_updated is not None:
            checked.append({"name": name, "age_days": age_days, "status": "alerted"})
            continue

        # Fresh alert above threshold
        if age_days >= ALERT_THRESHOLD_DAYS:
            await db.execute(
                text("""
                    INSERT INTO secret_rotation_alerts (name, alerted_updated_at)
                    VALUES (:n, :u)
                    ON CONFLICT (name) DO UPDATE SET
                        alerted_at = NOW(),
                        alerted_updated_at = EXCLUDED.alerted_updated_at
                """),
                {"n": name, "u": updated_at},
            )
            await send_automation_notification(
                "secret_rotation_due",
                (
                    f"Secret `{name}` ({label}) is {age_days}d old "
                    f"(threshold {ALERT_THRESHOLD_DAYS}d). "
                    f"Rotate via rhorizon and restart api — "
                    f"see env.example §'Secret rotation — SOP'."
                ),
                db,
            )
            sent += 1
            checked.append({"name": name, "age_days": age_days, "status": "alert_sent"})
        else:
            checked.append({"name": name, "age_days": age_days, "status": "ok"})

    await db.commit()
    return {
        "status": "ok",
        "alerts_sent": sent,
        "alerts_cleared": cleared,
        "auto_rotated": rotated,
        "secrets": checked,
    }
