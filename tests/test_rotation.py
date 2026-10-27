"""Secret rotation alerting — vault age check, alert/clear, auto-rotate."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import asyncpg
import pytest

from api.app.utils import rotation

from .conftest import ASYNCPG_DSN


def _iso(days_ago: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat()


async def _seed_alert(name: str, alerted_updated_at: datetime) -> None:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO secret_rotation_alerts (name, alerted_updated_at)
            VALUES ($1, $2)
            ON CONFLICT (name) DO UPDATE
                SET alerted_updated_at = EXCLUDED.alerted_updated_at
            """,
            name,
            alerted_updated_at,
        )
    finally:
        await conn.close()


async def _alert_exists(name: str) -> bool:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        return bool(
            await conn.fetchval(
                "SELECT 1 FROM secret_rotation_alerts WHERE name = $1", name
            )
        )
    finally:
        await conn.close()


@pytest.fixture
def fake_vault():
    """Patch vault_configured + HTTP calls. Returns a mutable `items` list."""
    items: list[dict] = []
    puts: list[tuple[str, str]] = []

    async def _fake_fetch():
        return items

    async def _fake_put(name, value):
        puts.append((name, value))

    with (
        patch(
            "api.app.utils.rotation.vault_configured",
            return_value=True,
        ),
        patch(
            "api.app.utils.rotation._fetch_vault_secrets",
            new=AsyncMock(side_effect=_fake_fetch),
        ),
        patch(
            "api.app.utils.rotation._put_vault_secret",
            new=AsyncMock(side_effect=_fake_put),
        ),
        patch(
            "api.app.utils.rotation.send_automation_notification",
            new_callable=AsyncMock,
        ) as mock_notif,
    ):
        yield {"items": items, "puts": puts, "notif": mock_notif}


@pytest.mark.anyio
async def test_skipped_when_vault_not_configured(client):
    """No vault → early return."""
    from api.app.database import async_session

    with patch("api.app.utils.rotation.vault_configured", return_value=False):
        async with async_session() as db:
            result = await rotation.check_rotations(db)

    assert result == {"status": "skipped", "reason": "vault_not_configured"}


@pytest.mark.anyio
async def test_error_when_vault_unreachable(client):
    """Fetch raising → status=error, reason propagated (truncated)."""
    from api.app.database import async_session

    with (
        patch("api.app.utils.rotation.vault_configured", return_value=True),
        patch(
            "api.app.utils.rotation._fetch_vault_secrets",
            new=AsyncMock(side_effect=RuntimeError("connection refused")),
        ),
    ):
        async with async_session() as db:
            result = await rotation.check_rotations(db)

    assert result["status"] == "error"
    assert "connection refused" in result["reason"]


@pytest.mark.anyio
async def test_missing_secret_reported(client, fake_vault):
    """Secret listed in _SECRETS but absent from vault → status=missing."""
    from api.app.database import async_session

    fake_vault["items"].clear()  # nothing in vault

    async with async_session() as db:
        result = await rotation.check_rotations(db)

    assert result["status"] == "ok"
    statuses = {s["name"]: s["status"] for s in result["secrets"]}
    for name in rotation._SECRETS:
        assert statuses[name] == "missing"
    fake_vault["notif"].assert_not_called()


@pytest.mark.anyio
async def test_fresh_secret_is_ok(client, fake_vault):
    """Age below threshold → status=ok, no alert, no notification."""
    from api.app.database import async_session

    fake_vault["items"].extend(
        {"name": n, "updated_at": _iso(30)} for n in rotation._SECRETS
    )

    async with async_session() as db:
        result = await rotation.check_rotations(db)

    assert result["alerts_sent"] == 0
    assert all(s["status"] == "ok" for s in result["secrets"])
    fake_vault["notif"].assert_not_called()


@pytest.mark.anyio
async def test_alert_sent_when_stale(client, fake_vault):
    """Age >= 330d + no prior alert → alert row inserted + notification sent."""
    from api.app.database import async_session

    fake_vault["items"].append({"name": "cmdb-gitea-token", "updated_at": _iso(335)})

    async with async_session() as db:
        result = await rotation.check_rotations(db)

    assert result["alerts_sent"] == 1
    assert await _alert_exists("cmdb-gitea-token")
    fake_vault["notif"].assert_called_once()
    msg = fake_vault["notif"].call_args[0][1]
    assert "cmdb-gitea-token" in msg
    assert "335d old" in msg


@pytest.mark.anyio
async def test_already_alerted_stays_quiet(client, fake_vault):
    """Second pass on same version → no duplicate notification."""
    from api.app.database import async_session

    updated = datetime.now(timezone.utc) - timedelta(days=340)
    await _seed_alert("cmdb-gitea-token", updated)

    fake_vault["items"].append(
        {"name": "cmdb-gitea-token", "updated_at": updated.isoformat()}
    )

    async with async_session() as db:
        result = await rotation.check_rotations(db)

    assert result["alerts_sent"] == 0
    fake_vault["notif"].assert_not_called()
    entry = next(s for s in result["secrets"] if s["name"] == "cmdb-gitea-token")
    assert entry["status"] == "alerted"


@pytest.mark.anyio
async def test_rotation_detected_clears_alert(client, fake_vault):
    """New updated_at > stored alerted_updated_at → clear alert + notify."""
    from api.app.database import async_session

    old = datetime.now(timezone.utc) - timedelta(days=340)
    await _seed_alert("cmdb-gitea-token", old)

    fake_vault["items"].append({"name": "cmdb-gitea-token", "updated_at": _iso(1)})

    async with async_session() as db:
        result = await rotation.check_rotations(db)

    assert result["alerts_cleared"] == 1
    assert not await _alert_exists("cmdb-gitea-token")
    fake_vault["notif"].assert_called_once()
    msg = fake_vault["notif"].call_args[0][1]
    assert "alert cleared" in msg


@pytest.mark.anyio
async def test_auto_rotate_secret_key(client, fake_vault):
    """cmdb-secret-key crosses 365d → auto-rotate PUT + notification."""
    from api.app.database import async_session

    fake_vault["items"].append({"name": "cmdb-secret-key", "updated_at": _iso(400)})

    async with async_session() as db:
        result = await rotation.check_rotations(db)

    assert result["auto_rotated"] == 1
    assert len(fake_vault["puts"]) == 1
    put_name, put_value = fake_vault["puts"][0]
    assert put_name == "cmdb-secret-key"
    # token_hex(32) = 64 hex chars
    assert len(put_value) == 64
    fake_vault["notif"].assert_called_once()
    msg = fake_vault["notif"].call_args[0][1]
    assert "Auto-rotated" in msg


@pytest.mark.anyio
async def test_auto_rotate_clears_previous_alert(client, fake_vault):
    """Auto-rotate on an already-alerted secret removes the alert row."""
    from api.app.database import async_session

    old = datetime.now(timezone.utc) - timedelta(days=400)
    await _seed_alert("cmdb-secret-key", old)

    fake_vault["items"].append(
        {"name": "cmdb-secret-key", "updated_at": old.isoformat()}
    )

    async with async_session() as db:
        await rotation.check_rotations(db)

    assert not await _alert_exists("cmdb-secret-key")
    assert len(fake_vault["puts"]) == 1


@pytest.mark.anyio
async def test_auto_rotate_put_failure(client, fake_vault):
    """PUT failure → status=rotate_failed, no notification, no alert change."""
    from api.app.database import async_session

    with patch(
        "api.app.utils.rotation._put_vault_secret",
        new=AsyncMock(side_effect=RuntimeError("vault 500")),
    ):
        fake_vault["items"].append({"name": "cmdb-secret-key", "updated_at": _iso(400)})

        async with async_session() as db:
            result = await rotation.check_rotations(db)

    assert result["auto_rotated"] == 0
    entry = next(s for s in result["secrets"] if s["name"] == "cmdb-secret-key")
    assert entry["status"] == "rotate_failed"
    # Notification only fires on success path
    fake_vault["notif"].assert_not_called()


@pytest.mark.anyio
async def test_non_auto_rotate_secret_only_alerts(client, fake_vault):
    """Secrets outside _AUTO_ROTATE stay on alert path even > 365d."""
    from api.app.database import async_session

    fake_vault["items"].append({"name": "cmdb-gitea-token", "updated_at": _iso(400)})

    async with async_session() as db:
        result = await rotation.check_rotations(db)

    assert result["auto_rotated"] == 0
    assert result["alerts_sent"] == 1
    assert len(fake_vault["puts"]) == 0


@pytest.mark.anyio
async def test_parse_iso_naive_defaults_utc():
    """_parse_iso treats naive timestamps as UTC (no crash, sane tz)."""
    dt = rotation._parse_iso("2026-01-01T12:00:00")
    assert dt.tzinfo is not None
    assert dt.tzinfo.utcoffset(dt).total_seconds() == 0


@pytest.mark.anyio
async def test_rotation_check_endpoint(client, auth, fake_vault):
    """POST /settings/rotation-check triggers the same logic via HTTP."""
    fake_vault["items"].append({"name": "cmdb-gitea-token", "updated_at": _iso(400)})

    r = await client.post("/api/v1/settings/rotation-check", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["alerts_sent"] == 1
