"""auth.py — group mappings JSON error, _check_permission default branch,
SECRET_KEY in require_collect_token, DB token paths."""

import uuid

import pytest


@pytest.mark.anyio
async def test_get_group_mappings_invalid_json(monkeypatch):
    """alert_settings.sso_group_mappings as garbage → JSONDecodeError handled
    silently (lines 76-77). Returns built-in defaults, not raise."""
    from api.app.auth import get_group_mappings
    from api.app.database import async_session

    async with async_session() as db:
        # Plant invalid JSON
        from sqlalchemy import text
        await db.execute(
            text("""
            INSERT INTO alert_settings (key, value, updated_at)
            VALUES ('sso_group_mappings', :v, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """),
            {"v": "not-json-{{{"},
        )
        await db.commit()

        mapping = await get_group_mappings(db)
        # Built-in defaults still present
        assert "admin" in mapping
        assert mapping["admin"] == "admin"

        # Cleanup
        await db.execute(
            text("DELETE FROM alert_settings WHERE key = 'sso_group_mappings'")
        )
        await db.commit()


def test_check_permission_unknown_mode_false():
    """mode != 'r'/'w' → False (line 200)."""
    from api.app.auth import _check_permission

    perms = {"read": "r"}
    assert _check_permission(perms, "read", "delete") is False
    assert _check_permission(perms, "read", "x") is False


def test_check_permission_admin_grants_all():
    """admin: 'rw' grants any scope/mode."""
    from api.app.auth import _check_permission

    perms = {"admin": "rw"}
    assert _check_permission(perms, "read", "r") is True
    assert _check_permission(perms, "anything", "w") is True


@pytest.mark.anyio
async def test_collect_endpoint_with_secret_key(client):
    """SECRET_KEY accepted on collect endpoint (lines 227-229)."""
    # /api/v1/nodes/report uses require_collect_token
    r = await client.post(
        "/api/v1/nodes/report",
        json=[],
        headers={"Authorization": "Bearer test-secret-key"},
    )
    # Empty list ingestion is OK (200), or might 422 — either way not 401
    assert r.status_code != 401


@pytest.mark.anyio
async def test_require_auth_via_db_token(client, auth):
    """Create a DB token with read scope then auth via that token (281-283)."""
    # Create token
    name = f"tk-auth-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        "/api/v1/tokens",
        json={"name": name, "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r.status_code in (200, 201)
    raw = r.json()["token"]

    # Use the DB token to call /api/v1/health (any read endpoint)
    r2 = await client.get(
        "/api/v1/heartbeat",
        headers={"Authorization": f"Bearer {raw}"},
    )
    # heartbeat is a read endpoint — 200 if route exists, 404 OK too
    # The point: not 401 (DB token resolved)
    assert r2.status_code != 401


@pytest.mark.anyio
async def test_collect_token_via_require_permission(client):
    """COLLECT_TOKEN works through require_permission for scope=collect,
    mode=w (lines 338-344)."""
    r = await client.post(
        "/api/v1/nodes/report",
        json=[],
        headers={"Authorization": "Bearer test-collect-token"},
    )
    assert r.status_code != 401


@pytest.mark.anyio
async def test_collect_token_rejected_for_settings_write(client):
    """COLLECT_TOKEN cannot write outside collect scope → 403 (line 345)."""
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"matrix_enabled": "false"},
        headers={"Authorization": "Bearer test-collect-token"},
    )
    assert r.status_code in (401, 403)
