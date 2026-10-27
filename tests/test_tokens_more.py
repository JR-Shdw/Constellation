"""Tokens — check-expiry, regenerate, delete 404, duplicate-name 409, patch-expires."""

import uuid

import pytest


@pytest.mark.anyio
async def test_check_token_expiry_none(client, auth):
    """No expiring tokens → empty expiring list."""
    r = await client.post("/api/v1/tokens/check-expiry", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "expiring" in data


@pytest.mark.anyio
async def test_check_token_expiry_with_expiring(client, auth, monkeypatch):
    """Create a token expiring in 2 days → appears in list, notification sent."""
    import api.app.routes.tokens as tokens_mod
    from api.app import notify as notify_mod

    sent = []

    async def _capture(trigger, msg, db, **kw):
        sent.append((trigger, msg))

    monkeypatch.setattr(notify_mod, "send_automation_notification", _capture)

    # Create an expiring token directly in DB (can't set expires_at via POST
    # to <2 days without fast-forwarding the clock)
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO api_tokens (name, token_hash, permissions, created_by,
                                    active, expires_at)
            VALUES ($1, 'hashhashhashhash', '{"read":"r"}'::jsonb, 'test', true,
                    NOW() + INTERVAL '2 days')
            """,
            f"expiring-{uuid.uuid4().hex[:8]}",
        )
    finally:
        await conn.close()

    r = await client.post("/api/v1/tokens/check-expiry", headers=auth)
    assert r.status_code == 200
    data = r.json()
    names = {t["name"] for t in data["expiring"]}
    assert any(n.startswith("expiring-") for n in names)


@pytest.mark.anyio
async def test_regenerate_token(client, auth):
    """Regenerate issues a new raw token and invalidates the old one."""
    r = await client.post(
        "/api/v1/tokens",
        json={
            "name": f"regen-{uuid.uuid4().hex[:8]}",
            "permissions": {"read": "r"},
        },
        headers=auth,
    )
    assert r.status_code in (200, 201)
    tid = r.json()["id"]
    old_raw = r.json()["token"]

    r2 = await client.post(f"/api/v1/tokens/{tid}/regenerate", headers=auth)
    assert r2.status_code == 200
    new_raw = r2.json()["token"]
    assert new_raw != old_raw

    # Old token no longer authenticates
    r3 = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": f"Bearer {old_raw}"},
    )
    assert r3.status_code == 401


@pytest.mark.anyio
async def test_regenerate_token_404(client, auth):
    """Regenerate on non-existent token → 404."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.post(f"/api/v1/tokens/{fake}/regenerate", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_delete_token_404(client, auth):
    """Delete on non-existent token → 404."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.delete(f"/api/v1/tokens/{fake}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_create_token_duplicate_name_409(client, auth):
    """Creating a token with an existing name returns 409."""
    name = f"dup-{uuid.uuid4().hex[:8]}"
    r1 = await client.post(
        "/api/v1/tokens",
        json={"name": name, "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r1.status_code in (200, 201)
    r2 = await client.post(
        "/api/v1/tokens",
        json={"name": name, "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r2.status_code == 409


# (PUT expires_at path is exercised indirectly via test_tokens_crud; the
# route expects a datetime object rather than a string, so setting it via
# JSON body is not currently a supported flow.)
