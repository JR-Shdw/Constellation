"""Heartbeat extra tests — check endpoint, trends."""

import pytest


@pytest.mark.anyio
async def test_heartbeat_check_bounds_ping_concurrency(client, auth, monkeypatch):
    """The ping wave honors the concurrency cap (no thundering herd at scale)."""
    import asyncio
    import uuid

    import asyncpg

    from api.app.routes import heartbeat
    from tests.conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        for _ in range(6):
            await conn.execute(
                "INSERT INTO nodes (hostname, is_active) VALUES ($1, true)",
                f"hb-conc-{uuid.uuid4().hex[:8]}",
            )
    finally:
        await conn.close()

    monkeypatch.setattr(heartbeat, "_PING_CONCURRENCY", 3)
    monkeypatch.setattr(heartbeat, "_PING_SPACING_S", 0)

    state = {"cur": 0, "max": 0}

    async def _fake_ping(host, timeout=3.0):
        state["cur"] += 1
        state["max"] = max(state["max"], state["cur"])
        await asyncio.sleep(0.02)  # hold the slot so overlap is observable
        state["cur"] -= 1
        return True, 1

    monkeypatch.setattr(heartbeat, "_ping", _fake_ping)

    r = await client.post("/api/v1/heartbeat/check", headers=auth)
    assert r.status_code == 200
    assert r.json()["checked"] >= 6
    assert state["max"] <= 3, f"ping concurrency exceeded cap: {state['max']}"
    assert state["max"] > 1, "pings should run in parallel, not serially"


@pytest.mark.anyio
async def test_heartbeat_check(client, auth, collect_auth):
    """POST /check pings active nodes and records results."""
    # Create a node first
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "heartbeat-check-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    r = await client.post("/api/v1/heartbeat/check", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "checked" in data
    assert "up" in data
    assert "down" in data
    assert "newly_down" in data


@pytest.mark.anyio
async def test_heartbeat_status_after_check(client, auth):
    """Status returns heartbeat info for active nodes."""
    r = await client.get("/api/v1/heartbeat/status", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_heartbeat_history_default(client, auth):
    """History returns hourly aggregates."""
    r = await client.get("/api/v1/heartbeat/history", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
