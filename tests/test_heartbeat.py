"""Integration tests — heartbeat status + history + patch."""

import asyncpg
import pytest

from .conftest import ASYNCPG_DSN


@pytest.fixture
async def node_for_heartbeat(client, collect_auth):
    """Create an active node for heartbeat tests."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "heartbeat-test-node",
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
    return r.json()["node_id"]


@pytest.mark.anyio
async def test_heartbeat_status(client, auth, node_for_heartbeat):
    """Heartbeat status returns active nodes."""
    r = await client.get("/api/v1/heartbeat/status", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    hostnames = [i["hostname"] for i in items]
    assert "heartbeat-test-node" in hostnames


@pytest.mark.anyio
async def test_heartbeat_history(client, auth):
    """Heartbeat history returns data."""
    r = await client.get("/api/v1/heartbeat/history", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_heartbeat_history_with_node(client, auth, node_for_heartbeat):
    """Heartbeat history filtered by node."""
    r = await client.get(
        f"/api/v1/heartbeat/history?node_id={node_for_heartbeat}",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_heartbeat_history_custom_days(client, auth):
    """Heartbeat history with custom days range."""
    r = await client.get("/api/v1/heartbeat/history?days=30", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_heartbeat_trends_24h_shape(client, auth, node_for_heartbeat):
    """24h trends — one row per hour, with up/down/avg_latency/down_events."""
    # Seed pings : one up at 1h ago, one down at 30 min ago.
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO node_heartbeats (node_id, status, latency_ms, checked_at)
            VALUES
                ($1, 'up', 12, NOW() - INTERVAL '1 hour'),
                ($1, 'down', NULL, NOW() - INTERVAL '30 minutes')
            """,
            node_for_heartbeat,
        )
    finally:
        await conn.close()

    r = await client.get("/api/v1/heartbeat/trends?hours=24", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert len(data["items"]) >= 24, "should produce one row per hour"
    keys = data["items"][0].keys()
    for k in ("hour", "up", "down", "avg_latency_ms", "down_events"):
        assert k in keys
    # The up→down transition we seeded should be counted as one event.
    total_events = sum(b["down_events"] for b in data["items"])
    assert total_events >= 1


@pytest.mark.anyio
async def test_heartbeat_trends_clamps_hours(client, auth):
    """Out-of-range hours param is rejected."""
    r = await client.get("/api/v1/heartbeat/trends?hours=999", headers=auth)
    assert r.status_code == 422


@pytest.mark.anyio
async def test_heartbeat_patch_check_address(client, auth, node_for_heartbeat):
    """Update check_address for a node."""
    r = await client.patch(
        f"/api/v1/heartbeat/nodes/{node_for_heartbeat}",
        json={"check_address": "192.0.2.99"},
        headers=auth,
    )
    assert r.status_code == 200

    # Verify it was set
    r = await client.get("/api/v1/heartbeat/status", headers=auth)
    node = [i for i in r.json()["items"] if i["hostname"] == "heartbeat-test-node"]
    assert node[0]["check_address"] == "192.0.2.99"
