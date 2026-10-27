"""Scan status endpoint — stale detection + automation evaluation."""

import pytest


@pytest.mark.anyio
async def test_scan_status_with_nodes(client, auth, collect_auth):
    """Scan status after node collection returns items."""
    # Collect a node first
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "scan-test-node",
            "os": "Debian 12",
            "os_family": "debian",
            "kernel": "6.1.0",
            "arch": "x86_64",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )

    r = await client.get("/api/v1/scan/status", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    # The node should appear in scan status
    if data["items"]:
        item = data["items"][0]
        assert "hostname" in item


@pytest.mark.anyio
async def test_scan_status_empty(client, auth):
    """Scan status with no nodes returns empty items."""
    r = await client.get("/api/v1/scan/status", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_scan_stale_fires_on_old_timestamp(client, auth, collect_auth):
    """A node not scanned in 7+ days fires the scan_stale automation event.

    Regression: scan.py read non-existent *_age columns from v_scan_status,
    so item.get() was always None and scan_stale could never fire.
    """
    import asyncpg

    from .conftest import ASYNCPG_DSN

    hostname = "scan-stale-fires"
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "type": "vm",
            "os": "debian",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )

    # Age the last host scan 10 days into the past so the node reads as stale.
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "UPDATE nodes SET last_trivy_host_scan = NOW() - INTERVAL '10 days' "
            "WHERE hostname = $1",
            hostname,
        )
    finally:
        await conn.close()

    # Enabled scan_stale policy (action 'ignore' — logs, no side effects).
    # Creating it via the API also invalidates the trigger-type cache.
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "scan-stale-test",
            "trigger_type": "scan_stale",
            "action": "ignore",
            "enabled": True,
        },
        headers=auth,
    )
    assert r.status_code == 200

    r = await client.get("/api/v1/scan/status", headers=auth)
    assert r.status_code == 200

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        fired = await conn.fetchval(
            "SELECT COUNT(*) FROM automation_log "
            "WHERE trigger_type = 'scan_stale' AND hostname = $1",
            hostname,
        )
    finally:
        await conn.close()
    assert fired >= 1
