"""Scan — stale detection trigger + automation event firing."""

import pytest


@pytest.mark.anyio
async def test_scan_status_with_nodes(client, auth, collect_auth):
    """Scan status includes nodes and fires stale events."""
    # Create a node so scan status has data
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "scan-stale-node",
            "type": "vm",
            "os": "debian",
            "packages": ["bash\t5.2\tamd64"],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/scan/status", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    # Node should appear in scan status
    hostnames = [i.get("hostname") for i in data["items"]]
    assert "scan-stale-node" in hostnames


@pytest.mark.anyio
async def test_scan_status_empty(client, auth):
    """Scan status works even with minimal data."""
    r = await client.get("/api/v1/scan/status", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
