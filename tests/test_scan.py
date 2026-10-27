"""Integration tests — scan status endpoint."""

import pytest


@pytest.mark.anyio
async def test_scan_status(client, auth):
    """Scan status returns items from v_scan_status."""
    r = await client.get("/api/v1/scan/status", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
