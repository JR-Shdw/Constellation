"""Scan + resync + managers coverage."""

import uuid

import pytest

# Scan status


@pytest.mark.anyio
async def test_scan_status(client, auth):
    """GET /scan/status returns scan overview."""
    r = await client.get("/api/v1/scan/status", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data


# Resync endpoints


@pytest.mark.anyio
async def test_resync_wazuh_no_config(client, auth):
    """Resync Wazuh when CVE feature disabled returns error immediately."""
    # Disable CVE feature so the endpoint short-circuits (no 300s poll)
    await client.put(
        "/api/v1/settings/alerts",
        json={"feature_cve_enabled": "false"},
        headers=auth,
    )
    r = await client.post("/api/v1/resync/wazuh", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "error"
    assert "disabled" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_resync_opencve_no_config(client, auth):
    """Resync OpenCVE when CVE feature disabled returns error."""
    await client.put(
        "/api/v1/settings/alerts",
        json={"feature_cve_enabled": "false"},
        headers=auth,
    )
    r = await client.post(
        "/api/v1/resync/opencve",
        json={"hours": 24},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"
    assert "disabled" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_reset_cve_wrong_confirm(client, auth):
    """Reset CVE with wrong confirm string is rejected."""
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={"confirm": "wrong"},
        headers=auth,
    )
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert "error" in r.json().get("status", "") or "error" in r.json()


# Managers


@pytest.mark.anyio
async def test_list_managers(client, auth):
    """List container managers."""
    r = await client.get("/api/v1/managers", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_add_manager(client, auth):
    """Add a container manager."""
    name = f"test-portainer-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/managers",
        json={
            "name": name,
            "url": "https://portainer.test.com",
            "token": "test-token",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert "id" in r.json()


@pytest.mark.anyio
async def test_delete_manager(client, auth):
    """Delete a container manager."""
    name = f"del-mgr-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/managers",
        json={
            "name": name,
            "url": "https://portainer.del.com",
            "token": "tok",
        },
        headers=auth,
    )
    mgr_id = r.json()["id"]
    r = await client.delete(f"/api/v1/managers/{mgr_id}", headers=auth)
    assert r.status_code == 200
