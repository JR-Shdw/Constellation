"""Deployment tests — CRUD, state machine, preflight, stats."""

import pytest


@pytest.fixture
async def deployment(client, auth):
    """Create a deployment in draft status."""
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": "Deploy CMDB v2",
            "deploy_type": "image_pull",
            "worker_hostname": "host-a",
            "repo_name": "youruser/cmdb",
            "branch": "main",
        },
        headers=auth,
    )
    return r.json()["id"]


# CRUD


@pytest.mark.anyio
async def test_create_deployment(client, auth):
    """Create a deployment."""
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": "Test deploy",
            "deploy_type": "image_pull",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert "id" in r.json()


@pytest.mark.anyio
async def test_list_deployments(client, auth, deployment):
    """List deployments."""
    r = await client.get("/api/v1/deployments", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_list_deployments_filter_status(client, auth, deployment):
    """Filter deployments by status."""
    r = await client.get("/api/v1/deployments?status=draft", headers=auth)
    assert r.status_code == 200
    for d in r.json()["items"]:
        assert d["status"] == "draft"


@pytest.mark.anyio
async def test_get_deployment(client, auth, deployment):
    """Get single deployment detail."""
    r = await client.get(f"/api/v1/deployments/{deployment}", headers=auth)
    assert r.status_code == 200
    assert r.json()["title"] == "Deploy CMDB v2"


@pytest.mark.anyio
async def test_update_deployment(client, auth, deployment):
    """Update a draft deployment."""
    r = await client.put(
        f"/api/v1/deployments/{deployment}",
        json={"title": "Deploy CMDB v3"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True

    r = await client.get(f"/api/v1/deployments/{deployment}", headers=auth)
    assert r.json()["title"] == "Deploy CMDB v3"


@pytest.mark.anyio
async def test_update_deployment_empty(client, auth, deployment):
    """Update with no fields does nothing."""
    r = await client.put(
        f"/api/v1/deployments/{deployment}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is False


# Stats


@pytest.mark.anyio
async def test_deployment_stats(client, auth, deployment):
    """Deployment stats returns summary."""
    r = await client.get("/api/v1/deployments/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "active" in data
    assert data["total"] >= 1


# Preflight


@pytest.mark.anyio
async def test_preflight_check(client, auth, deployment):
    """Preflight check runs without error."""
    r = await client.post(f"/api/v1/deployments/{deployment}/preflight", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "checks" in data
    assert "preflight_ok" in data
