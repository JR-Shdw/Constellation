"""Deployments — list filters, update draft, preflight details, delete."""

import uuid

import pytest


async def _make_deployment(client, auth, **overrides):
    """Create a deployment, return id."""
    data = {
        "title": f"dep-{uuid.uuid4().hex[:8]}",
        "deploy_type": "image_pull",
    }
    data.update(overrides)
    r = await client.post("/api/v1/deployments", json=data, headers=auth)
    assert r.status_code == 200
    return r.json()["id"]


# List filters


@pytest.mark.anyio
async def test_list_deployments_empty(client, auth):
    """List with no deployments returns empty."""
    r = await client.get("/api/v1/deployments", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.anyio
async def test_list_deployments_filter_status(client, auth):
    """Filter deployments by status."""
    await _make_deployment(client, auth)
    r = await client.get("/api/v1/deployments?status=draft", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_list_deployments_filter_type(client, auth):
    """Filter deployments by deploy_type."""
    await _make_deployment(client, auth, deploy_type="ansible_playbook")
    r = await client.get(
        "/api/v1/deployments?deploy_type=ansible_playbook", headers=auth
    )
    assert r.status_code == 200
    assert r.json()["total"] >= 1


# Get detail


@pytest.mark.anyio
async def test_get_deployment_detail(client, auth):
    """Get single deployment detail."""
    dep_id = await _make_deployment(client, auth)
    r = await client.get(f"/api/v1/deployments/{dep_id}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == dep_id
    assert data["status"] == "draft"


@pytest.mark.anyio
async def test_get_deployment_not_found(client, auth):
    """Get non-existent deployment returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.get(f"/api/v1/deployments/{fake_id}", headers=auth)
    assert r.status_code == 404


# Update


@pytest.mark.anyio
async def test_update_draft_deployment(client, auth):
    """Update title and branch on a draft deployment."""
    dep_id = await _make_deployment(client, auth)
    r = await client.put(
        f"/api/v1/deployments/{dep_id}",
        json={"title": "updated-title", "branch": "dev"},
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_update_deployment_no_changes(client, auth):
    """Update with empty payload returns ok/unchanged."""
    dep_id = await _make_deployment(client, auth)
    r = await client.put(
        f"/api/v1/deployments/{dep_id}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json().get("changed") is False


@pytest.mark.anyio
async def test_update_approved_deployment_fails(client, auth):
    """Cannot update an approved deployment."""
    dep_id = await _make_deployment(client, auth)
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)
    r = await client.put(
        f"/api/v1/deployments/{dep_id}",
        json={"title": "nope"},
        headers=auth,
    )
    assert r.status_code == 409


@pytest.mark.anyio
async def test_update_not_found(client, auth):
    """Update non-existent deployment returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.put(
        f"/api/v1/deployments/{fake_id}",
        json={"title": "x"},
        headers=auth,
    )
    assert r.status_code == 404


# Stats


@pytest.mark.anyio
async def test_deployment_stats(client, auth):
    """Deployment stats returns counts."""
    await _make_deployment(client, auth)
    r = await client.get("/api/v1/deployments/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    assert "active" in data
    assert "running" in data
