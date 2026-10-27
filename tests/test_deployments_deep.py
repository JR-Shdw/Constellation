"""Deployments deep coverage — execute, filter, stats, lifecycle."""

import uuid

import pytest

# Execute approved deployment


@pytest.mark.anyio
async def test_execute_approved_deployment(client, auth):
    """Execute an approved deployment (may 503 without CI)."""
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": f"exec-dep-{uuid.uuid4().hex[:8]}",
            "deploy_type": "container_build",
            "worker_hostname": "test-worker",
            "repo_name": "youruser/cmdb",
            "branch": "main",
        },
        headers=auth,
    )
    dep_id = r.json()["id"]

    # Submit → approve → execute
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)

    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    # 200 (success) or 503 (no CI configured) are both valid
    assert r.status_code in (200, 503)


# Deployment filters


@pytest.mark.anyio
async def test_list_deployments_filter_type(client, auth):
    """Filter deployments by deploy_type."""
    await client.post(
        "/api/v1/deployments",
        json={
            "title": f"filter-{uuid.uuid4().hex[:8]}",
            "deploy_type": "ansible_playbook",
            "worker_hostname": "test",
        },
        headers=auth,
    )
    r = await client.get(
        "/api/v1/deployments?deploy_type=ansible_playbook",
        headers=auth,
    )
    assert r.status_code == 200
    for d in r.json()["items"]:
        assert d["deploy_type"] == "ansible_playbook"


@pytest.mark.anyio
async def test_list_deployments_has_total(client, auth):
    """Deployments list includes total count."""
    r = await client.get("/api/v1/deployments", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] >= 0


# Deployment stats


@pytest.mark.anyio
async def test_deployment_stats_has_fields(client, auth):
    """Deployment stats returns expected fields."""
    r = await client.get("/api/v1/deployments/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data or "items" in data


# Deployment get non-existent


@pytest.mark.anyio
async def test_get_nonexistent_deployment(client, auth):
    """GET non-existent deployment returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.get(f"/api/v1/deployments/{fake_id}", headers=auth)
    assert r.status_code == 404
