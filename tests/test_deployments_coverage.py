"""Deployments coverage — update fields, preflight details, delete."""

import pytest


@pytest.fixture
async def draft_deployment(client, auth):
    """Create a draft deployment and return its ID."""
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": "Coverage deploy test",
            "deploy_type": "image_pull",
            "worker_hostname": "host-b",
        },
        headers=auth,
    )
    return r.json()["id"]


@pytest.mark.anyio
async def test_update_deployment_title(client, auth, draft_deployment):
    """Update deployment title."""
    r = await client.put(
        f"/api/v1/deployments/{draft_deployment}",
        json={"title": "Updated title"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_deployment_branch(client, auth, draft_deployment):
    """Update deployment branch and repo_name."""
    r = await client.put(
        f"/api/v1/deployments/{draft_deployment}",
        json={"repo_name": "youruser/cmdb", "branch": "main"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_deployment_config(client, auth, draft_deployment):
    """Update deployment config JSON."""
    r = await client.put(
        f"/api/v1/deployments/{draft_deployment}",
        json={"config": {"image": "nginx:1.25", "tag": "latest"}},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_deployment_not_found(client, auth):
    """Update nonexistent deployment returns 404."""
    import uuid

    r = await client.put(
        f"/api/v1/deployments/{uuid.uuid4()}",
        json={"title": "nope"},
        headers=auth,
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_update_approved_deployment_rejected(client, auth, draft_deployment):
    """Cannot update deployment after approval."""
    # Submit then approve
    await client.post(f"/api/v1/deployments/{draft_deployment}/submit", headers=auth)
    await client.post(f"/api/v1/deployments/{draft_deployment}/approve", headers=auth)
    r = await client.put(
        f"/api/v1/deployments/{draft_deployment}",
        json={"title": "too late"},
        headers=auth,
    )
    assert r.status_code == 409


@pytest.mark.anyio
async def test_deployment_full_lifecycle(client, auth):
    """Full lifecycle: create → submit → approve → execute."""
    # Create
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": "Lifecycle test",
            "deploy_type": "image_pull",
            "worker_hostname": "host-b",
        },
        headers=auth,
    )
    dep_id = r.json()["id"]

    # Submit
    r = await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    assert r.status_code == 200

    # Approve
    r = await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)
    assert r.status_code == 200

    # Execute
    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    assert r.status_code == 200

    # Verify final status
    r = await client.get(f"/api/v1/deployments/{dep_id}", headers=auth)
    assert r.json()["status"] in ("running", "success", "failure")


@pytest.mark.anyio
async def test_deployment_reject_lifecycle(client, auth):
    """Reject lifecycle: create → submit → reject."""
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": "Reject test",
            "deploy_type": "container_deploy",
            "worker_hostname": "host-a",
        },
        headers=auth,
    )
    dep_id = r.json()["id"]

    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/reject", headers=auth)
    assert r.status_code == 200

    r = await client.get(f"/api/v1/deployments/{dep_id}", headers=auth)
    assert r.json()["status"] == "cancelled"
