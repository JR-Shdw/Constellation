"""Deployment state machine tests — submit, approve, reject, complete, cancel."""

import pytest


@pytest.fixture
async def draft_deployment(client, auth):
    """Create a deployment in draft status."""
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": "State machine test",
            "deploy_type": "image_pull",
            "worker_hostname": "host-a",
        },
        headers=auth,
    )
    return r.json()["id"]


# Submit (draft → pending)


@pytest.mark.anyio
async def test_submit_deployment(client, auth, draft_deployment):
    """Submit transitions draft to pending."""
    r = await client.post(
        f"/api/v1/deployments/{draft_deployment}/submit",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["new_status"] == "pending"


@pytest.mark.anyio
async def test_submit_non_draft_fails(client, auth, draft_deployment):
    """Submit from non-draft status fails."""
    # First submit to pending
    await client.post(
        f"/api/v1/deployments/{draft_deployment}/submit",
        headers=auth,
    )
    # Try to submit again
    r = await client.post(
        f"/api/v1/deployments/{draft_deployment}/submit",
        headers=auth,
    )
    assert r.status_code == 409


# Approve (pending → approved)


@pytest.mark.anyio
async def test_approve_deployment(client, auth, draft_deployment):
    """Approve transitions pending to approved."""
    await client.post(
        f"/api/v1/deployments/{draft_deployment}/submit",
        headers=auth,
    )
    r = await client.post(
        f"/api/v1/deployments/{draft_deployment}/approve",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["new_status"] == "approved"


@pytest.mark.anyio
async def test_approve_draft_fails(client, auth, draft_deployment):
    """Cannot approve a draft deployment."""
    r = await client.post(
        f"/api/v1/deployments/{draft_deployment}/approve",
        headers=auth,
    )
    assert r.status_code == 409


# Reject (pending → cancelled)


@pytest.mark.anyio
async def test_reject_deployment(client, auth, draft_deployment):
    """Reject transitions pending to cancelled."""
    await client.post(
        f"/api/v1/deployments/{draft_deployment}/submit",
        headers=auth,
    )
    r = await client.post(
        f"/api/v1/deployments/{draft_deployment}/reject",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["new_status"] == "cancelled"


# Execute (approved → running)


@pytest.mark.anyio
async def test_execute_deployment(client, auth, draft_deployment):
    """Execute transitions approved to running."""
    await client.post(
        f"/api/v1/deployments/{draft_deployment}/submit",
        headers=auth,
    )
    await client.post(
        f"/api/v1/deployments/{draft_deployment}/approve",
        headers=auth,
    )
    r = await client.post(
        f"/api/v1/deployments/{draft_deployment}/execute",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["new_status"] == "running"


@pytest.mark.anyio
async def test_execute_draft_fails(client, auth, draft_deployment):
    """Cannot execute a draft deployment."""
    r = await client.post(
        f"/api/v1/deployments/{draft_deployment}/execute",
        headers=auth,
    )
    assert r.status_code == 409


# Non-existent deployment


@pytest.mark.anyio
async def test_get_nonexistent_deployment(client, auth):
    """Get non-existent deployment returns 404."""
    r = await client.get(
        "/api/v1/deployments/00000000-0000-0000-0000-000000000000",
        headers=auth,
    )
    assert r.status_code == 404
