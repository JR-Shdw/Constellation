"""Extra automation tests — CRUD, toggle, log listing."""

import pytest


@pytest.mark.anyio
async def test_policy_create_and_list(client, auth):
    """Create policy and verify it appears in list."""
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "test-auto-notify",
            "trigger_type": "cve_detected",
            "action": "notify",
            "match_severity": ["critical"],
            "match_environment": ["production"],
            "auto_execute": True,
            "priority": 50,
        },
        headers=auth,
    )
    assert r.status_code == 200
    policy_id = r.json()["id"]

    # List
    r = await client.get("/api/v1/automation/policies", headers=auth)
    assert r.status_code == 200
    found = [p for p in r.json()["items"] if p["id"] == policy_id]
    assert len(found) == 1
    assert found[0]["trigger_type"] == "cve_detected"


@pytest.mark.anyio
async def test_policy_update(client, auth):
    """Update a policy via PUT."""
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "update-test-policy",
            "trigger_type": "backup_overdue",
            "action": "notify",
            "enabled": True,
        },
        headers=auth,
    )
    policy_id = r.json()["id"]

    # Update via PUT (disable)
    r = await client.put(
        f"/api/v1/automation/policies/{policy_id}",
        json={
            "name": "update-test-policy",
            "trigger_type": "backup_overdue",
            "action": "notify",
            "enabled": False,
        },
        headers=auth,
    )
    assert r.status_code == 200

    # Verify disabled
    r = await client.get("/api/v1/automation/policies", headers=auth)
    policy = [p for p in r.json()["items"] if p["id"] == policy_id]
    assert policy[0]["enabled"] is False


@pytest.mark.anyio
async def test_policy_delete(client, auth):
    """Delete a policy."""
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "delete-test-policy",
            "trigger_type": "worker_offline",
            "action": "notify",
        },
        headers=auth,
    )
    policy_id = r.json()["id"]

    r = await client.delete(f"/api/v1/automation/policies/{policy_id}", headers=auth)
    assert r.status_code == 200

    # Verify deleted
    r = await client.get("/api/v1/automation/policies", headers=auth)
    ids = [p["id"] for p in r.json()["items"]]
    assert policy_id not in ids


@pytest.mark.anyio
async def test_automation_log(client, auth):
    """List automation log."""
    r = await client.get("/api/v1/automation/log", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
