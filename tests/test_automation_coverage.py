"""Automation coverage — matcher logic, policy filters, log queries."""

import uuid

import pytest


@pytest.fixture
async def policy_id(client, auth):
    """Create a policy and return its ID."""
    name = f"cov-policy-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 50,
            "enabled": True,
            "auto_execute": False,
            "match_severity": ["critical"],
            "match_environment": ["production"],
        },
        headers=auth,
    )
    return r.json()["id"]


@pytest.mark.anyio
async def test_policy_in_list(client, auth, policy_id):
    """Created policy appears in list."""
    r = await client.get("/api/v1/automation/policies", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(p["id"] == policy_id for p in items)


@pytest.mark.anyio
async def test_policy_update_filters(client, auth, policy_id):
    """Update policy match filters."""
    r = await client.put(
        f"/api/v1/automation/policies/{policy_id}",
        json={
            "match_severity": ["critical", "high"],
            "match_hostname": "%prod%",
            "priority": 100,
        },
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_policy_toggle_enabled(client, auth, policy_id):
    """Toggle policy enabled status via PUT."""
    r = await client.put(
        f"/api/v1/automation/policies/{policy_id}",
        json={"enabled": False},
        headers=auth,
    )
    assert r.status_code == 200
    # Verify in list
    r = await client.get("/api/v1/automation/policies", headers=auth)
    policy = [p for p in r.json()["items"] if p["id"] == policy_id]
    assert policy and policy[0]["enabled"] is False


@pytest.mark.anyio
async def test_automation_log_list(client, auth):
    """List automation execution log."""
    r = await client.get("/api/v1/automation/log", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_automation_log_filter_status(client, auth):
    """Filter automation log by status."""
    r = await client.get("/api/v1/automation/log?status=executed", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_policy_test_match(client, auth, policy_id):
    """Test endpoint finds matching policy for event."""
    r = await client.post(
        "/api/v1/automation/test",
        json={
            "trigger_type": "cve_detected",
            "hostname": "prod-server",
            "cve_id": "CVE-2024-1234",
            "severity": "critical",
            "environment": "production",
        },
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert "matched" in data
    assert "event" in data


@pytest.mark.anyio
async def test_policy_test_no_match(client, auth, policy_id):
    """Test endpoint with non-matching event."""
    r = await client.post(
        "/api/v1/automation/test",
        json={
            "trigger_type": "backup_overdue",
            "hostname": "lab-server",
        },
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_policy_delete(client, auth):
    """Delete a policy."""
    name = f"del-policy-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "backup_overdue",
            "action": "notify",
        },
        headers=auth,
    )
    pid = r.json()["id"]
    r = await client.delete(f"/api/v1/automation/policies/{pid}", headers=auth)
    assert r.status_code == 200
