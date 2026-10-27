"""Integration tests — automation policies + matching."""

import pytest


@pytest.mark.anyio
async def test_policy_crud(client, auth):
    """Create, list, update, delete a policy."""
    # Create
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "test-notify-critical",
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 10,
            "match_severity": ["critical"],
            "match_environment": ["production"],
        },
        headers=auth,
    )
    assert r.status_code == 200
    pid = r.json()["id"]

    # List
    r = await client.get("/api/v1/automation/policies", headers=auth)
    assert r.status_code == 200
    names = [p["name"] for p in r.json()["items"]]
    assert "test-notify-critical" in names

    # Update
    r = await client.put(
        f"/api/v1/automation/policies/{pid}",
        json={"priority": 20},
        headers=auth,
    )
    assert r.status_code == 200

    # Delete
    r = await client.delete(f"/api/v1/automation/policies/{pid}", headers=auth)
    assert r.status_code == 200

    # Verify deleted
    r = await client.get("/api/v1/automation/policies", headers=auth)
    names = [p["name"] for p in r.json()["items"]]
    assert "test-notify-critical" not in names


@pytest.mark.anyio
async def test_policy_matching_dry_run(client, auth):
    """Dry-run: test which policy matches an event."""
    # Create two policies
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "catch-all",
            "trigger_type": "cve_detected",
            "action": "ignore",
            "priority": 0,
        },
        headers=auth,
    )
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "critical-prod",
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 10,
            "match_severity": ["critical"],
            "match_environment": ["production"],
        },
        headers=auth,
    )

    # Test: critical + production → should match "critical-prod" (higher priority)
    r = await client.post(
        "/api/v1/automation/test",
        json={
            "trigger_type": "cve_detected",
            "severity": "critical",
            "environment": "production",
            "hostname": "host-b",
        },
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["matched"] is True
    assert data["policy"]["name"] == "critical-prod"

    # Test: low severity → should match "catch-all"
    r = await client.post(
        "/api/v1/automation/test",
        json={
            "trigger_type": "cve_detected",
            "severity": "low",
            "environment": "production",
        },
        headers=auth,
    )
    data = r.json()
    assert data["matched"] is True
    assert data["policy"]["name"] == "catch-all"

    # Test: different trigger → no match
    r = await client.post(
        "/api/v1/automation/test",
        json={"trigger_type": "backup_overdue", "hostname": "host-b"},
        headers=auth,
    )
    assert r.json()["matched"] is False

    # Cleanup
    policies = (await client.get("/api/v1/automation/policies", headers=auth)).json()[
        "items"
    ]
    for p in policies:
        await client.delete(f"/api/v1/automation/policies/{p['id']}", headers=auth)
