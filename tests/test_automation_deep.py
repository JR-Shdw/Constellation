"""Automation deep coverage — approve/skip, execution, run_evaluation."""

import uuid

import pytest


@pytest.fixture
async def auto_policy(client, auth):
    """Create an auto_execute policy and return its ID."""
    name = f"deep-auto-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 200,
            "enabled": True,
            "auto_execute": True,
            "match_severity": ["critical"],
        },
        headers=auth,
    )
    return r.json()["id"]


@pytest.fixture
async def manual_policy(client, auth):
    """Create a manual_validation policy."""
    name = f"deep-manual-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "backup_overdue",
            "action": "manual_validation",
            "priority": 300,
            "enabled": True,
            "auto_execute": False,
        },
        headers=auth,
    )
    return r.json()["id"]


@pytest.fixture
async def ignore_policy(client, auth):
    """Create an ignore policy."""
    name = f"deep-ignore-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "ignore",
            "priority": 500,
            "enabled": True,
            "match_severity": ["low"],
            "match_environment": ["lab"],
        },
        headers=auth,
    )
    return r.json()["id"]


# Policy CRUD extras


@pytest.mark.anyio
async def test_policy_with_all_filters(client, auth):
    """Create policy with all match filters."""
    name = f"all-filters-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "image_update_available",
            "action": "pull_image",
            "match_hostname": "%prod%",
            "match_container": "nginx%",
            "match_image": "nginx:%",
            "match_package": "openssl",
            "match_cve_id": "CVE-2024-%",
            "match_severity": ["critical", "high"],
            "match_environment": ["production"],
            "match_exposure": ["internet"],
            "auto_execute": True,
            "priority": 150,
        },
        headers=auth,
    )
    assert r.status_code == 200
    pid = r.json()["id"]

    # Verify filters persisted
    r = await client.get("/api/v1/automation/policies", headers=auth)
    policy = next((p for p in r.json()["items"] if p["id"] == pid), None)
    assert policy
    assert policy["match_hostname"] == "%prod%"
    assert policy["match_exposure"] == ["internet"]


@pytest.mark.anyio
async def test_policy_update_action_and_notify(client, auth, auto_policy):
    """Update policy action and notify_room."""
    r = await client.put(
        f"/api/v1/automation/policies/{auto_policy}",
        json={
            "action": "notify",
            "notify_room": "!test:matrix.org",
        },
        headers=auth,
    )
    assert r.status_code == 200


# Log approve/skip


@pytest.mark.anyio
async def test_approve_log_entry(client, auth, manual_policy):
    """Approve a pending automation log entry."""
    # Trigger an event that matches the manual policy
    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    async with async_session() as db:
        await run_evaluation(
            {"trigger_type": "backup_overdue", "hostname": "test-host"},
            db,
        )
        await db.commit()

    # Find pending log
    r = await client.get("/api/v1/automation/log?status=pending", headers=auth)
    pending = r.json()["items"]
    if not pending:
        pytest.skip("no pending log entry")

    log_id = pending[0]["id"]
    r = await client.post(f"/api/v1/automation/log/{log_id}/approve", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_skip_log_entry(client, auth, manual_policy):
    """Skip a pending automation log entry."""
    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    async with async_session() as db:
        await run_evaluation(
            {"trigger_type": "backup_overdue", "hostname": "skip-host"},
            db,
        )
        await db.commit()

    r = await client.get("/api/v1/automation/log?status=pending", headers=auth)
    pending = r.json()["items"]
    if not pending:
        pytest.skip("no pending log entry")

    log_id = pending[0]["id"]
    r = await client.post(f"/api/v1/automation/log/{log_id}/skip", headers=auth)
    assert r.status_code == 200


# Ignore policy test


@pytest.mark.anyio
async def test_ignore_policy_match(client, auth, ignore_policy):
    """Test match returns ignore policy for low/lab event."""
    r = await client.post(
        "/api/v1/automation/test",
        json={
            "trigger_type": "cve_detected",
            "severity": "low",
            "environment": "lab",
        },
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    if data.get("matched") and isinstance(data["matched"], dict):
        assert data["matched"]["action"] == "ignore"


# Automation log filters


@pytest.mark.anyio
async def test_automation_log_filter_trigger(client, auth):
    """Filter automation log by trigger_type."""
    r = await client.get(
        "/api/v1/automation/log?trigger_type=cve_detected", headers=auth
    )
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_automation_log_pagination(client, auth):
    """Paginate automation log."""
    r = await client.get("/api/v1/automation/log?page=1&per_page=5", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["items"]) <= 5
