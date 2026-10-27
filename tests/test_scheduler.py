"""Scheduler tests — CRUD jobs, toggle, runs, stats."""

import uuid

import pytest


@pytest.fixture
async def scheduler_job(client, auth):
    """Create a scheduler job and return its id."""
    r = await client.post(
        "/api/v1/scheduler/jobs",
        json={
            "name": f"test-sync-job-{uuid.uuid4().hex[:8]}",
            "job_type": "http_request",
            "cron_expr": "0 */6 * * *",
            "config": {
                "method": "GET",
                "url": "/api/v1/health",
                "expected_status": [200],
            },
            "enabled": False,
        },
        headers=auth,
    )
    return r.json()["id"]


# Jobs CRUD


@pytest.mark.anyio
async def test_create_job(client, auth):
    """Create a scheduler job."""
    r = await client.post(
        "/api/v1/scheduler/jobs",
        json={
            "name": f"create-test-{uuid.uuid4().hex[:8]}",
            "job_type": "http_request",
            "cron_expr": "*/5 * * * *",
            "config": {"method": "GET", "url": "/api/v1/health"},
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert "id" in r.json()


@pytest.mark.anyio
async def test_create_job_invalid_cron(client, auth):
    """Invalid cron expression returns error."""
    r = await client.post(
        "/api/v1/scheduler/jobs",
        json={
            "name": f"bad-cron-{uuid.uuid4().hex[:8]}",
            "job_type": "http_request",
            "cron_expr": "not a cron",
            "config": {},
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert "error" in r.json()


@pytest.mark.anyio
async def test_list_jobs(client, auth, scheduler_job):
    """List jobs returns items."""
    r = await client.get("/api/v1/scheduler/jobs", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


@pytest.mark.anyio
async def test_list_jobs_filter_type(client, auth, scheduler_job):
    """Filter jobs by type."""
    r = await client.get("/api/v1/scheduler/jobs?job_type=http_request", headers=auth)
    assert r.status_code == 200
    for j in r.json()["items"]:
        assert j["job_type"] == "http_request"


@pytest.mark.anyio
async def test_get_job_detail(client, auth, scheduler_job):
    """Get single job detail with runs."""
    r = await client.get(f"/api/v1/scheduler/jobs/{scheduler_job}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "job" in data
    assert "recent_runs" in data
    assert data["job"]["name"].startswith("test-sync-job-")


@pytest.mark.anyio
async def test_update_job(client, auth, scheduler_job):
    """Update a job via PUT."""
    r = await client.put(
        f"/api/v1/scheduler/jobs/{scheduler_job}",
        json={"description": "updated description"},
        headers=auth,
    )
    assert r.status_code == 200

    # Verify
    r = await client.get(f"/api/v1/scheduler/jobs/{scheduler_job}", headers=auth)
    assert r.json()["job"]["description"] == "updated description"


@pytest.mark.anyio
async def test_toggle_job(client, auth, scheduler_job):
    """Toggle a job on/off."""
    r = await client.post(
        f"/api/v1/scheduler/jobs/{scheduler_job}/toggle", headers=auth
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is True

    # Toggle back
    r = await client.post(
        f"/api/v1/scheduler/jobs/{scheduler_job}/toggle", headers=auth
    )
    assert r.json()["enabled"] is False


@pytest.mark.anyio
async def test_delete_job(client, auth):
    """Delete a job."""
    r = await client.post(
        "/api/v1/scheduler/jobs",
        json={
            "name": f"to-delete-{uuid.uuid4().hex[:8]}",
            "job_type": "http_request",
            "cron_expr": "0 0 * * *",
            "config": {},
        },
        headers=auth,
    )
    job_id = r.json()["id"]

    r = await client.delete(f"/api/v1/scheduler/jobs/{job_id}", headers=auth)
    assert r.status_code == 200


# Runs


@pytest.mark.anyio
async def test_list_runs(client, auth):
    """List scheduler runs (empty is fine)."""
    r = await client.get("/api/v1/scheduler/runs", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
    assert "total" in r.json()


# Stats


@pytest.mark.anyio
async def test_scheduler_stats(client, auth, scheduler_job):
    """Scheduler stats returns summary."""
    r = await client.get("/api/v1/scheduler/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total_jobs" in data
    assert "enabled_jobs" in data
    assert "running_jobs" in data
    assert "failure_24h" in data
    assert "success_24h" in data
