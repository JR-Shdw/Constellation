"""Scheduler coverage — trigger, runs filter, duplicate name, job types."""

import uuid

import pytest


@pytest.fixture
async def http_job(client, auth):
    """Create an enabled HTTP job and return its ID."""
    r = await client.post(
        "/api/v1/scheduler/jobs",
        json={
            "name": f"cov-http-{uuid.uuid4().hex[:8]}",
            "job_type": "http_request",
            "cron_expr": "0 */6 * * *",
            "config": {
                "method": "GET",
                "url": "/api/v1/health",
                "expected_status": [200],
            },
            "enabled": True,
        },
        headers=auth,
    )
    return r.json()["id"]


# Trigger


@pytest.mark.anyio
async def test_trigger_http_job(client, auth, http_job):
    """Trigger an HTTP job manually executes it."""
    r = await client.post(f"/api/v1/scheduler/jobs/{http_job}/trigger", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") in ("ok", "triggered", "running")


@pytest.mark.anyio
async def test_trigger_nonexistent_job(client, auth):
    """Trigger a non-existent job returns error."""
    fake_id = str(uuid.uuid4())
    r = await client.post(f"/api/v1/scheduler/jobs/{fake_id}/trigger", headers=auth)
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert "error" in r.json() or r.json().get("status") == "error"


# Runs filters


@pytest.mark.anyio
async def test_list_runs_filter_status(client, auth, http_job):
    """Filter runs by status."""
    # Trigger to create a run first
    await client.post(f"/api/v1/scheduler/jobs/{http_job}/trigger", headers=auth)

    r = await client.get("/api/v1/scheduler/runs?status=success", headers=auth)
    assert r.status_code == 200
    for run in r.json()["items"]:
        assert run["status"] == "success"


@pytest.mark.anyio
async def test_list_runs_filter_job_id(client, auth, http_job):
    """Filter runs by job_id."""
    await client.post(f"/api/v1/scheduler/jobs/{http_job}/trigger", headers=auth)

    r = await client.get(f"/api/v1/scheduler/runs?job_id={http_job}", headers=auth)
    assert r.status_code == 200
    for run in r.json()["items"]:
        assert run["job_id"] == http_job


@pytest.mark.anyio
async def test_list_runs_pagination(client, auth):
    """Paginate runs."""
    r = await client.get("/api/v1/scheduler/runs?page=1&per_page=5", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["items"]) <= 5


# Job types


@pytest.mark.anyio
async def test_create_woodpecker_job(client, auth):
    """Create a woodpecker_pipeline job."""
    r = await client.post(
        "/api/v1/scheduler/jobs",
        json={
            "name": f"wp-job-{uuid.uuid4().hex[:8]}",
            "job_type": "woodpecker_pipeline",
            "cron_expr": "0 3 * * *",
            "config": {"repo_name": "youruser/cmdb", "branch": "main"},
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert "id" in r.json()


@pytest.mark.anyio
async def test_create_gitlab_job(client, auth):
    """Create a gitlab_pipeline job."""
    r = await client.post(
        "/api/v1/scheduler/jobs",
        json={
            "name": f"gl-job-{uuid.uuid4().hex[:8]}",
            "job_type": "gitlab_pipeline",
            "cron_expr": "30 2 * * *",
            "config": {"repo_name": "shdw/infra", "branch": "main"},
        },
        headers=auth,
    )
    assert r.status_code == 200


# Job update with cron


@pytest.mark.anyio
async def test_update_job_cron(client, auth, http_job):
    """Update job cron expression."""
    r = await client.put(
        f"/api/v1/scheduler/jobs/{http_job}",
        json={"cron_expr": "*/30 * * * *"},
        headers=auth,
    )
    assert r.status_code == 200

    r = await client.get(f"/api/v1/scheduler/jobs/{http_job}", headers=auth)
    assert r.json()["job"]["cron_expr"] == "*/30 * * * *"


@pytest.mark.anyio
async def test_update_job_config(client, auth, http_job):
    """Update job config."""
    r = await client.put(
        f"/api/v1/scheduler/jobs/{http_job}",
        json={
            "config": {
                "method": "POST",
                "url": "/api/v1/cicd/workers/sync",
                "expected_status": [200],
            }
        },
        headers=auth,
    )
    assert r.status_code == 200
