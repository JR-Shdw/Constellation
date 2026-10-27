"""CI/CD tests — repos, pipelines, workers, servers, stats."""

import pytest


@pytest.fixture
async def cicd_data(client, collect_auth):
    """Ingest repos, pipelines, and workers."""
    await client.post(
        "/api/v1/cicd/repos/report",
        json=[
            {
                "forge": "gitea",
                "full_name": "youruser/cmdb",
                "owner": "testuser",
                "description": "CMDB project",
                "default_branch": "main",
                "html_url": "https://gitea.example.com/youruser/cmdb",
                "private": False,
                "language": "Python",
                "topics": ["infra", "security"],
                "stars_count": 5,
                "has_pipeline": True,
                "branches": ["main", "dev"],
            },
        ],
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": "youruser/cmdb",
                "number": 100,
                "status": "success",
                "event": "push",
                "branch": "main",
                "commit": "abc123",
                "message": "test commit",
                "author": "testuser",
                "duration_secs": 120,
                "link": "https://ci.example.com/100",
            },
            {
                "ci_system": "woodpecker",
                "repo_name": "youruser/cmdb",
                "number": 101,
                "status": "failure",
                "event": "push",
                "branch": "dev",
                "commit": "def456",
                "message": "broken",
                "author": "testuser",
                "duration_secs": 30,
            },
        ],
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cicd/workers/report",
        json=[
            {
                "ci_system": "woodpecker",
                "external_id": "1",
                "name": "agent-1",
                "hostname": "host-a",
                "platform": "linux/amd64",
                "labels": {"host": "host-a"},
                "capacity": 2,
                "status": "connected",
            },
        ],
        headers=collect_auth,
    )


# Repos


@pytest.mark.anyio
async def test_repos_report(client, collect_auth):
    """Upsert repos returns ok."""
    r = await client.post(
        "/api/v1/cicd/repos/report",
        json=[{"full_name": "shdw/test", "forge": "gitea"}],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


@pytest.mark.anyio
async def test_list_repos(client, auth, cicd_data):
    """List repos returns items."""
    r = await client.get("/api/v1/cicd/repos", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


# Pipelines


@pytest.mark.anyio
async def test_pipelines_report(client, collect_auth):
    """Upsert pipelines returns ok."""
    r = await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "repo_name": "shdw/test",
                "number": 1,
                "status": "success",
                "ci_system": "woodpecker",
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


@pytest.mark.anyio
async def test_list_pipelines(client, auth, cicd_data):
    """List pipelines with filters."""
    r = await client.get("/api/v1/cicd/pipelines", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


@pytest.mark.anyio
async def test_list_pipelines_filter_status(client, auth, cicd_data):
    """Filter pipelines by status."""
    r = await client.get("/api/v1/cicd/pipelines?status=success", headers=auth)
    assert r.status_code == 200
    for p in r.json()["items"]:
        assert p["status"] == "success"


@pytest.mark.anyio
async def test_list_pipelines_filter_repo(client, auth, cicd_data):
    """Filter pipelines by repo."""
    r = await client.get("/api/v1/cicd/pipelines?repo=youruser/cmdb", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


# Stats


@pytest.mark.anyio
async def test_cicd_stats(client, auth, cicd_data):
    """CI/CD stats returns overview."""
    r = await client.get("/api/v1/cicd/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total_repos" in data
    assert "latest_per_repo" in data


# Workers


@pytest.mark.anyio
async def test_workers_report(client, collect_auth):
    """Upsert workers returns ok."""
    r = await client.post(
        "/api/v1/cicd/workers/report",
        json=[
            {
                "ci_system": "woodpecker",
                "external_id": "99",
                "name": "test-agent",
                "hostname": "test-host",
                "status": "connected",
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


@pytest.mark.anyio
async def test_list_workers(client, auth, cicd_data):
    """List workers returns items."""
    r = await client.get("/api/v1/cicd/workers", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


# Servers CRUD


@pytest.mark.anyio
async def test_server_crud(client, auth):
    """Create, list, delete a CI/CD server."""
    # Create
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": "test-ci",
            "url": "https://ci.test.com",
            "server_type": "woodpecker",
            "token": "secret",
        },
        headers=auth,
    )
    assert r.status_code == 200
    server_id = r.json()["id"]

    # List
    r = await client.get("/api/v1/cicd/servers", headers=auth)
    assert r.status_code == 200
    found = [s for s in r.json()["items"] if s["id"] == server_id]
    assert len(found) == 1
    # Token masked
    assert found[0]["token"] == "***"

    # Delete
    r = await client.delete(f"/api/v1/cicd/servers/{server_id}", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_server_invalid_type(client, auth):
    """Invalid server type rejected."""
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": "bad",
            "url": "https://bad.com",
            "server_type": "jenkins",
        },
        headers=auth,
    )
    assert r.status_code == 400
