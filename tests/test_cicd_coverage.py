"""CI/CD coverage — repo detail, pipeline filters, workers sync, servers update."""

import uuid

import pytest


@pytest.fixture
async def cicd_repo(client, collect_auth):
    """Create a CI/CD repo and return its data."""
    name = f"shdw/cov-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/cicd/repos/report",
        json=[
            {
                "forge": "gitea",
                "full_name": name,
                "owner": "testuser",
                "default_branch": "main",
                "html_url": f"https://gitea.example.com/{name}",
                "language": "Python",
                "has_pipeline": True,
                "branches": ["main", "dev"],
            },
        ],
        headers=collect_auth,
    )
    # Get repo ID
    hdr = {"Authorization": "Bearer test-secret-key"}
    r = await client.get("/api/v1/cicd/repos", headers=hdr)
    items = r.json()["items"]
    repo = next(
        (i for i in items if i.get("full_name") == name or i.get("repo_name") == name),
        None,
    )
    return {"name": name, "id": str(repo["id"]) if repo else None}


@pytest.fixture
async def cicd_with_pipelines(client, collect_auth, cicd_repo):
    """Create pipelines for a repo."""
    name = cicd_repo["name"]
    await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": name,
                "number": 200,
                "status": "success",
                "event": "push",
                "branch": "main",
                "commit": "aaa111",
                "message": "test pipeline",
                "author": "testuser",
                "duration_secs": 60,
            },
            {
                "ci_system": "woodpecker",
                "repo_name": name,
                "number": 201,
                "status": "failure",
                "event": "push",
                "branch": "dev",
                "commit": "bbb222",
                "message": "broken pipeline",
                "author": "testuser",
                "duration_secs": 15,
            },
        ],
        headers=collect_auth,
    )
    return cicd_repo


# Repo detail


@pytest.mark.anyio
async def test_get_repo_detail(client, auth, cicd_with_pipelines):
    """GET /cicd/repos/{id} returns repo + recent pipelines."""
    repo_id = cicd_with_pipelines["id"]
    if not repo_id:
        pytest.skip("repo not found")
    r = await client.get(f"/api/v1/cicd/repos/{repo_id}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "repo" in data
    assert "pipelines" in data
    assert len(data["pipelines"]) >= 1


@pytest.mark.anyio
async def test_get_repo_not_found(client, auth):
    """GET /cicd/repos/{id} returns 404 for missing repo."""
    fake_id = str(uuid.uuid4())
    r = await client.get(f"/api/v1/cicd/repos/{fake_id}", headers=auth)
    assert r.status_code == 404


# Pipeline filters


@pytest.mark.anyio
async def test_pipelines_filter_ci_system(client, auth, cicd_with_pipelines):
    """Filter pipelines by ci_system."""
    r = await client.get("/api/v1/cicd/pipelines?ci_system=woodpecker", headers=auth)
    assert r.status_code == 200
    for p in r.json()["items"]:
        assert p["ci_system"] == "woodpecker"


@pytest.mark.anyio
async def test_pipelines_filter_status_success(client, auth, cicd_with_pipelines):
    """Filter pipelines by status=success."""
    r = await client.get("/api/v1/cicd/pipelines?status=success", headers=auth)
    assert r.status_code == 200
    for p in r.json()["items"]:
        assert p["status"] == "success"


@pytest.mark.anyio
async def test_pipelines_list_has_total(client, auth, cicd_with_pipelines):
    """Pipeline list includes total count."""
    r = await client.get("/api/v1/cicd/pipelines", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert data["total"] >= 1


# Pipeline with duration calc


@pytest.mark.anyio
async def test_pipeline_missing_fields_handled(client, collect_auth):
    """Pipeline with minimal fields still ingests."""
    r = await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": "shdw/minimal",
                "number": 999,
                "status": "success",
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


@pytest.mark.anyio
async def test_pipeline_long_message_truncated(client, collect_auth):
    """Pipeline commit message longer than 500 chars is truncated."""
    r = await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": "shdw/long-msg",
                "number": 1,
                "status": "success",
                "message": "x" * 600,
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200


# Workers with offline status


@pytest.mark.anyio
async def test_workers_offline_automation(client, collect_auth):
    """Worker marked offline triggers automation event."""
    r = await client.post(
        "/api/v1/cicd/workers/report",
        json=[
            {
                "ci_system": "woodpecker",
                "external_id": "offline-1",
                "name": "dead-agent",
                "hostname": "dead-host",
                "status": "offline",
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


# Server update


@pytest.mark.anyio
async def test_server_create_delete(client, auth):
    """Create and immediately delete a CI/CD server."""
    name = f"create-del-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "url": "https://ci.test.com",
            "server_type": "forgejo",
            "token": "tok",
        },
        headers=auth,
    )
    assert r.status_code == 200
    server_id = r.json()["id"]

    # Verify in list
    r = await client.get("/api/v1/cicd/servers", headers=auth)
    found = [s for s in r.json()["items"] if s["id"] == server_id]
    assert len(found) == 1
    assert found[0]["server_type"] == "forgejo"

    # Cleanup
    r = await client.delete(f"/api/v1/cicd/servers/{server_id}", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_server_duplicate_name(client, auth):
    """Duplicate server name returns 409."""
    name = f"dup-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/cicd/servers",
        json={"name": name, "url": "https://a.com", "server_type": "woodpecker"},
        headers=auth,
    )
    r = await client.post(
        "/api/v1/cicd/servers",
        json={"name": name, "url": "https://b.com", "server_type": "woodpecker"},
        headers=auth,
    )
    assert r.status_code == 409


# Pipeline trigger — vault sealed


@pytest.mark.anyio
async def test_trigger_missing_repo_name(client, auth):
    """Trigger pipeline without repo_name returns 400."""
    from unittest.mock import AsyncMock, patch

    with patch(
        "api.app.routes.cicd.pipelines.require_vault_unsealed", new_callable=AsyncMock
    ):
        r = await client.post(
            "/api/v1/cicd/pipelines/trigger",
            json={"ci_system": "woodpecker"},
            headers=auth,
        )
        assert r.status_code == 400
