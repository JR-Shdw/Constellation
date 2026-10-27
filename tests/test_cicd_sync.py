"""CI/CD sync, server CRUD, trigger coverage."""

import uuid

import pytest


# Sync endpoint

@pytest.mark.anyio
async def test_cicd_sync_no_servers(client, auth):
    """Sync with no configured servers returns empty results."""
    r = await client.post("/api/v1/cicd/sync", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "repos" in data
    assert "pipelines" in data
    assert "workers" in data


# Server CRUD

@pytest.mark.anyio
async def test_add_server(client, auth):
    """Add a CI/CD server."""
    name = f"test-srv-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "url": "https://ci.example.com",
            "server_type": "woodpecker",
            "token": "test-token",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert "id" in r.json()


@pytest.mark.anyio
async def test_add_server_missing_fields(client, auth):
    """Add server without name or URL returns 400."""
    r = await client.post(
        "/api/v1/cicd/servers",
        json={"server_type": "woodpecker"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_add_server_invalid_type(client, auth):
    """Add server with invalid type returns 400."""
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": "bad-type",
            "url": "https://ci.example.com",
            "server_type": "jenkins",
        },
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_add_server_duplicate(client, auth):
    """Add duplicate server name returns 409."""
    name = f"dup-srv-{uuid.uuid4().hex[:8]}"
    payload = {
        "name": name,
        "url": "https://ci.example.com",
        "server_type": "gitea",
        "token": "tok",
    }
    await client.post("/api/v1/cicd/servers", json=payload, headers=auth)
    r = await client.post("/api/v1/cicd/servers", json=payload, headers=auth)
    assert r.status_code == 409


@pytest.mark.anyio
async def test_test_server_not_found(client, auth):
    """Test non-existent server returns 404."""
    fake_id = "00000000-0000-0000-0000-000000000001"
    r = await client.post(f"/api/v1/cicd/servers/{fake_id}/test", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_test_server_unreachable(client, auth):
    """Test server with unreachable URL updates status to error."""
    name = f"unreachable-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "url": "http://127.0.0.1:19999",
            "server_type": "woodpecker",
            "token": "tok",
        },
        headers=auth,
    )
    srv_id = r.json()["id"]
    r = await client.post(f"/api/v1/cicd/servers/{srv_id}/test", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_delete_server(client, auth):
    """Delete a CI/CD server."""
    name = f"del-srv-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "url": "https://ci.example.com",
            "server_type": "gitlab",
            "token": "tok",
        },
        headers=auth,
    )
    srv_id = r.json()["id"]
    r = await client.delete(f"/api/v1/cicd/servers/{srv_id}", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_delete_server_not_found(client, auth):
    """Delete non-existent server returns 404."""
    fake_id = "00000000-0000-0000-0000-000000000002"
    r = await client.delete(f"/api/v1/cicd/servers/{fake_id}", headers=auth)
    assert r.status_code == 404


# Trigger

@pytest.mark.anyio
async def test_trigger_missing_repo(client, auth):
    """Trigger without repo_name returns 400."""
    r = await client.post(
        "/api/v1/cicd/pipelines/trigger",
        json={"ci_system": "woodpecker"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_trigger_no_ci_config(client, auth):
    """Trigger with no CI configured returns 503."""
    r = await client.post(
        "/api/v1/cicd/pipelines/trigger",
        json={"ci_system": "woodpecker", "repo_name": "shdw/test"},
        headers=auth,
    )
    assert r.status_code == 503


# Workers sync

@pytest.mark.anyio
async def test_workers_sync_no_config(client, auth):
    """Workers sync without configured CI returns appropriate response."""
    r = await client.post("/api/v1/cicd/workers/sync", headers=auth)
    assert r.status_code in (200, 503)
