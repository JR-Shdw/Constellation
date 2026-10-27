"""CI/CD deep coverage — server test, pipeline automation, workers sync."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest

# Server test connection


@pytest.mark.anyio
async def test_server_test_connection(client, auth):
    """Test connection to a CI/CD server (mocked)."""
    # Create a server
    name = f"test-conn-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "url": "https://ci.test.com",
            "server_type": "woodpecker",
            "token": "test-token",
        },
        headers=auth,
    )
    server_id = r.json()["id"]

    # Mock the CI connector
    mock_ci = AsyncMock()
    mock_ci.test_connection = AsyncMock(
        return_value={"username": "testuser", "status": "connected"}
    )

    with patch("api.app.routes.cicd.servers.get_ci", return_value=mock_ci):
        r = await client.post(
            f"/api/v1/cicd/servers/{server_id}/test",
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "connected"
        assert "testuser" in data["detail"]

    # Cleanup
    await client.delete(f"/api/v1/cicd/servers/{server_id}", headers=auth)


@pytest.mark.anyio
async def test_server_test_not_found(client, auth):
    """Test connection for non-existent server returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.post(f"/api/v1/cicd/servers/{fake_id}/test", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_server_test_connection_error(client, auth):
    """Test connection returns error on failure."""
    name = f"fail-conn-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "url": "https://ci.unreachable.com",
            "server_type": "gitea",
            "token": "tok",
        },
        headers=auth,
    )
    server_id = r.json()["id"]

    mock_forge = AsyncMock()
    mock_forge.test_connection = AsyncMock(side_effect=Exception("Connection refused"))

    with patch("api.app.routes.cicd.servers.get_forge", return_value=mock_forge):
        r = await client.post(
            f"/api/v1/cicd/servers/{server_id}/test",
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "error"

    await client.delete(f"/api/v1/cicd/servers/{server_id}", headers=auth)


# Pipeline report with automation trigger


@pytest.mark.anyio
async def test_pipeline_failure_triggers_automation(client, collect_auth):
    """Pipeline with status=failure triggers automation event."""
    r = await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": "shdw/fail-test",
                "number": 500,
                "status": "failure",
                "event": "push",
                "branch": "main",
                "commit": "deadbeef",
                "message": "broken build",
                "author": "testuser",
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


# Workers sync — mocked


@pytest.mark.anyio
async def test_workers_sync_not_configured(client, auth):
    """Workers sync returns 503 when CI not configured."""
    r = await client.post(
        "/api/v1/cicd/workers/sync?ci_system=woodpecker",
        headers=auth,
    )
    assert r.status_code == 503


# Server delete not found


@pytest.mark.anyio
async def test_server_delete_not_found(client, auth):
    """Delete non-existent server returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.delete(f"/api/v1/cicd/servers/{fake_id}", headers=auth)
    assert r.status_code == 404


# Repos filter by forge


@pytest.mark.anyio
async def test_repos_report_gitlab(client, collect_auth, auth):
    """Ingest a gitlab repo and verify it appears in list."""
    name = f"shdw/gl-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/cicd/repos/report",
        json=[
            {
                "forge": "gitlab",
                "full_name": name,
                "owner": "testuser",
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1

    # Verify in list
    r = await client.get("/api/v1/cicd/repos", headers=auth)
    found = any(
        r.get("full_name") == name or r.get("repo_name") == name
        for r in r.json()["items"]
    )
    assert found
