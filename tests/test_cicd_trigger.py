"""CI/CD — trigger pipeline, sync workers, _resolve_ci_credentials."""

from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.anyio
async def test_trigger_pipeline_no_repo(client, auth):
    """Trigger pipeline without repo_name returns 400."""
    r = await client.post(
        "/api/v1/cicd/pipelines/trigger",
        json={"ci_system": "woodpecker", "repo_name": ""},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_trigger_pipeline_not_configured(client, auth):
    """Trigger pipeline when CI not configured returns 503."""
    r = await client.post(
        "/api/v1/cicd/pipelines/trigger",
        json={"ci_system": "woodpecker", "repo_name": "youruser/cmdb"},
        headers=auth,
    )
    assert r.status_code == 503


@pytest.mark.anyio
async def test_trigger_pipeline_woodpecker_success(client, auth):
    """Trigger Woodpecker pipeline success with mocked CI."""
    mock_repos = [
        {"id": 42, "full_name": "youruser/cmdb"},
        {"id": 99, "full_name": "shdw/other"},
    ]
    mock_result = {"number": 123}

    with (
        patch(
            "api.app.routes.cicd.pipelines._resolve_ci_credentials",
            new_callable=AsyncMock,
            return_value=("http://ci.test", "token123"),
        ),
        patch("api.app.routes.cicd.pipelines.get_ci") as mock_get_ci,
        patch(
            "api.app.routes.cicd.pipelines.require_vault_unsealed",
            new_callable=AsyncMock,
        ),
    ):
        mock_ci = AsyncMock()
        mock_ci.list_repos = AsyncMock(return_value=mock_repos)
        mock_ci.trigger_pipeline = AsyncMock(return_value=mock_result)
        mock_get_ci.return_value = mock_ci

        r = await client.post(
            "/api/v1/cicd/pipelines/trigger",
            json={
                "ci_system": "woodpecker",
                "repo_name": "youruser/cmdb",
                "branch": "main",
            },
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["pipeline_number"] == 123
        assert data["repo_name"] == "youruser/cmdb"


@pytest.mark.anyio
async def test_trigger_pipeline_repo_not_found(client, auth):
    """Trigger pipeline on nonexistent repo returns 404."""
    with (
        patch(
            "api.app.routes.cicd.pipelines._resolve_ci_credentials",
            new_callable=AsyncMock,
            return_value=("http://ci.test", "token123"),
        ),
        patch("api.app.routes.cicd.pipelines.get_ci") as mock_get_ci,
        patch(
            "api.app.routes.cicd.pipelines.require_vault_unsealed",
            new_callable=AsyncMock,
        ),
    ):
        mock_ci = AsyncMock()
        mock_ci.list_repos = AsyncMock(return_value=[])
        mock_get_ci.return_value = mock_ci

        r = await client.post(
            "/api/v1/cicd/pipelines/trigger",
            json={"ci_system": "woodpecker", "repo_name": "shdw/nonexist"},
            headers=auth,
        )
        assert r.status_code == 404


@pytest.mark.anyio
async def test_trigger_pipeline_gitlab(client, auth):
    """Trigger GitLab pipeline uses project path as repo_id."""
    mock_result = {"number": 456}

    with (
        patch(
            "api.app.routes.cicd.pipelines._resolve_ci_credentials",
            new_callable=AsyncMock,
            return_value=("http://gitlab.test", "glpat-token"),
        ),
        patch("api.app.routes.cicd.pipelines.get_ci") as mock_get_ci,
        patch(
            "api.app.routes.cicd.pipelines.require_vault_unsealed",
            new_callable=AsyncMock,
        ),
    ):
        mock_ci = AsyncMock()
        mock_ci.trigger_pipeline = AsyncMock(return_value=mock_result)
        mock_get_ci.return_value = mock_ci

        r = await client.post(
            "/api/v1/cicd/pipelines/trigger",
            json={
                "ci_system": "gitlab",
                "repo_name": "shdw/infra",
                "branch": "main",
                "variables": {"DEPLOY": "true"},
            },
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"


@pytest.mark.anyio
async def test_sync_workers_not_configured(client, auth):
    """Sync workers when CI not configured returns 503."""
    r = await client.post(
        "/api/v1/cicd/workers/sync?ci_system=woodpecker", headers=auth
    )
    assert r.status_code == 503


@pytest.mark.anyio
async def test_sync_workers_success(client, auth):
    """Sync workers with mocked CI returns workers."""
    mock_runners = [
        {
            "external_id": "1",
            "name": "runner-1",
            "platform": "linux/amd64",
            "labels": {"host": "host-b"},
            "capacity": 2,
            "status": "connected",
        },
    ]

    with (
        patch(
            "api.app.routes.cicd.workers._resolve_ci_credentials",
            new_callable=AsyncMock,
            return_value=("http://ci.test", "token123"),
        ),
        patch("api.app.routes.cicd.workers.get_ci") as mock_get_ci,
    ):
        mock_ci = AsyncMock()
        mock_ci.list_runners = AsyncMock(return_value=mock_runners)
        mock_get_ci.return_value = mock_ci

        r = await client.post(
            "/api/v1/cicd/workers/sync?ci_system=woodpecker", headers=auth
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["upserted"] >= 1


@pytest.mark.anyio
async def test_sync_workers_invalid_ci_system(client, auth):
    """Sync workers with invalid CI system type returns 400."""
    with patch(
        "api.app.routes.cicd.workers._resolve_ci_credentials",
        new_callable=AsyncMock,
        return_value=("http://ci.test", "token123"),
    ):
        r = await client.post(
            "/api/v1/cicd/workers/sync?ci_system=jenkins", headers=auth
        )
        assert r.status_code == 400


@pytest.mark.anyio
async def test_sync_workers_api_error(client, auth):
    """Sync workers handles CI API errors."""
    with (
        patch(
            "api.app.routes.cicd.workers._resolve_ci_credentials",
            new_callable=AsyncMock,
            return_value=("http://ci.test", "token123"),
        ),
        patch("api.app.routes.cicd.workers.get_ci") as mock_get_ci,
    ):
        mock_ci = AsyncMock()
        mock_ci.list_runners = AsyncMock(side_effect=Exception("API unreachable"))
        mock_get_ci.return_value = mock_ci

        r = await client.post(
            "/api/v1/cicd/workers/sync?ci_system=woodpecker", headers=auth
        )
        assert r.status_code == 502
