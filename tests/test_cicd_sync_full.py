"""cicd/sync.py — full sync path with mocked forge and CI connectors.

The default test_cicd_sync.py only hits the no-servers branch. This
file exercises the forge loop (list_repos → get_branches → has_ci_config
→ repos_report) and the CI loop (list_repos → list_pipelines →
list_runners → pipelines_report + workers_report) so the full sync
isn't just 30% covered.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


async def _add_server(client, auth, server_type: str) -> str:
    name = f"sync-{server_type}-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "url": "https://fake.example.com",
            "server_type": server_type,
            "token": "tok",
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    # Default status is 'unknown' which passes `status != 'offline'`.
    return r.json()["id"]


@pytest.mark.anyio
async def test_sync_gitea_forge_upserts_repos(client, auth):
    await _add_server(client, auth, "gitea")

    fake_forge = MagicMock()
    fake_forge.list_repos = AsyncMock(
        return_value=[
            {
                "name": "youruser/cmdb",
                "owner": "testuser",
                "description": "constellation",
                "default_branch": "main",
                "url": "https://gitea.example/youruser/cmdb",
                "private": False,
                "language": "Python",
                "topics": ["caasm"],
                "stars": 1,
            }
        ]
    )
    fake_forge.get_branches = AsyncMock(return_value=["main", "dev"])
    fake_forge.has_ci_config = AsyncMock(return_value=True)

    with patch("api.app.routes.cicd.sync.get_forge", return_value=fake_forge):
        r = await client.post("/api/v1/cicd/sync", headers=auth)

    assert r.status_code == 200, r.text
    data = r.json()
    assert data["repos"] >= 1
    assert data["errors"] == []
    fake_forge.list_repos.assert_awaited_once()
    fake_forge.get_branches.assert_awaited()
    fake_forge.has_ci_config.assert_awaited()


@pytest.mark.anyio
async def test_sync_forge_branches_errors_are_swallowed(client, auth):
    """get_branches / has_ci_config exceptions must not abort the forge sync."""
    await _add_server(client, auth, "forgejo")

    fake_forge = MagicMock()
    fake_forge.list_repos = AsyncMock(
        return_value=[
            {
                "name": "ops/infra",
                "owner": "ops",
                "default_branch": "main",
                "url": "https://forgejo.example/ops/infra",
            }
        ]
    )
    fake_forge.get_branches = AsyncMock(side_effect=RuntimeError("502"))
    fake_forge.has_ci_config = AsyncMock(side_effect=RuntimeError("403"))

    with patch("api.app.routes.cicd.sync.get_forge", return_value=fake_forge):
        r = await client.post("/api/v1/cicd/sync", headers=auth)

    assert r.status_code == 200
    assert r.json()["errors"] == []


@pytest.mark.anyio
async def test_sync_forge_list_failure_is_recorded(client, auth):
    """forge.list_repos raising is captured in results['errors']."""
    await _add_server(client, auth, "gitea")

    fake_forge = MagicMock()
    fake_forge.list_repos = AsyncMock(side_effect=RuntimeError("DNS"))

    with patch("api.app.routes.cicd.sync.get_forge", return_value=fake_forge):
        r = await client.post("/api/v1/cicd/sync", headers=auth)

    data = r.json()
    assert any("forge:gitea" in e for e in data["errors"])


@pytest.mark.anyio
async def test_sync_woodpecker_pipelines_and_workers(client, auth):
    """CI loop: list_repos → list_pipelines → pipelines_report +
    list_runners → workers_report."""
    await _add_server(client, auth, "woodpecker")

    # Seed a node so workers_report can resolve hostname.
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('wood-runner-01', 'vm', 'debian', '12', 'amd64')
            """
        )
    finally:
        await conn.close()

    fake_ci = MagicMock()
    fake_ci.list_repos = AsyncMock(return_value=[{"id": 1, "full_name": "youruser/cmdb"}])
    fake_ci.list_pipelines = AsyncMock(
        return_value=[
            {
                "number": 42,
                "status": "success",
                "event": "push",
                "branch": "main",
                "commit_sha": "a" * 40,
                "author": "testuser",
                "duration_secs": 30,
            }
        ]
    )
    fake_ci.list_runners = AsyncMock(
        return_value=[
            {
                "external_id": "99",
                "name": "runner-1",
                "labels": {"host": "wood-runner-01"},
                "platform": "linux/amd64",
                "capacity": 4,
            }
        ]
    )

    with patch("api.app.routes.cicd.sync.get_ci", return_value=fake_ci):
        r = await client.post("/api/v1/cicd/sync", headers=auth)

    assert r.status_code == 200, r.text
    data = r.json()
    assert data["pipelines"] >= 1
    assert data["workers"] >= 1
    assert data["errors"] == []


@pytest.mark.anyio
async def test_sync_ci_list_pipelines_error_swallowed(client, auth):
    """Per-repo list_pipelines failure must not stop the CI sync."""
    await _add_server(client, auth, "gitlab")

    fake_ci = MagicMock()
    fake_ci.list_repos = AsyncMock(
        return_value=[
            {"id": 1, "full_name": "a/b"},
            {"id": 2, "full_name": "c/d"},
        ]
    )

    async def _list_pipes(repo_id, limit=50):
        if repo_id == 1:
            raise RuntimeError("rate limit")
        return [
            {
                "number": 1,
                "status": "failure",
                "event": "push",
                "branch": "main",
                "commit_sha": "b" * 40,
                "author": "x",
                "duration_secs": 10,
            }
        ]

    fake_ci.list_pipelines = AsyncMock(side_effect=_list_pipes)
    fake_ci.list_runners = AsyncMock(return_value=[])

    with patch("api.app.routes.cicd.sync.get_ci", return_value=fake_ci):
        r = await client.post("/api/v1/cicd/sync", headers=auth)

    assert r.status_code == 200
    assert r.json()["pipelines"] >= 1


@pytest.mark.anyio
async def test_sync_ci_list_runners_error_recorded_but_continues(client, auth):
    """list_runners failing logs a warning but sync_all keeps going."""
    await _add_server(client, auth, "woodpecker")

    fake_ci = MagicMock()
    fake_ci.list_repos = AsyncMock(return_value=[])
    fake_ci.list_pipelines = AsyncMock(return_value=[])
    fake_ci.list_runners = AsyncMock(side_effect=RuntimeError("boom"))

    with patch("api.app.routes.cicd.sync.get_ci", return_value=fake_ci):
        r = await client.post("/api/v1/cicd/sync", headers=auth)

    # Workers failure does NOT append to errors (only the outer CI try does).
    # The call must still succeed.
    assert r.status_code == 200


@pytest.mark.anyio
async def test_sync_ci_outer_failure_records_error(client, auth):
    """get_ci raising before iteration → results['errors'] has ci:gitlab."""
    await _add_server(client, auth, "gitlab")

    with patch(
        "api.app.routes.cicd.sync.get_ci",
        side_effect=RuntimeError("connector init"),
    ):
        r = await client.post("/api/v1/cicd/sync", headers=auth)

    data = r.json()
    assert any("ci:gitlab" in e for e in data["errors"])


@pytest.mark.anyio
async def test_sync_uses_env_settings_when_no_db_server(client, auth):
    """Fallback path : no cicd_servers row → settings.gitea_url/token used."""

    fake_forge = MagicMock()
    fake_forge.list_repos = AsyncMock(return_value=[])
    fake_forge.get_branches = AsyncMock(return_value=[])
    fake_forge.has_ci_config = AsyncMock(return_value=False)

    with (
        patch("api.app.routes.cicd.sync.app_settings") as mock_settings,
        patch("api.app.routes.cicd.sync.get_forge", return_value=fake_forge),
    ):
        mock_settings.gitea_url = "https://env.gitea"
        mock_settings.gitea_token = "env-token"
        mock_settings.forgejo_url = ""
        mock_settings.forgejo_token = ""
        mock_settings.woodpecker_url = ""
        mock_settings.woodpecker_token = ""
        mock_settings.gitlab_url = ""
        mock_settings.gitlab_token = ""

        r = await client.post("/api/v1/cicd/sync", headers=auth)

    assert r.status_code == 200
    fake_forge.list_repos.assert_awaited_once()
