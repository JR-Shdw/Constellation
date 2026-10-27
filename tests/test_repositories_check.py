"""Repository check + check-all + list filters with registry mock."""

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
async def repo_id(client, auth):
    """Create a repository and return its ID."""
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": "library/redis",
            "registry": "dockerhub",
            "current_tag": "7.2",
            "listen": "docker_internal",
        },
        headers=auth,
    )
    return r.json()["id"]


@pytest.mark.anyio
async def test_check_repository_update_available(client, auth, repo_id):
    """Check single repo detects update available."""
    with patch(
        "api.app.routes.repositories.resolve_latest",
        new_callable=AsyncMock,
        return_value="7.4",
    ):
        r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data["latest_tag_available"] == "7.4"
        assert data["update_available"] is True


@pytest.mark.anyio
async def test_check_repository_no_update(client, auth, repo_id):
    """Check single repo when already on latest."""
    with patch(
        "api.app.routes.repositories.resolve_latest",
        new_callable=AsyncMock,
        return_value="7.2",
    ):
        r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data["update_available"] is False


@pytest.mark.anyio
async def test_check_repository_resolve_none(client, auth, repo_id):
    """Check repo when registry returns None (unreachable)."""
    with patch(
        "api.app.routes.repositories.resolve_latest",
        new_callable=AsyncMock,
        return_value=None,
    ):
        r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data["update_available"] is False


@pytest.mark.anyio
async def test_check_repository_not_found(client, auth):
    """Check nonexistent repo returns error."""
    import uuid

    r = await client.post(f"/api/v1/repositories/{uuid.uuid4()}/check", headers=auth)
    assert r.status_code == 200
    assert "error" in r.json()


@pytest.mark.anyio
async def test_check_all_repositories(client, auth, repo_id):
    """Check-all updates all repositories."""
    with patch(
        "api.app.routes.repositories.resolve_latest",
        new_callable=AsyncMock,
        return_value="7.4",
    ):
        r = await client.post("/api/v1/repositories/check-all", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["checked"] >= 1


@pytest.mark.anyio
async def test_list_repositories_filter_update_available(client, auth, repo_id):
    """Filter repositories by update_available flag."""
    r = await client.get("/api/v1/repositories?update_available=true", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_list_repositories_filter_listen(client, auth, repo_id):
    """Filter repositories by listen field."""
    r = await client.get("/api/v1/repositories?listen=docker_internal", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_list_repositories_filter_registry(client, auth, repo_id):
    """Filter repositories by registry type."""
    r = await client.get("/api/v1/repositories?registry=dockerhub", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_list_repositories_search(client, auth, repo_id):
    """Search repositories by image name."""
    r = await client.get("/api/v1/repositories?search=redis", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_resolve_latest_unknown_registry():
    """resolve_latest returns None for unknown registry type."""
    from api.app.routes.repositories import resolve_latest

    result = await resolve_latest("test/image", "unknown_registry")
    assert result is None
