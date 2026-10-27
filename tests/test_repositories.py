"""Repository CRUD tests — create, list, patch, delete."""

import pytest


@pytest.mark.anyio
async def test_create_repository(client, auth):
    """Create a repository entry."""
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": "library/nginx",
            "registry": "dockerhub",
            "current_tag": "1.25",
            "listen": "internet",
        },
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "id" in data


@pytest.mark.anyio
async def test_list_repositories(client, auth):
    """List repositories returns paginated results."""
    r = await client.get("/api/v1/repositories", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data


@pytest.mark.anyio
async def test_list_repositories_filter_project(client, auth):
    """List repositories with project filter."""
    # Create one first
    await client.post(
        "/api/v1/repositories",
        json={"image_name": "myproject/api", "current_tag": "v2"},
        headers=auth,
    )
    r = await client.get("/api/v1/repositories?project=myproject", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_patch_repository(client, auth):
    """Patch repository listen field."""
    cr = await client.post(
        "/api/v1/repositories",
        json={"image_name": "patchtest/app", "current_tag": "latest"},
        headers=auth,
    )
    repo_id = cr.json()["id"]
    r = await client.patch(
        f"/api/v1/repositories/{repo_id}",
        json={"listen": "private_network"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_patch_repository_empty(client, auth):
    """Patch with no fields returns error."""
    cr = await client.post(
        "/api/v1/repositories",
        json={"image_name": "emptytest/app", "current_tag": "latest"},
        headers=auth,
    )
    repo_id = cr.json()["id"]
    r = await client.patch(
        f"/api/v1/repositories/{repo_id}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert "error" in r.json()


@pytest.mark.anyio
async def test_delete_repository(client, auth):
    """Delete a repository entry."""
    cr = await client.post(
        "/api/v1/repositories",
        json={"image_name": "deltest/app", "current_tag": "v1"},
        headers=auth,
    )
    repo_id = cr.json()["id"]
    r = await client.delete(f"/api/v1/repositories/{repo_id}", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_repository_report(client, collect_auth):
    """Ingest repository data via collect endpoint."""
    # Create a node first
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "repo-report-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    r = await client.post(
        "/api/v1/repositories/report",
        json={
            "hostname": "repo-report-node",
            "images": [
                {
                    "image_name": "library/postgres",
                    "registry": "dockerhub",
                    "current_tag": "17-bookworm",
                    "listen": "docker_internal",
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] == 1
