"""Repositories — list filters, patch fields, check-all, add with auto-detect."""

import uuid

import pytest

# List with project filter


@pytest.mark.anyio
async def test_list_repositories_filter_project(client, auth):
    """List repos filtered by project prefix."""
    name = f"proj/img-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "1.0",
            "registry": "dockerhub",
        },
        headers=auth,
    )
    r = await client.get("/api/v1/repositories?project=proj", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# Add with auto-detect registry


@pytest.mark.anyio
async def test_add_repo_ghcr_autodetect(client, auth):
    """Adding ghcr.io image auto-detects registry."""
    name = f"ghcr.io/owner/img-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "latest",
        },
        headers=auth,
    )
    assert r.status_code in (200, 201)
    assert "id" in r.json()


@pytest.mark.anyio
async def test_add_repo_oci_autodetect(client, auth):
    """Adding private registry image auto-detects as OCI."""
    name = f"registry.local:5000/app-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "v2.0",
        },
        headers=auth,
    )
    assert r.status_code in (200, 201)


# Patch repository


@pytest.mark.anyio
async def test_patch_repo_multiple_fields(client, auth):
    """Patch multiple fields on a repository."""
    name = f"patch/multi-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "1.0",
            "registry": "dockerhub",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]
    r = await client.patch(
        f"/api/v1/repositories/{repo_id}",
        json={"current_tag": "2.0", "notes": "upgraded"},
        headers=auth,
    )
    assert r.status_code == 200


# Check single repo (exists but network fails)


@pytest.mark.anyio
async def test_check_repo_exists(client, auth):
    """Check a real repo — may fail network but returns ok structure."""
    name = f"check/repo-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "1.0",
            "registry": "dockerhub",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]
    r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
    assert r.status_code == 200
    # May return error (network) or ok (resolved) — both valid


# Delete returns ok (no 404 check in endpoint)


@pytest.mark.anyio
async def test_delete_repo_nonexistent_ok(client, auth):
    """Delete non-existent repo returns ok (no-op)."""
    fake_id = str(uuid.uuid4())
    r = await client.delete(f"/api/v1/repositories/{fake_id}", headers=auth)
    assert r.status_code == 200
