"""Package repositories CRUD + check-updates tests."""

from unittest.mock import AsyncMock, patch

import pytest

from api.app.routes.pkg_repositories import _detect_os_family, _resolve_codename


@pytest.mark.anyio
async def test_create_pkg_repo(client, auth):
    """Create a package repository."""
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "debian-security",
            "os_family": "debian",
            "url": "http://security.debian.org/debian-security",
            "repo_type": "official",
            "description": "Debian security updates",
            "components": "main",
            "distribution": "bookworm-security",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "id" in r.json()


@pytest.mark.anyio
async def test_create_pkg_repo_invalid_os(client, auth):
    """Create with invalid os_family returns 400."""
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "invalid-repo",
            "os_family": "windows",
            "url": "http://example.com",
        },
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_create_pkg_repo_missing_fields(client, auth):
    """Create without name or url returns 400."""
    r = await client.post(
        "/api/v1/pkg-repos",
        json={"os_family": "debian"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_list_pkg_repos(client, auth):
    """List all package repositories."""
    r = await client.get("/api/v1/pkg-repos", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_list_pkg_repos_filter_os(client, auth):
    """List repos filtered by os_family."""
    # Create one first
    await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "arch-core",
            "os_family": "archlinux",
            "url": "https://geo.mirror.pkgbuild.com/core/os/x86_64",
        },
        headers=auth,
    )
    r = await client.get("/api/v1/pkg-repos?os_family=archlinux", headers=auth)
    assert r.status_code == 200
    assert r.json()["items"]


@pytest.mark.anyio
async def test_patch_pkg_repo(client, auth):
    """Update a package repository."""
    cr = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "patch-test-repo",
            "os_family": "ubuntu",
            "url": "http://archive.ubuntu.com/ubuntu",
        },
        headers=auth,
    )
    repo_id = cr.json()["id"]
    r = await client.patch(
        f"/api/v1/pkg-repos/{repo_id}",
        json={"enabled": False, "description": "disabled for testing"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_patch_pkg_repo_empty(client, auth):
    """Patch with no valid fields returns changed=False."""
    cr = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "empty-patch-repo",
            "os_family": "debian",
            "url": "http://example.com",
        },
        headers=auth,
    )
    repo_id = cr.json()["id"]
    r = await client.patch(
        f"/api/v1/pkg-repos/{repo_id}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is False


@pytest.mark.anyio
async def test_delete_pkg_repo(client, auth):
    """Delete a package repository."""
    cr = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "delete-test-repo",
            "os_family": "rocky",
            "url": "http://dl.rockylinux.org/pub/rocky",
        },
        headers=auth,
    )
    repo_id = cr.json()["id"]
    r = await client.delete(f"/api/v1/pkg-repos/{repo_id}", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_delete_pkg_repo_not_found(client, auth):
    """Delete nonexistent repo returns 404."""
    import uuid

    r = await client.delete(f"/api/v1/pkg-repos/{uuid.uuid4()}", headers=auth)
    assert r.status_code == 404


# Helper function unit tests


def test_detect_os_family():
    """OS name → os_family mapping."""
    assert _detect_os_family("debian") == "debian"
    assert _detect_os_family("Debian") == "debian"
    assert _detect_os_family("ubuntu") == "ubuntu"
    assert _detect_os_family("archlinux") == "archlinux"
    assert _detect_os_family("manjaro") == "archlinux"
    assert _detect_os_family("rocky") == "rocky"
    assert _detect_os_family("centos") == "centos"
    assert _detect_os_family("fedora") == "fedora"
    assert _detect_os_family("windows") is None
    assert _detect_os_family("") is None


def test_resolve_codename():
    """OS version → APT codename mapping."""
    assert _resolve_codename("debian", "12") == "bookworm"
    assert _resolve_codename("debian", "12.6") == "bookworm"
    assert _resolve_codename("debian", "13") == "trixie"
    assert _resolve_codename("ubuntu", "24.04") == "noble"
    assert _resolve_codename("ubuntu", "22.04") == "jammy"
    assert _resolve_codename("archlinux", "rolling") is None
    assert _resolve_codename("debian", None) is None
    assert _resolve_codename("debian", "99") is None


# Check-updates endpoint test (mocked fetches)


@pytest.mark.anyio
async def test_check_updates_groups_and_matches(client, auth, collect_auth):
    """check-updates resolves OS/arch/codename and updates available_ver."""
    # 1. Create a node with packages
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "check-upd-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0-20-amd64",
            "packages": ["curl\t7.88.1-10\tamd64", "wget\t1.21.3-1\tamd64"],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200

    # 2. Create a matching repo (TRUNCATE clears seeded data)
    await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "debian-bookworm-test",
            "os_family": "debian",
            "url": "https://deb.debian.org/debian",
            "repo_type": "official",
            "distribution": "bookworm",
            "components": "main",
        },
        headers=auth,
    )

    # 3. Mock fetch to return known versions
    mock_apt = AsyncMock(
        return_value={"curl": "7.88.1-11", "wget": "1.21.3-1", "nano": "7.2-1"}
    )
    with patch("api.app.routes.pkg_repositories._fetch_apt_packages", mock_apt):
        r = await client.post("/api/v1/pkg-repos/check-updates", headers=auth)

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["packages_updated"] >= 1  # curl got updated
    assert data["groups"]
    # Should have resolved codename bookworm and arch amd64
    # Filter on codename to avoid matching other debian nodes (no os_version)
    deb_grp = [
        g for g in data["groups"] if g["os"] == "debian" and g["codename"] == "bookworm"
    ]
    assert deb_grp, f"No debian/bookworm group found in {data['groups']}"
    assert deb_grp[0]["arch"] == "x86_64"

    # 4. Check the mock was called with correct arch (amd64 for x86_64)
    for call_args in mock_apt.call_args_list:
        assert call_args[0][3] == "amd64"  # 4th positional arg = arch
