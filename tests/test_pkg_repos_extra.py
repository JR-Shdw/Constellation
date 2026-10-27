"""Package repositories — filters, validation, version comparison, delete 404."""

import uuid

import pytest

# Version comparison


def test_ver_gt_true():
    """APT version comparison: newer version detected."""
    from api.app.routes.pkg_repositories import _ver_gt

    assert _ver_gt("2.0-1", "1.0-1") is True


def test_ver_gt_false():
    """APT version comparison: same or older."""
    from api.app.routes.pkg_repositories import _ver_gt

    assert _ver_gt("1.0-1", "2.0-1") is False


def test_ver_gt_epoch():
    """APT version with epoch."""
    from api.app.routes.pkg_repositories import _ver_gt

    assert _ver_gt("2:1.0-1", "1:2.0-1") is True


def test_ver_gt_extra_segment_no_hang():
    """Regression: '1.2.0' vs '1.2' used to infinite-loop (worker hang).

    A trailing numeric segment on the longer version must terminate and
    compare greater (dpkg: '.' orders above end-of-string).
    """
    from api.app.routes.pkg_repositories import _ver_gt

    assert _ver_gt("1.2.0", "1.2") is True
    assert _ver_gt("1.2", "1.2.0") is False
    assert _ver_gt("1.10.1", "1.10") is True


def test_ver_gt_tilde_prerelease():
    """'~' sorts before everything: 1.0~rc1 < 1.0."""
    from api.app.routes.pkg_repositories import _ver_gt

    assert _ver_gt("1.0", "1.0~rc1") is True
    assert _ver_gt("1.0~rc1", "1.0") is False


def test_ver_gt_numeric_run_not_lexical():
    """Revisions compared numerically: -10 > -2 (not lexical)."""
    from api.app.routes.pkg_repositories import _ver_gt

    assert _ver_gt("1.0-10", "1.0-2") is True
    assert _ver_gt("1.0-2", "1.0-10") is False


def test_ver_gt_no_revision():
    """Version without debian revision."""
    from api.app.routes.pkg_repositories import _ver_gt

    assert _ver_gt("2.0", "1.0") is True
    assert _ver_gt("1.0", "1.0") is False


# OS family detection extended


def test_detect_os_family_manjaro():
    """Manjaro detected as archlinux."""
    from api.app.routes.pkg_repositories import _detect_os_family

    assert _detect_os_family("Manjaro Linux") == "archlinux"


def test_detect_os_family_centos():
    """CentOS detected."""
    from api.app.routes.pkg_repositories import _detect_os_family

    assert _detect_os_family("CentOS Stream 9") == "centos"


def test_detect_os_family_fedora():
    """Fedora detected."""
    from api.app.routes.pkg_repositories import _detect_os_family

    assert _detect_os_family("Fedora 40") == "fedora"


# List with filters


@pytest.mark.anyio
async def test_list_pkg_repos_filter_os(client, auth):
    """List package repos filtered by os_family."""
    name = f"filt-repo-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": name,
            "os_family": "debian",
            "url": "https://deb.debian.org/debian",
            "distribution": "bookworm",
        },
        headers=auth,
    )
    r = await client.get("/api/v1/pkg-repos?os_family=debian", headers=auth)
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["os_family"] == "debian"


# Create validation


@pytest.mark.anyio
async def test_create_pkg_repo_missing_name(client, auth):
    """Creating repo without name returns 400."""
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "os_family": "debian",
            "url": "https://deb.debian.org/debian",
        },
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_create_pkg_repo_invalid_os(client, auth):
    """Creating repo with invalid os_family returns 400."""
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "bad-os",
            "os_family": "windows",
            "url": "https://example.com",
        },
        headers=auth,
    )
    assert r.status_code == 400


# Patch empty body


@pytest.mark.anyio
async def test_patch_pkg_repo_empty(client, auth):
    """Patch with empty body returns ok/unchanged."""
    name = f"noop-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": name,
            "os_family": "debian",
            "url": "https://deb.debian.org/debian",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]
    r = await client.patch(
        f"/api/v1/pkg-repos/{repo_id}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is False


# Delete not found


@pytest.mark.anyio
async def test_delete_pkg_repo_not_found(client, auth):
    """Delete non-existent package repo returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.delete(f"/api/v1/pkg-repos/{fake_id}", headers=auth)
    assert r.status_code == 404
