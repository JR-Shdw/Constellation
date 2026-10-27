"""Package repositories — CRUD, codename resolution, check-updates."""

import uuid

import pytest

# OS family detection

def test_safe_gunzip_caps_decompression():
    """_safe_gunzip decompresses normally but refuses a bomb past the cap."""
    import gzip as _gz

    from api.app.routes.pkg_repositories import _safe_gunzip

    blob = _gz.compress(b"A" * 10000)  # tiny compressed, 10k decompressed
    assert _safe_gunzip(blob) == "A" * 10000
    with pytest.raises(ValueError):
        _safe_gunzip(blob, cap=100)


def test_detect_os_family():
    """OS family detection from OS string."""
    from api.app.routes.pkg_repositories import _detect_os_family
    assert _detect_os_family("Debian GNU/Linux 12") == "debian"
    assert _detect_os_family("Ubuntu 22.04") == "ubuntu"
    assert _detect_os_family("Arch Linux") == "archlinux"
    assert _detect_os_family("Rocky Linux 9") == "rocky"
    assert _detect_os_family("Windows 11") is None


def test_resolve_codename_debian():
    """Codename resolution for Debian versions."""
    from api.app.routes.pkg_repositories import _resolve_codename
    assert _resolve_codename("debian", "12") == "bookworm"
    assert _resolve_codename("debian", "11") == "bullseye"


def test_resolve_codename_ubuntu():
    """Codename resolution for Ubuntu versions."""
    from api.app.routes.pkg_repositories import _resolve_codename
    assert _resolve_codename("ubuntu", "22.04") == "jammy"
    assert _resolve_codename("ubuntu", "24.04") == "noble"


def test_resolve_codename_unknown():
    """Unknown OS returns None."""
    from api.app.routes.pkg_repositories import _resolve_codename
    assert _resolve_codename("archlinux", "rolling") is None


# CRUD

@pytest.mark.anyio
async def test_list_pkg_repos(client, auth):
    """List package repositories."""
    r = await client.get("/api/v1/pkg-repos", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_add_pkg_repo(client, auth):
    """Add a package repository."""
    name = f"test-repo-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": name,
            "os_family": "debian",
            "url": "https://deb.debian.org/debian",
            "distribution": "bookworm",
            "components": "main",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert "id" in r.json()


@pytest.mark.anyio
async def test_patch_pkg_repo(client, auth):
    """Patch a package repository."""
    name = f"edit-repo-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": name,
            "os_family": "debian",
            "url": "https://deb.debian.org/debian",
            "distribution": "bookworm",
            "components": "main",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]
    r = await client.patch(
        f"/api/v1/pkg-repos/{repo_id}",
        json={"components": "main contrib"},
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_delete_pkg_repo(client, auth):
    """Delete a package repository."""
    name = f"del-repo-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": name,
            "os_family": "debian",
            "url": "https://deb.debian.org/debian",
            "distribution": "bookworm",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]
    r = await client.delete(f"/api/v1/pkg-repos/{repo_id}", headers=auth)
    assert r.status_code == 200


# Check updates

@pytest.mark.anyio
async def test_check_updates_empty(client, auth):
    """Check updates with no nodes."""
    r = await client.post("/api/v1/pkg-repos/check-updates", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["packages_updated"] == 0


# _fetch_apt_packages — direct httpx mock

class _AptResp:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content


class _AptClient:
    def __init__(self, responses):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        return self._responses.pop(0)


@pytest.mark.anyio
async def test_fetch_apt_packages_parses_gzip(monkeypatch):
    """Packages.gz content is gzipped, parsed into {name: version}."""
    import gzip as _gzip

    from api.app.routes import pkg_repositories

    body = (
        b"Package: curl\n"
        b"Version: 7.88.1-11\n"
        b"\n"
        b"Package: wget\n"
        b"Version: 1.21.3-1\n"
    )
    packed = _gzip.compress(body)
    client = _AptClient([_AptResp(200, packed)])
    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: client
    )
    out = await pkg_repositories._fetch_apt_packages(
        "https://mirror.example", "bookworm", "main", "amd64"
    )
    assert out == {"curl": "7.88.1-11", "wget": "1.21.3-1"}


@pytest.mark.anyio
async def test_fetch_apt_packages_keeps_higher_version(monkeypatch):
    """When the same package appears twice, the higher version wins."""
    import gzip as _gzip

    from api.app.routes import pkg_repositories

    body = (
        b"Package: curl\n"
        b"Version: 7.88.1-1\n"
        b"\n"
        b"Package: curl\n"
        b"Version: 7.88.1-2\n"
    )
    client = _AptClient([_AptResp(200, _gzip.compress(body))])
    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: client
    )
    out = await pkg_repositories._fetch_apt_packages(
        "https://m.example", "bookworm", "main", "amd64"
    )
    assert out["curl"] == "7.88.1-2"


@pytest.mark.anyio
async def test_fetch_apt_packages_dedup_uses_dpkg_order(monkeypatch):
    """Multi-version dedup uses dpkg order, not lexical: 1.10 > 1.9.

    Regression: the old `ver > pkgs[name]` string compare kept 1.9.0-1
    (lexically '1.10' < '1.9'), advertising an older version as available.
    """
    import gzip as _gzip

    from api.app.routes import pkg_repositories

    body = (
        b"Package: nginx\n"
        b"Version: 1.9.0-1\n"
        b"\n"
        b"Package: nginx\n"
        b"Version: 1.10.0-1\n"
    )
    client = _AptClient([_AptResp(200, _gzip.compress(body))])
    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: client
    )
    out = await pkg_repositories._fetch_apt_packages(
        "https://m.example", "bookworm", "main", "amd64"
    )
    assert out["nginx"] == "1.10.0-1"


@pytest.mark.anyio
async def test_fetch_apt_packages_non_200_returns_empty(monkeypatch):
    """404 on Packages.gz → empty dict, no crash."""
    from api.app.routes import pkg_repositories

    client = _AptClient([_AptResp(404, b"")])
    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: client
    )
    out = await pkg_repositories._fetch_apt_packages(
        "https://m.example", "bookworm", "main", "amd64"
    )
    assert out == {}


@pytest.mark.anyio
async def test_fetch_apt_packages_exception_swallowed(monkeypatch):
    """httpx/gzip error during fetch logged and returns empty."""
    from api.app.routes import pkg_repositories

    class _Boom:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            raise RuntimeError("connection reset")

    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: _Boom()
    )
    out = await pkg_repositories._fetch_apt_packages(
        "https://m.example", "bookworm", "main", "amd64"
    )
    assert out == {}


# _fetch_pacman_db — build a real minimal tar.gz

def _build_pacman_tar(entries: list[tuple[str, str]]) -> bytes:
    """Build an in-memory .db tar archive with `<pkg>-<ver>/desc` members."""
    import io as _io
    import tarfile as _tf

    buf = _io.BytesIO()
    with _tf.open(fileobj=buf, mode="w") as tar:
        for name, ver in entries:
            body = f"%NAME%\n{name}\n%VERSION%\n{ver}\n".encode()
            info = _tf.TarInfo(name=f"{name}-{ver}/desc")
            info.size = len(body)
            tar.addfile(info, _io.BytesIO(body))
    return buf.getvalue()


class _PacResp:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content


class _PacClient:
    def __init__(self, responses):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        return self._responses.pop(0)


@pytest.mark.anyio
async def test_fetch_pacman_db_ok(monkeypatch):
    """Minimal tar → returns {name: version}."""
    from api.app.routes import pkg_repositories

    tar_bytes = _build_pacman_tar([("vim", "9.1.0"), ("curl", "8.7.1")])
    client = _PacClient([_PacResp(200, tar_bytes)])
    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: client
    )
    out = await pkg_repositories._fetch_pacman_db(
        "https://mirror.example/core/os/x86_64"
    )
    assert out == {"vim": "9.1.0", "curl": "8.7.1"}


@pytest.mark.anyio
async def test_fetch_pacman_db_non_200(monkeypatch):
    """Non-200 from mirror → empty dict."""
    from api.app.routes import pkg_repositories

    client = _PacClient([_PacResp(503, b"")])
    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: client
    )
    out = await pkg_repositories._fetch_pacman_db(
        "https://mirror.example/core/os/x86_64"
    )
    assert out == {}


@pytest.mark.anyio
async def test_fetch_pacman_db_exception(monkeypatch):
    """Transport error → empty dict."""
    from api.app.routes import pkg_repositories

    class _Boom:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            raise RuntimeError("dns error")

    monkeypatch.setattr(
        pkg_repositories.httpx, "AsyncClient", lambda *a, **k: _Boom()
    )
    out = await pkg_repositories._fetch_pacman_db(
        "https://mirror.example/extra/os/x86_64"
    )
    assert out == {}


# check-updates — branches on top of the debian happy path

@pytest.mark.anyio
async def test_check_updates_no_codename_branch(client, auth, collect_auth):
    """Node without os_version exercises the no-codename repo query."""
    from unittest.mock import AsyncMock, patch

    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "nocodename-node",
            "type": "vm",
            "os": "archlinux",
            "arch": "x86_64",
            "kernel": "6.8",
            "packages": ["vim\t9.0.0\tx86_64"],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200

    await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "arch-core-test",
            "os_family": "archlinux",
            "url": "https://mirror/core/os/x86_64",
        },
        headers=auth,
    )

    mock_pac = AsyncMock(return_value={"vim": "9.1.0"})
    with patch("api.app.routes.pkg_repositories._fetch_pacman_db", mock_pac):
        r = await client.post("/api/v1/pkg-repos/check-updates", headers=auth)
    assert r.status_code == 200
    assert any(g["os"] == "archlinux" for g in r.json()["groups"])


@pytest.mark.anyio
async def test_check_updates_skips_unknown_os(client, auth, collect_auth):
    """Node with OS that doesn't map to a family is skipped (continue)."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "weirdos",
            "type": "vm",
            "os": "Plan9",
            "os_version": "4",
            "arch": "x86_64",
            "kernel": "n/a",
            "packages": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200

    r = await client.post("/api/v1/pkg-repos/check-updates", headers=auth)
    assert r.status_code == 200
    # No group should claim plan9
    assert all(g["os"] != "plan9" for g in r.json()["groups"])


@pytest.mark.anyio
async def test_check_updates_fetch_exception_swallowed(client, auth, collect_auth):
    """_fetch_apt_packages raising mid-loop logs + continues."""
    from unittest.mock import AsyncMock, patch

    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "deb-fail",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1",
            "packages": ["curl\t7.88.1-10\tamd64"],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    await client.post(
        "/api/v1/pkg-repos",
        json={
            "name": "debian-bookworm-boom",
            "os_family": "debian",
            "url": "https://example",
            "distribution": "bookworm",
            "components": "main",
        },
        headers=auth,
    )

    mock_apt = AsyncMock(side_effect=RuntimeError("network"))
    with patch("api.app.routes.pkg_repositories._fetch_apt_packages", mock_apt):
        r = await client.post("/api/v1/pkg-repos/check-updates", headers=auth)
    assert r.status_code == 200
    # packages_updated stays 0 because fetch failed.
    assert r.json()["packages_updated"] == 0
