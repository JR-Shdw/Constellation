"""SBOM import + read tests."""

import pytest


async def _ensure_node(client, collect_auth, hostname="sbom-host"):
    """Helper: create a node for SBOM tests."""
    await client.post(
        "/api/v1/nodes/report",
        json={"hostname": hostname, "type": "vm", "os": "debian", "packages": []},
        headers=collect_auth,
    )


@pytest.mark.anyio
async def test_sbom_import(client, auth, collect_auth):
    await _ensure_node(client, collect_auth)
    r = await client.post(
        "/api/v1/sbom/import",
        json={
            "hostname": "sbom-host",
            "components": [
                {
                    "name": "openssl",
                    "version": "3.0.2",
                    "type": "library",
                    "purl": "pkg:deb/openssl@3.0.2",
                },
                {"name": "zlib", "version": "1.2.11", "type": "library"},
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["imported"] == 2
    assert data["hostname"] == "sbom-host"


@pytest.mark.anyio
async def test_sbom_import_cyclonedx(client, auth, collect_auth):
    await _ensure_node(client, collect_auth, "sbom-cdx")
    r = await client.post(
        "/api/v1/sbom/import",
        json={
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"name": "sbom-cdx", "type": "application"}},
            "components": [
                {"name": "curl", "version": "7.88", "type": "library"},
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["imported"] == 1


@pytest.mark.anyio
async def test_sbom_import_no_hostname(client, collect_auth):
    r = await client.post(
        "/api/v1/sbom/import",
        json={"components": [{"name": "a", "version": "1"}]},
        headers=collect_auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_sbom_import_unknown_host(client, collect_auth):
    r = await client.post(
        "/api/v1/sbom/import",
        json={"hostname": "no-such-host", "components": []},
        headers=collect_auth,
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_sbom_list(client, auth, collect_auth):
    await _ensure_node(client, collect_auth, "sbom-list")
    await client.post(
        "/api/v1/sbom/import",
        json={
            "hostname": "sbom-list",
            "components": [
                {"name": "libssl", "version": "3.0.2", "type": "library"},
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/sbom", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.anyio
async def test_sbom_list_filter_node(client, auth, collect_auth):
    await _ensure_node(client, collect_auth, "sbom-filt")
    await client.post(
        "/api/v1/sbom/import",
        json={
            "hostname": "sbom-filt",
            "components": [{"name": "bash", "version": "5.2", "type": "library"}],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/sbom?node=sbom-filt", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_sbom_list_search(client, auth, collect_auth):
    await _ensure_node(client, collect_auth, "sbom-search")
    await client.post(
        "/api/v1/sbom/import",
        json={
            "hostname": "sbom-search",
            "components": [
                {"name": "unique-sbom-pkg", "version": "1.0", "type": "library"},
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/sbom?search=unique-sbom", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_sbom_stats(client, auth):
    r = await client.get("/api/v1/sbom/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total_components" in data
    assert "unique_packages" in data
    assert "vulnerable_packages" in data
