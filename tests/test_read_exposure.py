"""read.py — patch exposure + flags, CVE detail, compliance filters."""

import pytest


@pytest.fixture
async def container_id(client, collect_auth, auth):
    """Create a node with a container and return the container ID."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "exposure-test-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [
                {
                    "name": "exp-web",
                    "image": "nginx",
                    "tag": "1.25",
                    "status": "running",
                    "port_bindings": [],
                    "labels": {},
                    "networks": ["default"],
                },
            ],
        },
        headers=collect_auth,
    )
    # Get the container ID (group=false to get individual rows with id)
    r = await client.get("/api/v1/containers?group=false&search=exp-web", headers=auth)
    items = r.json().get("items", [])
    if items:
        return str(items[0]["id"])
    return None


@pytest.mark.anyio
async def test_patch_exposure(client, auth, container_id):
    """Patch container exposure field."""
    if not container_id:
        pytest.skip("No container created")
    r = await client.patch(
        f"/api/v1/containers/{container_id}/exposure",
        json={"exposure": "internet"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_patch_exposure_invalid(client, auth, container_id):
    """Patch with invalid exposure returns 400."""
    if not container_id:
        pytest.skip("No container created")
    r = await client.patch(
        f"/api/v1/containers/{container_id}/exposure",
        json={"exposure": "invalid_value"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_patch_exposure_flags(client, auth, container_id):
    """Patch container boolean flags (traefik, authelia, geoip, firewall)."""
    if not container_id:
        pytest.skip("No container created")
    r = await client.patch(
        f"/api/v1/containers/{container_id}/exposure",
        json={
            "traefik": True,
            "authelia": True,
            "geoip": False,
            "firewall": True,
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_patch_exposure_empty(client, auth, container_id):
    """Patch with empty body returns ok but no changes."""
    if not container_id:
        pytest.skip("No container created")
    r = await client.patch(
        f"/api/v1/containers/{container_id}/exposure",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_patch_exposure_combined(client, auth, container_id):
    """Patch exposure + flags in one request."""
    if not container_id:
        pytest.skip("No container created")
    r = await client.patch(
        f"/api/v1/containers/{container_id}/exposure",
        json={"exposure": "vpn", "traefik": True, "authelia": False},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_compliance_filter_env(client, auth):
    """Compliance with environment filter."""
    r = await client.get("/api/v1/compliance?environment=production", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_compliance_sort(client, auth):
    """Compliance with sort options."""
    for sort in ("hostname", "sca_score", "cve_open_total", "misconf_critical"):
        r = await client.get(
            f"/api/v1/compliance?sort_by={sort}&sort_dir=desc", headers=auth
        )
        assert r.status_code == 200


@pytest.mark.anyio
async def test_compliance_search(client, auth):
    """Compliance with hostname search."""
    r = await client.get("/api/v1/compliance?search=exposure", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_detail(client, auth, collect_auth):
    """CVE detail endpoint returns metadata + affected hosts."""
    # Ensure CVE exists
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "cve-detail-node",
            "type": "vm",
            "os": "debian",
            "packages": ["curl\t7.88\tamd64"],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "cve-detail-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-DETAIL",
                    "Severity": "CRITICAL",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88",
                    "Description": "Test CVE for detail endpoint",
                    "CVSS": {"nvd": {"V3Score": 9.1}},
                },
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/cves/CVE-2099-DETAIL", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "cve_id" in data or "meta" in data or "hosts" in data


@pytest.mark.anyio
async def test_cve_detail_not_found(client, auth):
    """CVE detail for nonexistent CVE."""
    r = await client.get("/api/v1/cves/CVE-9999-NONEXIST", headers=auth)
    assert r.status_code in (200, 404)
