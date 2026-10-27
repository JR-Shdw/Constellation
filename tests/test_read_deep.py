"""Deep read.py coverage — search, stats cache, secrets, CVE detail, audit actor."""

import pytest


@pytest.fixture
async def populated_node(client, collect_auth):
    """Create node with packages, containers, CVEs, secrets for search tests."""
    hostname = "deep-read-node"
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "type": "bare_metal",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["nginx\t1.24.0\tamd64", "curl\t7.88.1\tamd64"],
            "containers": [
                {
                    "name": "webapp",
                    "image": "myapp:v2.1",
                    "status": "running",
                    "port_bindings": [],
                    "labels": {},
                    "networks": ["internal"],
                },
            ],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": hostname,
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-DEEP1",
                    "Severity": "CRITICAL",
                    "PkgName": "nginx",
                    "InstalledVersion": "1.24.0",
                    "FixedVersion": "1.24.1",
                    "Description": "Deep read test CVE",
                    "CVSS": {"nvd": {"V3Score": 9.1}},
                },
            ],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/secrets/report",
        json={
            "hostname": hostname,
            "target_type": "host",
            "secrets": [
                {
                    "RuleID": "generic-api-key",
                    "Title": "Generic API Key",
                    "Severity": "HIGH",
                    "Match": "APIKEY=sk_live_1234567890abcdef",
                    "Target": "/etc/app/config.yml",
                    "Category": "generic",
                },
            ],
        },
        headers=collect_auth,
    )
    return hostname


# Search


@pytest.mark.anyio
async def test_search_containers(client, auth, populated_node):
    """Global search finds containers."""
    r = await client.get("/api/v1/search?q=webapp", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "containers" in data


@pytest.mark.anyio
async def test_search_cves(client, auth, populated_node):
    """Global search finds CVEs by ID."""
    r = await client.get("/api/v1/search?q=CVE-2099-DEEP", headers=auth)
    assert r.status_code == 200
    assert "cves" in r.json()


# CVE detail


@pytest.mark.anyio
async def test_cve_detail_full(client, auth, populated_node):
    """CVE detail returns hosts, severity, description, sources."""
    r = await client.get("/api/v1/cves/CVE-2099-DEEP1", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["cve_id"] == "CVE-2099-DEEP1"
    assert data["severity"] == "critical"
    assert "hosts" in data
    assert "containers" in data
    assert "nvd_url" in data
    assert "sources" in data
    assert len(data["hosts"]) >= 1


@pytest.mark.anyio
async def test_cve_detail_not_found(client, auth):
    """CVE detail for nonexistent CVE returns error."""
    r = await client.get("/api/v1/cves/CVE-0000-0000", headers=auth)
    assert r.status_code == 200
    assert "error" in r.json()


# Stats (cache bypass)


@pytest.mark.anyio
async def test_stats_fresh(client, auth, populated_node):
    """Stats returns all KPIs with cache cleared."""
    from api.app.routes.read import _cache

    _cache.clear()
    r = await client.get("/api/v1/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "nodes_total" in data
    assert "nodes_active" in data
    assert "cves_critical" in data
    assert "cves_total" in data
    assert "backups_ok" in data
    assert "trivy_host_scanned" in data
    assert "feature_cve_enabled" in data
    assert "feature_backup_enabled" in data


# Secrets


@pytest.mark.anyio
async def test_secrets_list_paginated(client, auth, populated_node):
    """Secrets list returns paginated results."""
    r = await client.get("/api/v1/secrets?per_page=10", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1


# Audit log filter by actor


@pytest.mark.anyio
async def test_audit_log_filter_actor(client, auth):
    """Audit log filtered by actor."""
    r = await client.get("/api/v1/audit?actor=secret_key", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# CVE list with node filter


@pytest.mark.anyio
async def test_cve_list_filter_node(client, auth, populated_node):
    """CVE list filtered by node_id."""
    # Get node_id
    r = await client.get("/api/v1/nodes/list", headers=auth)
    node_id = None
    for n in r.json()["items"]:
        if n["hostname"] == populated_node:
            node_id = str(n["id"])
            break
    assert node_id
    r = await client.get(f"/api/v1/cves?node_id={node_id}", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


# Exposure


@pytest.mark.anyio
async def test_exposure_matrix(client, auth, populated_node):
    """Exposure matrix returns container network data."""
    from api.app.routes.read import _cache

    _cache.clear()
    r = await client.get("/api/v1/exposure", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# Packages with version filter


@pytest.mark.anyio
async def test_packages_filter_version(client, auth, populated_node):
    """Package list filtered by version."""
    r = await client.get("/api/v1/packages?version=1.24.0", headers=auth)
    assert r.status_code == 200


# Containers grouped with tag filter


@pytest.mark.anyio
async def test_containers_filter_tag(client, auth, populated_node):
    """Container list filtered by tag."""
    r = await client.get("/api/v1/containers?tag=v2.1", headers=auth)
    assert r.status_code == 200


# Node environment invalid UUID


@pytest.mark.anyio
async def test_node_environment_invalid_uuid(client, auth):
    """Set environment with invalid UUID returns 400."""
    r = await client.put(
        "/api/v1/nodes/not-a-uuid/environment",
        json={"environment": "production"},
        headers=auth,
    )
    assert r.status_code == 400
