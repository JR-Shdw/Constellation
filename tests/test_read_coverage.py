"""Extra read.py coverage — node detail, compliance, containers filter, CVE filters."""

import pytest


@pytest.fixture
async def node_with_data(client, collect_auth, auth):
    """Create a node with packages, containers, and CVEs."""
    hostname = "read-cov-node"
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
                    "name": "web",
                    "image": "nginx",
                    "tag": "1.25",
                    "status": "running",
                    "port_bindings": [{"host_ip": "0.0.0.0", "host_port": "443"}],
                    "labels": {"traefik.enable": "true"},
                    "networks": ["proxy"],
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
                    "VulnerabilityID": "CVE-2099-RC01",
                    "Severity": "HIGH",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "FixedVersion": "7.88.2",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                },
            ],
        },
        headers=collect_auth,
    )
    # Get node_id (needs read permission, not collect)
    r = await client.get("/api/v1/nodes/list", headers=auth)
    for n in r.json()["items"]:
        if n["hostname"] == hostname:
            return str(n["id"])
    return None


# Node detail


@pytest.mark.anyio
async def test_node_detail_full(client, auth, node_with_data):
    """Node detail returns packages, containers, CVEs."""
    r = await client.get(f"/api/v1/nodes/{node_with_data}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "node" in data
    assert "packages" in data
    assert "containers" in data
    assert "cves" in data
    assert len(data["packages"]) >= 2


@pytest.mark.anyio
async def test_node_detail_not_found(client, auth):
    """Node detail for nonexistent UUID."""
    import uuid

    fake = str(uuid.uuid4())
    r = await client.get(f"/api/v1/nodes/{fake}", headers=auth)
    assert r.status_code == 200
    assert "error" in r.json()


# Compliance


@pytest.mark.anyio
async def test_compliance_summary(client, auth):
    """Compliance summary returns node scores."""
    r = await client.get("/api/v1/compliance", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# CVE filters


@pytest.mark.anyio
async def test_cve_list_filter_source(client, auth, node_with_data):
    """CVE list filtered by source."""
    r = await client.get("/api/v1/cves?source=trivy", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_exploited(client, auth, node_with_data):
    """CVE list filtered by exploited flag."""
    r = await client.get("/api/v1/cves?exploited=false", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_workflow(client, auth, node_with_data):
    """CVE list filtered by workflow status."""
    r = await client.get("/api/v1/cves?workflow_status=open", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_sort_options(client, auth, node_with_data):
    """CVE list with different sort options."""
    for sort in ("cvss", "severity", "score", "exploited"):
        r = await client.get(f"/api/v1/cves?sort={sort}&order=desc", headers=auth)
        assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_target_type(client, auth, node_with_data):
    """CVE list filtered by target type."""
    r = await client.get("/api/v1/cves?target_type=package", headers=auth)
    assert r.status_code == 200


# Containers filters


@pytest.mark.anyio
async def test_containers_filter_image(client, auth, node_with_data):
    """Container list filtered by image."""
    r = await client.get("/api/v1/containers?image=nginx", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_containers_ungrouped_filter(client, auth, node_with_data):
    """Container list ungrouped with search."""
    r = await client.get("/api/v1/containers?group=false&search=web", headers=auth)
    assert r.status_code == 200


# Packages filter by node


@pytest.mark.anyio
async def test_packages_filter_node(client, auth, node_with_data):
    """Package list filtered by node_id."""
    r = await client.get(f"/api/v1/packages?node_id={node_with_data}", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


# Container image hosts


@pytest.mark.anyio
async def test_container_image_hosts_with_data(client, auth, node_with_data):
    """Container image hosts returns hosts, CVEs, repos."""
    r = await client.get("/api/v1/containers/hosts?image=nginx", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "cves" in data
    assert "repos" in data
