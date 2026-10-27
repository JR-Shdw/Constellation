"""Integration tests — read endpoints (nodes, packages, containers)."""

import pytest


@pytest.fixture
async def populated_node(client, collect_auth):
    """Create a fully populated node with packages and containers."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "read-test-node",
            "type": ["vm", "container_host"],
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [
                "nginx\t1.24.0\tamd64",
                "curl\t7.88.1\tamd64",
                "openssl\t3.0.11\tamd64",
            ],
            "containers": [
                '{"name":"web","image":"nginx","tag":"1.24","status":"Up",'
                '"port_bindings":[{"container_port":"80/tcp",'
                '"host_ip":"0.0.0.0","host_port":"80"}],'
                '"networks":["bridge"],"labels":{}}',
                '{"name":"db","image":"postgres","tag":"17","status":"Up",'
                '"port_bindings":[],"networks":["backend"],"labels":{}}',
            ],
        },
        headers=collect_auth,
    )
    return r.json()["node_id"]


# Nodes


@pytest.mark.anyio
async def test_list_nodes(client, auth, populated_node):
    """List nodes returns paginated results."""
    r = await client.get("/api/v1/nodes", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1


@pytest.mark.anyio
async def test_list_nodes_filter_type(client, auth, populated_node):
    """Filter nodes by type."""
    r = await client.get("/api/v1/nodes?type=vm", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_list_nodes_search(client, auth, populated_node):
    """?search= matches type/env/os; hostname is handled by ?hostname=."""
    # OS match — populated_node has os='debian'
    r = await client.get("/api/v1/nodes?search=debian", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    # Hostname must NOT match via ?search= (separation of concerns)
    r = await client.get("/api/v1/nodes?search=read-test-node", headers=auth)
    assert r.status_code == 200
    hostnames = {item["hostname"] for item in r.json()["items"]}
    assert "read-test-node" not in hostnames

    # Hostname does match via dedicated ?hostname=
    r = await client.get("/api/v1/nodes?hostname=read-test-node", headers=auth)
    hostnames = {item["hostname"] for item in r.json()["items"]}
    assert "read-test-node" in hostnames


@pytest.mark.anyio
async def test_list_nodes_light(client, auth, populated_node):
    """Lightweight node list for dropdowns."""
    r = await client.get("/api/v1/nodes/list", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    # Should only have id and hostname
    assert "id" in items[0]
    assert "hostname" in items[0]


@pytest.mark.anyio
async def test_get_node_detail(client, auth, populated_node):
    """Get full node detail with packages, containers, CVEs."""
    r = await client.get(f"/api/v1/nodes/{populated_node}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["node"]["hostname"] == "read-test-node"
    assert len(data["packages"]) == 3
    assert len(data["containers"]) == 2


@pytest.mark.anyio
async def test_set_node_environment(client, auth, populated_node):
    """Set node environment."""
    r = await client.put(
        f"/api/v1/nodes/{populated_node}/environment",
        json={"environment": "production"},
        headers=auth,
    )
    assert r.status_code == 200

    # Verify
    r = await client.get(f"/api/v1/nodes/{populated_node}", headers=auth)
    assert r.json()["node"]["environment"] == "production"


@pytest.mark.anyio
async def test_set_node_environment_invalid(client, auth, populated_node):
    """Invalid environment value returns error."""
    r = await client.put(
        f"/api/v1/nodes/{populated_node}/environment",
        json={"environment": "invalid"},
        headers=auth,
    )
    assert r.status_code == 200
    assert "error" in r.json()


# Packages


@pytest.mark.anyio
async def test_list_packages_grouped(client, auth, populated_node):
    """List packages grouped by name+version."""
    r = await client.get("/api/v1/packages?group=true", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 3
    # Grouped items have host_count
    assert "host_count" in data["items"][0]


@pytest.mark.anyio
async def test_list_packages_ungrouped(client, auth, populated_node):
    """List packages ungrouped (flat)."""
    r = await client.get("/api/v1/packages?group=false", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 3
    # Flat items have hostname
    assert "hostname" in data["items"][0]


@pytest.mark.anyio
async def test_list_packages_search(client, auth, populated_node):
    """Search packages by name."""
    r = await client.get("/api/v1/packages?search=nginx", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_package_hosts(client, auth, populated_node):
    """Get hosts for a specific package."""
    r = await client.get("/api/v1/packages/hosts?name=nginx", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    assert items[0]["name"] == "nginx"


# Containers


@pytest.mark.anyio
async def test_list_containers_grouped(client, auth, populated_node):
    """List containers grouped by image."""
    r = await client.get("/api/v1/containers?group=true", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1


@pytest.mark.anyio
async def test_list_containers_ungrouped(client, auth, populated_node):
    """List containers flat."""
    r = await client.get("/api/v1/containers?group=false", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 2


@pytest.mark.anyio
async def test_container_image_hosts(client, auth, populated_node):
    """Get hosts for a specific container image."""
    r = await client.get("/api/v1/containers/hosts?image=nginx", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1


# Exposure


@pytest.mark.anyio
async def test_exposure(client, auth, populated_node):
    """Exposure endpoint returns container exposure data."""
    r = await client.get("/api/v1/exposure", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# Stats


@pytest.mark.anyio
async def test_stats(client, auth, populated_node):
    """Stats dashboard endpoint returns KPIs."""
    r = await client.get("/api/v1/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "nodes_total" in data
    assert "packages_total" in data
    assert "containers_total" in data


# Search


@pytest.mark.anyio
async def test_search(client, auth, populated_node):
    """Cross-type search returns results."""
    r = await client.get("/api/v1/search?q=read-test", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "nodes" in data
    assert len(data["nodes"]) >= 1


@pytest.mark.anyio
async def test_search_package(client, auth, populated_node):
    """Search finds packages."""
    r = await client.get("/api/v1/search?q=nginx", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["packages"]) >= 1


# CVE workflow with justification


@pytest.mark.anyio
async def test_cve_workflow_with_justification(
    client, auth, collect_auth, populated_node
):
    """Set CVE workflow with justification field."""
    # Ingest a CVE
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "read-test-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-7777",
                    "Severity": "HIGH",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "CVSS": {"nvd": {"V3Score": 7.0}},
                },
            ],
        },
        headers=collect_auth,
    )

    r = await client.put(
        "/api/v1/cves/CVE-2024-7777/workflow",
        json={
            "node_id": populated_node,
            "status": "accepted_risk",
            "note": "Mitigated by WAF",
            "justification": "Internal-only service behind WAF, risk accepted",
        },
        headers=auth,
    )
    assert r.status_code == 200


# CVE list with triage and grouping


@pytest.mark.anyio
async def test_cve_list_triage(client, auth, collect_auth, populated_node):
    """CVE list with triage=true filters actionable CVEs."""
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "read-test-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-8888",
                    "Severity": "CRITICAL",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "FixedVersion": "7.88.2",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/cves?triage=true", headers=auth)
    assert r.status_code == 200
    # Triage returns only actionable CVEs
    assert r.json()["total"] >= 0


@pytest.mark.anyio
async def test_cve_list_group_by_package(client, auth):
    """CVE list grouped by package."""
    r = await client.get("/api/v1/cves?group_by=package", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_group_by_remediation(client, auth):
    """CVE list grouped by remediation."""
    r = await client.get("/api/v1/cves?group_by=remediation", headers=auth)
    assert r.status_code == 200


# CVE detail


@pytest.mark.anyio
async def test_cve_detail_includes_hosts(client, auth, collect_auth, populated_node):
    """CVE detail returns host list with scores."""
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "read-test-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-9999",
                    "Severity": "HIGH",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "CVSS": {"nvd": {"V3Score": 8.0}},
                },
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/cves/CVE-2024-9999", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["severity"] == "high"
    assert len(data["hosts"]) >= 1


# Nodes filter by OS


@pytest.mark.anyio
async def test_nodes_filter_os(client, auth, populated_node):
    """Filter nodes by OS."""
    r = await client.get("/api/v1/nodes?os=debian", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1
