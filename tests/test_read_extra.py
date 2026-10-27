"""Extra read tests — trends, audit log, secrets list, CVE filters."""

import pytest


@pytest.fixture
async def node_with_data(client, collect_auth):
    """Create a node with packages, containers, and CVEs for read tests."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "read-extra-node",
            "type": "container_host",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [
                "bash\t5.2.15\tamd64",
                "openssl\t3.0.11\tamd64",
            ],
            "containers": [
                '{"name":"web","image":"nginx","tag":"1.25","status":"Up",'
                '"port_bindings":[{"container_port":"80/tcp",'
                '"host_ip":"0.0.0.0","host_port":"80"}],'
                '"networks":["bridge"],"labels":{}}',
            ],
        },
        headers=collect_auth,
    )
    node_id = r.json()["node_id"]

    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "read-extra-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-0001",
                    "Severity": "CRITICAL",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "FixedVersion": "3.0.12",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
                {
                    "VulnerabilityID": "CVE-2025-0002",
                    "Severity": "LOW",
                    "PkgName": "bash",
                    "InstalledVersion": "5.2.15",
                    "CVSS": {"nvd": {"V3Score": 2.0}},
                },
            ],
        },
        headers=collect_auth,
    )
    return node_id


# Stats trends


@pytest.mark.anyio
async def test_stats_trends(client, auth, node_with_data):
    """Stats trends returns time series data."""
    r = await client.get("/api/v1/stats/trends?days=30", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "cves" in data
    assert "backups" in data


@pytest.mark.anyio
async def test_stats_trends_short(client, auth, node_with_data):
    """Stats trends with 1 day (hourly bucket)."""
    r = await client.get("/api/v1/stats/trends?days=1", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_stats_trends_long(client, auth, node_with_data):
    """Stats trends with 365 days (weekly bucket)."""
    r = await client.get("/api/v1/stats/trends?days=365", headers=auth)
    assert r.status_code == 200


# Audit log


@pytest.mark.anyio
async def test_audit_log(client, auth, node_with_data):
    """Audit log returns paginated items."""
    r = await client.get("/api/v1/audit", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data


@pytest.mark.anyio
async def test_audit_log_filter_target_type(client, auth, node_with_data):
    """Filter audit log by target type."""
    r = await client.get("/api/v1/audit?target_type=node", headers=auth)
    assert r.status_code == 200


# Secrets list


@pytest.mark.anyio
async def test_secrets_list(client, auth):
    """Secrets list endpoint returns items."""
    r = await client.get("/api/v1/secrets", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# CVE filters


@pytest.mark.anyio
async def test_cve_list_filter_severity(client, auth, node_with_data):
    """Filter CVEs by severity."""
    r = await client.get("/api/v1/cves?severity=critical", headers=auth)
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["severity"] == "critical"


@pytest.mark.anyio
async def test_cve_list_search(client, auth, node_with_data):
    """Search CVEs by CVE ID."""
    r = await client.get("/api/v1/cves?search=CVE-2025-0001", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_cve_list_pagination(client, auth, node_with_data):
    """CVE list respects pagination."""
    r = await client.get("/api/v1/cves?per_page=1&page=1", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["items"]) <= 1


# Containers filter


@pytest.mark.anyio
async def test_containers_filter_search(client, auth, node_with_data):
    """Search containers by image."""
    r = await client.get("/api/v1/containers?search=nginx", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1
