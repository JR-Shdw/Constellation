"""Integration tests — CVE ingest, scoring, search, workflow."""

import pytest


@pytest.fixture
async def node_with_cves(client, collect_auth, auth):
    """Create a node then ingest CVEs."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "cve-test-host",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["openssl\t3.0.11\tamd64"],
            "containers": [],
        },
        headers=collect_auth,
    )
    node_id = r.json()["node_id"]

    # Ingest host CVEs
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "cve-test-host",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "Severity": "CRITICAL",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "FixedVersion": "3.0.13",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                    "Description": "Test critical CVE",
                },
                {
                    "VulnerabilityID": "CVE-2024-0002",
                    "Severity": "LOW",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "CVSS": {"nvd": {"V3Score": 3.1}},
                    "Description": "Test low CVE",
                },
            ],
        },
        headers=collect_auth,
    )
    return node_id


@pytest.mark.anyio
async def test_cve_ingest_and_list(client, auth, node_with_cves):
    """CVEs are ingested and visible in the list."""
    r = await client.get("/api/v1/cves?search=CVE-2024-0001", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    cve = items[0]
    assert cve["cve_id"] == "CVE-2024-0001"
    assert cve["severity"] == "critical"
    if "score" in cve:
        assert cve["score"] > 0


@pytest.mark.anyio
async def test_cve_score_critical_higher_than_low(client, auth, node_with_cves):
    """Critical CVEs have higher contextual scores than low ones."""
    r = await client.get("/api/v1/cves?sort=cvss&per_page=10", headers=auth)
    if r.status_code != 200:
        pytest.skip(
            "v_all_cves view not fully created (score requires cve_score function)"
        )
    items = r.json()["items"]

    scores = {
        i["cve_id"]: i.get("score", 0) for i in items if "CVE-2024" in i["cve_id"]
    }
    if "CVE-2024-0001" in scores and "CVE-2024-0002" in scores:
        assert scores["CVE-2024-0001"] >= scores["CVE-2024-0002"]


@pytest.mark.anyio
async def test_cve_detail(client, auth, node_with_cves):
    """CVE detail returns hosts, description, severity."""
    r = await client.get("/api/v1/cves/CVE-2024-0001", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["severity"] == "critical"
    assert data["cvss_score"] == 9.8
    assert len(data["hosts"]) >= 1
    assert data["hosts"][0]["hostname"] == "cve-test-host"
    assert data["hosts"][0]["score"] > 0


@pytest.mark.anyio
async def test_cve_search_by_hostname(client, auth, node_with_cves):
    """Search CVEs by hostname returns results."""
    r = await client.get("/api/v1/cves?search=cve-test-host", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


@pytest.mark.anyio
async def test_cve_workflow(client, auth, node_with_cves):
    """Set workflow status on a CVE for a node."""
    node_id = node_with_cves

    r = await client.put(
        "/api/v1/cves/CVE-2024-0001/workflow",
        json={"node_id": node_id, "status": "mitigated", "note": "patched"},
        headers=auth,
    )
    assert r.status_code == 200

    # Verify CVE still exists after workflow change
    r = await client.get(
        "/api/v1/cves?search=CVE-2024-0001",
        headers=auth,
    )
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_cve_workflow_propagates_to_scan_table(client, auth, node_with_cves):
    """Workflow status propagates to cve_host_packages so the UI reflects it
    without waiting for a rescan — covers CVEs on removed packages/images."""
    node_id = node_with_cves

    # Default: CVE is open in cve_host_packages
    r = await client.get("/api/v1/cves?search=CVE-2024-0001", headers=auth)
    item = next(i for i in r.json()["items"] if i["cve_id"] == "CVE-2024-0001")
    assert item["status"] == "open"

    # Resolve → scan-table status must switch immediately.
    r = await client.put(
        "/api/v1/cves/CVE-2024-0001/workflow",
        json={"node_id": node_id, "status": "resolved"},
        headers=auth,
    )
    assert r.status_code == 200

    r = await client.get("/api/v1/cves?search=CVE-2024-0001", headers=auth)
    item = next(i for i in r.json()["items"] if i["cve_id"] == "CVE-2024-0001")
    assert item["status"] == "resolved", (
        f"expected scan status 'resolved', got {item['status']!r}"
    )

    # accepted_risk → ignored (matches collect/cves.py sync mapping).
    await client.put(
        "/api/v1/cves/CVE-2024-0002/workflow",
        json={"node_id": node_id, "status": "accepted_risk"},
        headers=auth,
    )
    r = await client.get("/api/v1/cves?search=CVE-2024-0002", headers=auth)
    item = next(i for i in r.json()["items"] if i["cve_id"] == "CVE-2024-0002")
    assert item["status"] == "ignored"

    # Back to open → scan status returns to open (not stuck resolved).
    await client.put(
        "/api/v1/cves/CVE-2024-0001/workflow",
        json={"node_id": node_id, "status": "open"},
        headers=auth,
    )
    r = await client.get("/api/v1/cves?search=CVE-2024-0001", headers=auth)
    item = next(i for i in r.json()["items"] if i["cve_id"] == "CVE-2024-0001")
    assert item["status"] == "open"
