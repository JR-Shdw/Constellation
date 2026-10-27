"""Integration tests — misconfigurations ingest + list + compliance."""

import pytest


@pytest.fixture
async def node_for_misconf(client, collect_auth):
    """Create a node for misconf tests."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "misconf-test-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    return r.json()["node_id"]


@pytest.mark.anyio
async def test_misconf_report_and_list(client, collect_auth, auth, node_for_misconf):
    """Ingest misconfigurations and verify they appear in list."""
    r = await client.post(
        "/api/v1/misconfigurations/report",
        json={
            "hostname": "misconf-test-node",
            "source": "trivy",
            "misconfigurations": [
                {
                    "ID": "AVD-KSV-0001",
                    "Title": "Process can elevate privileges",
                    "Severity": "CRITICAL",
                    "Target": "deployment.yaml",
                    "Message": "Container runs as root",
                    "Resolution": "Set runAsNonRoot to true",
                },
                {
                    "ID": "AVD-KSV-0012",
                    "Title": "Missing resource limits",
                    "Severity": "MEDIUM",
                    "Target": "deployment.yaml",
                    "Message": "No resource limits set",
                    "Resolution": "Add resources.limits",
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["inserted"] == 2

    # List misconfigurations
    r = await client.get("/api/v1/misconfigurations", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    rules = [i["rule_id"] for i in items]
    assert "AVD-KSV-0001" in rules


@pytest.mark.anyio
async def test_misconf_report_unknown_node(client, collect_auth):
    """Misconf report for unknown node returns error."""
    r = await client.post(
        "/api/v1/misconfigurations/report",
        json={
            "hostname": "nonexistent-node",
            "misconfigurations": [
                {"ID": "TEST-001", "Severity": "LOW", "Target": "test"},
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_misconf_filter_by_severity(client, collect_auth, auth, node_for_misconf):
    """Filter misconfigurations by severity."""
    await client.post(
        "/api/v1/misconfigurations/report",
        json={
            "hostname": "misconf-test-node",
            "misconfigurations": [
                {"ID": "FILTER-HIGH", "Severity": "HIGH", "Target": "test"},
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/misconfigurations?severity=high", headers=auth)
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["severity"] == "high"


@pytest.mark.anyio
async def test_misconf_filter_by_node(client, auth, node_for_misconf):
    """Filter misconfigurations by node_id."""
    r = await client.get(
        f"/api/v1/misconfigurations?node_id={node_for_misconf}", headers=auth
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_misconf_upsert(client, collect_auth, auth, node_for_misconf):
    """Same rule_id updates instead of duplicating."""
    payload = {
        "hostname": "misconf-test-node",
        "misconfigurations": [
            {
                "ID": "UPSERT-001",
                "Title": "Original",
                "Severity": "LOW",
                "Target": "test.yaml",
                "Message": "msg1",
                "Resolution": "fix1",
            },
        ],
    }
    await client.post(
        "/api/v1/misconfigurations/report", json=payload, headers=collect_auth
    )

    # Update severity
    payload["misconfigurations"][0]["Severity"] = "HIGH"
    payload["misconfigurations"][0]["Message"] = "msg2"
    await client.post(
        "/api/v1/misconfigurations/report", json=payload, headers=collect_auth
    )

    r = await client.get(
        f"/api/v1/misconfigurations?node_id={node_for_misconf}", headers=auth
    )
    matches = [i for i in r.json()["items"] if i["rule_id"] == "UPSERT-001"]
    assert len(matches) == 1
    assert matches[0]["severity"] == "high"


@pytest.mark.anyio
async def test_compliance_summary(client, auth):
    """Compliance summary endpoint returns data."""
    r = await client.get("/api/v1/compliance", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
