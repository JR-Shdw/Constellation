"""SCA (Security Configuration Assessment) tests — report, list, summary, detail."""

import uuid

import pytest


@pytest.fixture
async def sca_node(client, collect_auth):
    """Create a node and ingest SCA results, return hostname."""
    hostname = f"sca-node-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
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
    return hostname


@pytest.mark.anyio
async def test_sca_report(client, collect_auth, sca_node):
    """Ingest SCA policies for a node."""
    r = await client.post(
        "/api/v1/sca/report",
        json={
            "hostname": sca_node,
            "source": "wazuh",
            "policies": [
                {
                    "policy_id": "cis_debian12",
                    "policy_name": "CIS Debian 12 Benchmark",
                    "score": 72,
                    "total_checks": 100,
                    "passed": 72,
                    "failed": 28,
                },
                {
                    "policy_id": "sca_unix_audit",
                    "policy_name": "Unix Audit",
                    "score": 85,
                    "total_checks": 50,
                    "passed": 42,
                    "failed": 8,
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["policies_ingested"] == 2


@pytest.mark.anyio
async def test_sca_report_missing_hostname(client, collect_auth):
    """Report without hostname returns error."""
    r = await client.post(
        "/api/v1/sca/report",
        json={"hostname": "", "policies": []},
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_sca_report_unknown_host(client, collect_auth):
    """Report for unknown host returns error."""
    r = await client.post(
        "/api/v1/sca/report",
        json={"hostname": "nonexistent-node", "policies": []},
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_sca_list(client, auth, collect_auth, sca_node):
    """List SCA results."""
    # Ingest first
    await client.post(
        "/api/v1/sca/report",
        json={
            "hostname": sca_node,
            "source": "wazuh",
            "policies": [
                {
                    "policy_id": "cis_test",
                    "policy_name": "CIS Test",
                    "score": 90,
                    "total_checks": 10,
                    "passed": 9,
                    "failed": 1,
                },
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/sca/", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.anyio
async def test_sca_list_filter_hostname(client, auth, collect_auth, sca_node):
    """List SCA with hostname filter."""
    await client.post(
        "/api/v1/sca/report",
        json={
            "hostname": sca_node,
            "source": "wazuh",
            "policies": [
                {
                    "policy_id": "cis_filter",
                    "policy_name": "CIS Filter",
                    "score": 80,
                    "total_checks": 20,
                    "passed": 16,
                    "failed": 4,
                },
            ],
        },
        headers=collect_auth,
    )
    r = await client.get(f"/api/v1/sca/?hostname={sca_node}", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_sca_summary(client, auth):
    """SCA summary returns global average and per-node breakdown."""
    r = await client.get("/api/v1/sca/summary", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "global_avg_score" in data
    assert "nodes" in data


@pytest.mark.anyio
async def test_sca_node_detail(client, auth, collect_auth, sca_node):
    """Get SCA detail for a specific node."""
    # Ingest and capture node_id from response
    r = await client.post(
        "/api/v1/sca/report",
        json={
            "hostname": sca_node,
            "source": "wazuh",
            "policies": [
                {
                    "policy_id": "cis_detail",
                    "policy_name": "CIS Detail",
                    "score": 65,
                    "total_checks": 40,
                    "passed": 26,
                    "failed": 14,
                },
            ],
        },
        headers=collect_auth,
    )
    node_id = r.json()["node_id"]

    r = await client.get(f"/api/v1/sca/{node_id}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert len(data["items"]) >= 1


@pytest.mark.anyio
async def test_sca_summary_handles_null_score(client, auth, collect_auth, sca_node):
    """A node whose policies all have NULL score must not 500 /summary.

    Regression: global_avg did sum(avg_score) over items including None
    (avg of all-NULL scores), raising float + None TypeError.
    """
    r = await client.post(
        "/api/v1/sca/report",
        json={
            "hostname": sca_node,
            "source": "wazuh",
            "policies": [
                {
                    "policy_id": "no_score_policy",
                    "policy_name": "Score-less policy",
                    "total_checks": 10,
                    "passed": 5,
                    "failed": 5,
                    # score intentionally omitted → NULL
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200

    r = await client.get("/api/v1/sca/summary", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "global_avg_score" in data  # no crash; may be None or a float


@pytest.mark.anyio
async def test_sca_node_detail_invalid_uuid(client, auth):
    """Malformed node_id → 400 (validate_uuid), not a 500 from asyncpg."""
    r = await client.get("/api/v1/sca/not-a-uuid", headers=auth)
    assert r.status_code == 400
