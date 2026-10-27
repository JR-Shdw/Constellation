"""Integration tests — drift detection report + list + patch."""

import pytest


@pytest.fixture
async def node_for_drift(client, collect_auth):
    """Create a node for drift tests."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "drift-test-node",
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
async def test_drift_report_and_list(client, collect_auth, auth, node_for_drift):
    """Ingest drift report and verify items appear in list."""
    r = await client.post(
        "/api/v1/drift/report",
        json={
            "hostname": "drift-test-node",
            "source": "ansible",
            "items": [
                {
                    "drift_type": "file",
                    "resource_name": "/etc/ssh/sshd_config",
                    "expected": "PermitRootLogin no",
                    "actual": "PermitRootLogin yes",
                    "severity": "critical",
                },
                {
                    "drift_type": "package",
                    "resource_name": "nginx",
                    "expected": "1.24.0",
                    "actual": "1.22.1",
                    "severity": "medium",
                },
                {
                    "drift_type": "service",
                    "resource_name": "firewalld",
                    "expected": "running",
                    "actual": "stopped",
                    "severity": "high",
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["inserted"] == 3

    # List drift reports
    r = await client.get("/api/v1/drift", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    resources = [i["resource_name"] for i in items]
    assert "/etc/ssh/sshd_config" in resources


@pytest.mark.anyio
async def test_drift_report_unknown_node(client, collect_auth):
    """Drift report for unknown node returns error."""
    r = await client.post(
        "/api/v1/drift/report",
        json={
            "hostname": "nonexistent-drift-node",
            "items": [
                {
                    "drift_type": "file",
                    "resource_name": "/etc/test",
                    "severity": "low",
                }
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_drift_filter_by_severity(client, collect_auth, auth, node_for_drift):
    """Filter drift reports by severity."""
    await client.post(
        "/api/v1/drift/report",
        json={
            "hostname": "drift-test-node",
            "items": [
                {
                    "drift_type": "config",
                    "resource_name": "/etc/test-filter",
                    "severity": "high",
                }
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/drift?severity=high", headers=auth)
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["severity"] == "high"


@pytest.mark.anyio
async def test_drift_filter_by_node(client, auth, node_for_drift):
    """Filter drift reports by node_id."""
    r = await client.get(f"/api/v1/drift?node_id={node_for_drift}", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_drift_patch_status(client, collect_auth, auth, node_for_drift):
    """Patch drift report status to acknowledged."""
    # Create a drift item
    await client.post(
        "/api/v1/drift/report",
        json={
            "hostname": "drift-test-node",
            "items": [
                {
                    "drift_type": "file",
                    "resource_name": "/etc/patch-test",
                    "severity": "medium",
                }
            ],
        },
        headers=collect_auth,
    )
    # Get drift ID
    r = await client.get("/api/v1/drift", headers=auth)
    items = r.json()["items"]
    patch_item = [i for i in items if i["resource_name"] == "/etc/patch-test"]
    if not patch_item:
        pytest.skip("drift item not found")
    drift_id = str(patch_item[0]["id"])

    # Patch status
    r = await client.patch(
        f"/api/v1/drift/{drift_id}",
        json={"status": "acknowledged"},
        headers=auth,
    )
    assert r.status_code == 200

    # Patch to resolved
    r = await client.patch(
        f"/api/v1/drift/{drift_id}",
        json={"status": "resolved"},
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_drift_patch_invalid_status(client, auth):
    """Patch with invalid status returns 400."""
    fake_uuid = "00000000-0000-0000-0000-000000000001"
    r = await client.patch(
        f"/api/v1/drift/{fake_uuid}",
        json={"status": "invalid_status"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_drift_upsert_updates_existing(
    client, collect_auth, auth, node_for_drift
):
    """Submitting same resource_name updates instead of duplicating."""
    payload = {
        "hostname": "drift-test-node",
        "items": [
            {
                "drift_type": "file",
                "resource_name": "/etc/upsert-test",
                "expected": "old",
                "actual": "new",
                "severity": "low",
            }
        ],
    }
    await client.post("/api/v1/drift/report", json=payload, headers=collect_auth)

    # Update with new actual value
    payload["items"][0]["actual"] = "newer"
    payload["items"][0]["severity"] = "high"
    await client.post("/api/v1/drift/report", json=payload, headers=collect_auth)

    r = await client.get("/api/v1/drift", headers=auth)
    matches = [i for i in r.json()["items"] if i["resource_name"] == "/etc/upsert-test"]
    assert len(matches) == 1
    assert matches[0]["actual"] == "newer"
    assert matches[0]["severity"] == "high"
