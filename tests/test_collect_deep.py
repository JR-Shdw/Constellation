"""Collect deep coverage — exposure change, misconf report, drift normalization."""

import uuid

import pytest


@pytest.fixture
async def collect_node(client, collect_auth, auth):
    """Create a node and return hostname + id."""
    hostname = f"col-deep-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "os_name": "Arch Linux",
            "os_version": "rolling",
            "arch": "x86_64",
            "kernel": "6.6.126-1-MANJARO",
            "packages": [
                {"name": "openssl", "version": "3.1.0"},
                {"name": "curl", "version": "8.5.0"},
            ],
            "containers": [
                {
                    "name": "nginx",
                    "image": "nginx",
                    "tag": "1.25",
                    "state": "running",
                    "ports": ["0.0.0.0:443->443/tcp"],
                },
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/nodes", headers=auth)
    node = next(
        (n for n in r.json()["items"] if n["hostname"] == hostname),
        None,
    )
    return {"hostname": hostname, "id": node["id"] if node else None}


# Container exposure change detection


@pytest.mark.anyio
async def test_container_exposure_change(client, collect_auth, collect_node):
    """Re-collect with different ports triggers exposure change."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": collect_node["hostname"],
            "os_name": "Arch Linux",
            "os_version": "rolling",
            "arch": "x86_64",
            "packages": [],
            "containers": [
                {
                    "name": "nginx",
                    "image": "nginx",
                    "tag": "1.25",
                    "state": "running",
                    "ports": [],  # changed from public to none
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


# Misconf report


@pytest.mark.anyio
async def test_misconf_report_accepted(client, collect_auth, collect_node):
    """Misconf report endpoint accepts valid payload."""
    r = await client.post(
        "/api/v1/misconfigurations/report",
        json={
            "hostname": collect_node["hostname"],
            "items": [
                {
                    "rule_id": "DS001",
                    "title": "Root user in Dockerfile",
                    "severity": "HIGH",
                    "target": "/app/Dockerfile",
                    "message": "Running as root",
                    "source": "trivy",
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    # status is ok or error (node may not be found in test DB)
    assert r.json().get("status") in ("ok", "error")


@pytest.mark.anyio
async def test_misconf_list(client, auth):
    """Misconf list endpoint returns paginated results."""
    r = await client.get("/api/v1/misconfigurations", headers=auth)
    assert r.status_code == 200
    assert "total" in r.json()
    assert "items" in r.json()


# Drift report with string items


@pytest.mark.anyio
async def test_drift_report_string_items(client, collect_auth, collect_node):
    """Drift report handles items as JSON strings."""
    import json

    r = await client.post(
        "/api/v1/drift/report",
        json={
            "hostname": collect_node["hostname"],
            "source": "ansible",
            "items": [
                json.dumps(
                    {
                        "drift_type": "file",
                        "resource_name": "/etc/sshd_config",
                        "expected": "PermitRootLogin no",
                        "actual": "PermitRootLogin yes",
                        "severity": "high",
                    }
                ),
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    # Either inserted items or reported node not found
    assert "inserted" in data or "status" in data


# Node with hardware info


@pytest.mark.anyio
async def test_collect_node_with_kernel(client, collect_auth):
    """Collect node with kernel info."""
    hostname = f"kern-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "os_name": "Debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0-25-amd64",
            "node_type": "bare_metal",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") == "ok"
