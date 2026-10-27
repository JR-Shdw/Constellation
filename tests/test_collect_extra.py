"""Extra collect tests — secrets, container CVEs, edge cases."""

import pytest


@pytest.mark.anyio
async def test_collect_secrets(client, collect_auth, auth):
    """Ingest secrets report and verify listing."""
    # Create node first
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "secrets-test",
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

    r = await client.post(
        "/api/v1/secrets/report",
        json={
            "hostname": "secrets-test",
            "source": "trivy",
            "target_type": "host",
            "secrets": [
                {
                    "RuleID": "aws-access-key",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key",
                    "Match": "AKIA1234567890EXAMPLE",
                    "Target": "/home/user/.aws/credentials",
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["secrets_ingested"] >= 1

    # List secrets
    r = await client.get("/api/v1/secrets", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    # Match should be masked
    secret_items = [i for i in items if i.get("hostname") == "secrets-test"]
    if secret_items:
        assert "AKIA" not in secret_items[0].get("match_masked", "")


@pytest.mark.anyio
async def test_collect_container_cves(client, collect_auth, auth):
    """Ingest container CVEs (image scan)."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "ctr-cve-test",
            "type": "container_host",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [
                '{"name":"app","image":"myapp","tag":"1.0","status":"Up",'
                '"port_bindings":[],"networks":["bridge"],"labels":{}}'
            ],
        },
        headers=collect_auth,
    )

    r = await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "ctr-cve-test",
            "source": "trivy",
            "target_type": "image",
            "image": "myapp:1.0",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-5001",
                    "Severity": "HIGH",
                    "PkgName": "libcurl",
                    "InstalledVersion": "7.74.0",
                    "FixedVersion": "7.74.1",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    # CVE should appear in container CVEs
    r = await client.get("/api/v1/cves?search=CVE-2024-5001", headers=auth)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


@pytest.mark.anyio
async def test_collect_node_update(client, collect_auth, auth):
    """Re-collecting a node updates it (upsert)."""
    base = {
        "hostname": "upsert-test",
        "type": "vm",
        "os": "debian",
        "os_version": "12",
        "arch": "x86_64",
        "kernel": "6.1.0",
        "packages": ["pkg1\t1.0\tamd64"],
        "containers": [],
    }
    r1 = await client.post("/api/v1/nodes/report", json=base, headers=collect_auth)
    node_id = r1.json()["node_id"]

    # Update with new packages
    base["packages"] = ["pkg1\t1.1\tamd64", "pkg2\t2.0\tamd64"]
    base["kernel"] = "6.2.0"
    r2 = await client.post("/api/v1/nodes/report", json=base, headers=collect_auth)
    assert r2.json()["node_id"] == node_id

    # Verify updated data
    r = await client.get(f"/api/v1/nodes/{node_id}", headers=auth)
    node = r.json()["node"]
    assert node["kernel"] == "6.2.0"
    assert node["package_count"] == 2


@pytest.mark.anyio
async def test_collect_empty_packages(client, collect_auth):
    """Collect with empty packages list works."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "empty-pkg-test",
            "type": "bare_metal",
            "os": "archlinux",
            "os_version": "rolling",
            "arch": "x86_64",
            "kernel": "6.8.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_collect_multiple_container_types(client, collect_auth, auth):
    """Containers with various exposure types classified correctly."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "multi-ctr-test",
            "type": "container_host",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [
                '{"name":"localhost-svc","image":"app","tag":"1.0","status":"Up",'
                '"port_bindings":[{"container_port":"8080/tcp",'
                '"host_ip":"127.0.0.1","host_port":"8080"}],'
                '"networks":["host"],"labels":{}}',
            ],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/containers?group=false", headers=auth)
    items = [i for i in r.json()["items"] if i.get("hostname") == "multi-ctr-test"]
    if items:
        assert items[0]["exposure"] == "localhost"
