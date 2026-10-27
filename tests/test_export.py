"""Integration tests — CSV export endpoints."""

import pytest


@pytest.mark.anyio
async def test_export_cves_csv(client, auth, collect_auth):
    """Export CVEs returns CSV with correct headers."""
    # Ensure at least one node + CVE exists
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "export-cve-test",
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
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "export-cve-test",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-9901",
                    "Severity": "HIGH",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                },
            ],
        },
        headers=collect_auth,
    )

    r = await client.get("/api/v1/export/cves", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "cmdb-cves-" in r.headers["content-disposition"]
    body = r.text
    assert "cve_id" in body
    assert "CVE-2024-9901" in body


@pytest.mark.anyio
async def test_export_cves_with_severity_filter(client, auth):
    """Export CVEs with severity filter."""
    r = await client.get("/api/v1/export/cves?severity=critical", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


@pytest.mark.anyio
async def test_export_cves_with_triage(client, auth):
    """Export CVEs with triage mode."""
    r = await client.get("/api/v1/export/cves?triage=true", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


@pytest.mark.anyio
async def test_export_nodes_csv(client, auth):
    """Export nodes returns CSV."""
    r = await client.get("/api/v1/export/nodes", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "cmdb-nodes-" in r.headers["content-disposition"]


@pytest.mark.anyio
async def test_export_nodes_with_env_filter(client, auth):
    """Export nodes with environment filter."""
    r = await client.get("/api/v1/export/nodes?environment=production", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_export_backup_csv(client, auth):
    """Export backup summary returns CSV."""
    r = await client.get("/api/v1/export/backup", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


@pytest.mark.anyio
async def test_export_compliance_csv(client, auth):
    """Export compliance summary returns CSV."""
    r = await client.get("/api/v1/export/compliance", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


@pytest.mark.anyio
async def test_export_audit_csv(client, auth):
    """Export audit log returns CSV."""
    r = await client.get("/api/v1/export/audit", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "cmdb-audit-" in r.headers["content-disposition"]


@pytest.mark.anyio
async def test_export_audit_custom_days(client, auth):
    """Export audit log with custom days parameter."""
    r = await client.get("/api/v1/export/audit?days=7", headers=auth)
    assert r.status_code == 200
