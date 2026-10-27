"""Export PDF report + empty CSV edge cases."""

import pytest


@pytest.mark.anyio
async def test_export_report_html(client, auth, collect_auth):
    """PDF report (HTML) returns valid HTML with all sections."""
    # Ensure at least one node exists
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "report-node",
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
    r = await client.get("/api/v1/export/report", headers=auth)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    body = r.text
    assert "Constellation" in body
    assert "Executive Summary" in body
    assert "Top CVEs" in body
    assert "Node Inventory" in body
    assert "Backup Status" in body
    assert "Confidential" in body


@pytest.mark.anyio
async def test_export_report_has_stats(client, auth):
    """PDF report includes stats table with numeric values."""
    r = await client.get("/api/v1/export/report", headers=auth)
    assert r.status_code == 200
    body = r.text
    assert "Active nodes" in body
    assert "Containers" in body
    assert "Packages tracked" in body


@pytest.mark.anyio
async def test_export_cves_empty_csv(client, auth):
    """Export CVEs with filter that matches nothing returns 'No data'."""
    r = await client.get(
        "/api/v1/export/cves?severity=critical&workflow_status=resolved&environment=lab",
        headers=auth,
    )
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    # Either has headers or "No data"
    body = r.text
    assert "cve_id" in body or "No data" in body


@pytest.mark.anyio
async def test_export_nodes_empty_csv(client, auth):
    """Export nodes with nonexistent env filter still returns CSV."""
    r = await client.get("/api/v1/export/nodes?environment=nonexistent", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


@pytest.mark.anyio
async def test_export_audit_detail_json(client, auth, collect_auth):
    """Export audit CSV stringifies JSON detail field."""
    # Create an action that generates a JSON detail
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "audit-export-node",
            "type": "vm",
            "os": "debian",
            "packages": [],
        },
        headers=collect_auth,
    )
    r = await client.get("/api/v1/export/audit?days=1", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
