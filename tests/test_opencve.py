"""OpenCVE routes tests — webhook, batch, alerts, subscriptions, impact."""

import pytest


@pytest.mark.anyio
async def test_opencve_webhook(client, collect_auth):
    """Single CVE webhook ingestion."""
    r = await client.post(
        "/api/v1/opencve/webhook",
        json={
            "cve_id": "CVE-2099-9999",
            "vendor": "openssl",
            "product": "openssl",
            "title": "Test CVE for webhook",
            "description": "A test vulnerability",
            "severity": "high",
            "cvss_v3": 8.1,
            "cwe_ids": ["CWE-79"],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["cve_id"] == "CVE-2099-9999"


@pytest.mark.anyio
async def test_opencve_webhook_kev(client, collect_auth):
    """Webhook with KEV flag propagates exploited status."""
    r = await client.post(
        "/api/v1/opencve/webhook",
        json={
            "cve_id": "CVE-2099-8888",
            "vendor": "test",
            "product": "test",
            "title": "KEV test",
            "kev": True,
            "cvss_v3": 9.8,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_opencve_webhook_cvss_severity(client, collect_auth):
    """Webhook derives severity from CVSS score."""
    cases = [(9.5, "critical"), (7.5, "high"), (5.0, "medium"), (2.0, "low")]
    for cvss, expected_sev in cases:
        r = await client.post(
            "/api/v1/opencve/webhook",
            json={
                "cve_id": f"CVE-2099-{int(cvss * 100)}",
                "title": f"CVSS {cvss}",
                "cvss_v3": cvss,
            },
            headers=collect_auth,
        )
        assert r.status_code == 200


@pytest.mark.anyio
async def test_opencve_webhook_batch(client, collect_auth):
    """Batch import multiple alerts."""
    r = await client.post(
        "/api/v1/opencve/webhook/batch",
        json=[
            {
                "cve_id": "CVE-2099-5001",
                "vendor": "linux",
                "product": "kernel",
                "title": "Batch CVE 1",
                "severity": "critical",
                "cvss_v3": 9.1,
            },
            {
                "cve_id": "CVE-2099-5002",
                "vendor": "linux",
                "product": "kernel",
                "title": "Batch CVE 2",
                "severity": "medium",
                "cvss_v3": 5.5,
            },
            {
                "cve_id": "CVE-2099-5003",
                "vendor": "apache",
                "product": "httpd",
                "title": "Batch CVE 3 KEV",
                "kev": True,
            },
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["imported"] == 3
    assert data["kev_propagated"] == 1


@pytest.mark.anyio
async def test_opencve_alerts_list(client, auth, collect_auth):
    """List alerts after ingestion."""
    # Ingest one first
    await client.post(
        "/api/v1/opencve/webhook",
        json={"cve_id": "CVE-2099-7001", "title": "Alert test", "cvss_v3": 7.0},
        headers=collect_auth,
    )
    r = await client.get("/api/v1/opencve/alerts?matched_only=false", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1


@pytest.mark.anyio
async def test_opencve_alerts_severity_filter(client, auth, collect_auth):
    """Filter alerts by severity."""
    await client.post(
        "/api/v1/opencve/webhook",
        json={"cve_id": "CVE-2099-7002", "title": "Critical", "cvss_v3": 9.9},
        headers=collect_auth,
    )
    r = await client.get(
        "/api/v1/opencve/alerts?severity=critical&matched_only=false",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_opencve_impact(client, auth):
    """CVE impact correlation."""
    r = await client.get("/api/v1/opencve/impact", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_opencve_impact_by_cve(client, auth):
    """Impact for a specific CVE."""
    r = await client.get("/api/v1/opencve/impact?cve_id=CVE-2099-9999", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_opencve_subscriptions_crud(client, auth):
    """Add and list subscriptions."""
    r = await client.post(
        "/api/v1/opencve/subscriptions",
        json={"vendor": "nginx", "product": "nginx"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    r = await client.get("/api/v1/opencve/subscriptions", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(s["vendor"] == "nginx" for s in items)
