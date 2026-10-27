"""OpenCVE coverage — subscriptions CRUD, alerts list, webhook."""

import uuid

import pytest

# Subscriptions


@pytest.mark.anyio
async def test_list_subscriptions(client, auth):
    """List OpenCVE subscriptions."""
    r = await client.get("/api/v1/opencve/subscriptions", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_add_subscription(client, auth):
    """Add an OpenCVE subscription."""
    r = await client.post(
        "/api/v1/opencve/subscriptions",
        json={"vendor": "linux", "product": "linux_kernel"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


@pytest.mark.anyio
async def test_add_duplicate_subscription(client, auth):
    """Adding same subscription twice is idempotent."""
    vendor = f"dup-{uuid.uuid4().hex[:6]}"
    payload = {"vendor": vendor, "product": "test"}
    r1 = await client.post(
        "/api/v1/opencve/subscriptions",
        json=payload,
        headers=auth,
    )
    assert r1.status_code == 200
    r2 = await client.post(
        "/api/v1/opencve/subscriptions",
        json=payload,
        headers=auth,
    )
    assert r2.status_code == 200


@pytest.mark.anyio
async def test_subscription_appears_in_list(client, auth):
    """Added subscription appears in list."""
    vendor = f"list-{uuid.uuid4().hex[:6]}"
    await client.post(
        "/api/v1/opencve/subscriptions",
        json={"vendor": vendor, "product": "listtest"},
        headers=auth,
    )
    r = await client.get("/api/v1/opencve/subscriptions", headers=auth)
    items = r.json().get("items", [])
    found = any(s.get("vendor") == vendor for s in items)
    assert found


# Alerts


@pytest.mark.anyio
async def test_list_alerts(client, auth):
    """List OpenCVE alerts (may be empty)."""
    r = await client.get("/api/v1/opencve/alerts", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_list_alerts_filter_severity(client, auth):
    """Filter alerts by severity."""
    r = await client.get("/api/v1/opencve/alerts?severity=critical", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_list_alerts_pagination(client, auth):
    """Paginate alerts."""
    r = await client.get("/api/v1/opencve/alerts?page=1&per_page=10", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["items"]) <= 10


# Webhook


@pytest.mark.anyio
async def test_opencve_webhook(client, collect_auth):
    """OpenCVE webhook ingests alert data."""
    r = await client.post(
        "/api/v1/opencve/webhook",
        json={
            "type": "alert",
            "data": {
                "cve_id": "CVE-2026-9999",
                "title": "Test CVE",
                "description": "A test vulnerability",
                "metrics": {},
                "vendors": {"linux": ["linux_kernel"]},
            },
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_opencve_webhook_invalid_type(client, collect_auth):
    """OpenCVE webhook with unknown type still returns ok."""
    r = await client.post(
        "/api/v1/opencve/webhook",
        json={"type": "unknown", "data": {}},
        headers=collect_auth,
    )
    assert r.status_code == 200


# Impact


@pytest.mark.anyio
async def test_opencve_impact(client, auth):
    """Check CVE impact on infrastructure."""
    r = await client.get("/api/v1/opencve/impact?cve_id=CVE-2026-9999", headers=auth)
    assert r.status_code == 200
    assert "hosts" in r.json() or "items" in r.json() or "cve_id" in r.json()
