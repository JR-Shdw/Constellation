"""Extra settings tests — read, write, features, webhooks."""

import pytest


@pytest.mark.anyio
async def test_get_alert_settings(client, auth):
    """Read alert settings."""
    r = await client.get("/api/v1/settings/alerts", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)


@pytest.mark.anyio
async def test_set_and_read_setting(client, auth):
    """Set a setting value and read it back."""
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"cve_count_exclude_low": "true"},
        headers=auth,
    )
    assert r.status_code == 200

    r = await client.get("/api/v1/settings/alerts", headers=auth)
    assert r.json().get("cve_count_exclude_low") == "true"


@pytest.mark.anyio
async def test_feature_toggle_requires_confirm(client, auth):
    """Toggle feature requires confirm string."""
    # Without confirm — should fail
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve", "enabled": False, "confirm": "wrong"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_feature_toggle_invalid_feature(client, auth):
    """Toggle invalid feature returns 400."""
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "invalid", "enabled": True, "confirm": "ENABLE INVALID"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_webhook_crud(client, auth):
    """Create, list, delete webhook."""
    # Create — needs WebhookCreate model fields
    r = await client.post(
        "/api/v1/settings/webhooks",
        json={
            "name": "test-hook",
            "webhook_url": "https://hooks.example.com/test",
            "platform": "mattermost",
        },
        headers=auth,
    )
    assert r.status_code == 200
    hook_id = r.json().get("id")

    # List
    r = await client.get("/api/v1/settings/webhooks", headers=auth)
    assert r.status_code == 200
    hooks = r.json()["items"]
    found = [h for h in hooks if h.get("name") == "test-hook"]
    assert len(found) >= 1

    # Delete
    if hook_id:
        r = await client.delete(f"/api/v1/settings/webhooks/{hook_id}", headers=auth)
        assert r.status_code == 200
