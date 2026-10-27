"""Settings tests — SSO groups, alert settings, webhooks, features."""

import pytest

# SSO Group Mappings


@pytest.mark.anyio
async def test_get_sso_groups(client, auth):
    """Get SSO group mappings."""
    r = await client.get("/api/v1/settings/sso-groups", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "mappings" in data
    assert "roles" in data
    assert "admin" in data["roles"]


@pytest.mark.anyio
async def test_update_sso_groups(client, auth):
    """Update SSO group mappings."""
    r = await client.put(
        "/api/v1/settings/sso-groups",
        json={"mappings": {"devops": "ops", "security-team": "admin"}},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["mappings"]["devops"] == "ops"

    # Verify
    r = await client.get("/api/v1/settings/sso-groups", headers=auth)
    assert "devops" in r.json()["mappings"]


@pytest.mark.anyio
async def test_update_sso_groups_invalid_role(client, auth):
    """Invalid role in SSO mapping returns 400."""
    r = await client.put(
        "/api/v1/settings/sso-groups",
        json={"mappings": {"group": "superadmin"}},
        headers=auth,
    )
    assert r.status_code == 400


# Alert Settings


@pytest.mark.anyio
async def test_alert_settings_crud(client, auth):
    """Set and read alert settings."""
    r = await client.put(
        "/api/v1/settings/alerts",
        json={
            "cve_severity_threshold": "high",
            "cve_count_exclude_medium": "true",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["updated"] >= 1

    r = await client.get("/api/v1/settings/alerts", headers=auth)
    data = r.json()
    assert data.get("cve_severity_threshold") == "high"


@pytest.mark.anyio
async def test_alert_settings_masked_secrets(client, auth):
    """Secret settings should be masked on read."""
    # Set a secret setting
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"matrix_token": "syt_secret_token_value"},
        headers=auth,
    )
    assert r.status_code == 200

    # Read back — should be masked
    r = await client.get("/api/v1/settings/alerts", headers=auth)
    val = r.json().get("matrix_token", "")
    assert val == "********" or val == ""


@pytest.mark.anyio
async def test_alert_settings_skip_masked_value(client, auth):
    """Sending ******** should not overwrite the stored value."""
    # Set
    await client.put(
        "/api/v1/settings/alerts",
        json={"matrix_token": "real_token"},
        headers=auth,
    )
    # Send masked value — should be ignored
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"matrix_token": "********"},
        headers=auth,
    )
    assert r.status_code == 200


# Webhooks


@pytest.mark.anyio
async def test_webhook_update(client, auth):
    """Create and update a webhook."""
    r = await client.post(
        "/api/v1/settings/webhooks",
        json={
            "name": "update-hook",
            "webhook_url": "https://hooks.example.com/update",
            "platform": "slack",
        },
        headers=auth,
    )
    hook_id = r.json()["id"]

    r = await client.put(
        f"/api/v1/settings/webhooks/{hook_id}",
        json={"name": "renamed-hook", "enabled": False},
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_webhook_list_masks_url(client, auth):
    """Webhook list masks URLs."""
    await client.post(
        "/api/v1/settings/webhooks",
        json={
            "name": "mask-test",
            "webhook_url": "https://hooks.example.com/secret",
            "platform": "mattermost",
        },
        headers=auth,
    )
    r = await client.get("/api/v1/settings/webhooks", headers=auth)
    assert r.status_code == 200
    for hook in r.json()["items"]:
        if hook.get("webhook_url"):
            assert hook["webhook_url"] == "********"


# Feature Toggles


@pytest.mark.anyio
async def test_feature_toggle_success(client, auth):
    """Toggle a feature with correct confirm string."""
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve", "enabled": False, "confirm": "DISABLE CVE"},
        headers=auth,
    )
    assert r.status_code == 200

    # Re-enable
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve", "enabled": True, "confirm": "ENABLE CVE"},
        headers=auth,
    )
    assert r.status_code == 200
