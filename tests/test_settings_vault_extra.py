"""Settings — webhook CRUD lifecycle, vault status unconfigured."""

import uuid

import pytest

# Webhooks CRUD


@pytest.mark.anyio
async def test_webhook_create_list_delete(client, auth):
    """Webhook CRUD lifecycle."""
    name = f"wh-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/settings/webhooks",
        json={
            "name": name,
            "webhook_url": "https://hooks.example.com/test",
            "platform": "slack",
        },
        headers=auth,
    )
    assert r.status_code == 200
    wh_id = r.json()["id"]

    # List
    r = await client.get("/api/v1/settings/webhooks", headers=auth)
    assert r.status_code == 200
    assert any(w["id"] == wh_id for w in r.json()["items"])

    # Delete
    r = await client.delete(f"/api/v1/settings/webhooks/{wh_id}", headers=auth)
    assert r.status_code == 200


# Vault status (no vault configured)


@pytest.mark.anyio
async def test_vault_status_not_configured(client, auth):
    """Vault status when not configured."""
    r = await client.get("/api/v1/settings/vault/status", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "configured" in data
