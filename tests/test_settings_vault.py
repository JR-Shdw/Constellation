"""Settings vault coverage — vault secrets endpoint, cache invalidation."""

import pytest


@pytest.mark.anyio
async def test_vault_secrets_not_configured(client, auth):
    """Vault secrets when not configured returns not_configured status."""
    r = await client.get("/api/v1/settings/vault/secrets", headers=auth)
    assert r.status_code == 200
    data = r.json()
    # In test env, vault is not configured
    assert data["configured"] is False
    for s in data["secrets"]:
        assert s["status"] == "not_configured"


@pytest.mark.anyio
async def test_vault_secrets_has_all_mappings(client, auth):
    """Vault secrets endpoint returns all 8 mapped secrets."""
    r = await client.get("/api/v1/settings/vault/secrets", headers=auth)
    assert r.status_code == 200
    secrets = r.json()["secrets"]
    assert len(secrets) == 8
    names = {s["vault_name"] for s in secrets}
    assert "cmdb-secret-key" in names
    assert "cmdb-collect-token" in names
    assert "cmdb-woodpecker-token" in names


@pytest.mark.anyio
async def test_vault_status_endpoint(client, auth):
    """Vault status endpoint returns structured response."""
    r = await client.get("/api/v1/settings/vault/status", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "configured" in data
    assert "sealed" in data
    assert "url" in data


@pytest.mark.anyio
async def test_vault_check_valid_format(client, auth):
    """Vault check with unreachable URL returns error status."""
    r = await client.post(
        "/api/v1/settings/vault-check",
        json={"vault_url": "http://127.0.0.1:19999"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_save_vault_settings(client, auth):
    """Save vault_url and vault_token in settings."""
    r = await client.put(
        "/api/v1/settings/alerts",
        json={
            "vault_url": "http://test-vault:8200",
            "vault_token": "rh_test_token",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["updated"] >= 1

    # Clean up
    await client.put(
        "/api/v1/settings/alerts",
        json={"vault_url": "", "vault_token": ""},
        headers=auth,
    )
