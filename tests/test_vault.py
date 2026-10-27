"""Vault integration tests — client, guard, status endpoint."""

from unittest.mock import AsyncMock, patch

import pytest

# Vault connector unit tests


@pytest.mark.anyio
async def test_vault_not_configured():
    """When vault_url is empty, vault_is_unsealed returns True (legacy mode)."""
    from api.app.connectors.vault import vault_configured, vault_is_unsealed

    with patch("api.app.connectors.vault.settings") as mock_settings:
        mock_settings.vault_url = ""
        mock_settings.vault_token = ""
        assert not vault_configured()
        assert await vault_is_unsealed()


@pytest.mark.anyio
async def test_vault_configured_sealed():
    """When vault is configured but sealed, vault_is_unsealed returns False."""
    from api.app.connectors.vault import (
        VaultSealedError,
        invalidate_cache,
        require_vault_unsealed,
        vault_is_unsealed,
    )

    invalidate_cache()
    with (
        patch("api.app.connectors.vault.settings") as mock_settings,
        patch(
            "api.app.connectors.vault._vault_status",
            new_callable=AsyncMock,
        ) as mock_status,
    ):
        mock_settings.vault_url = "http://vault:8200"
        mock_settings.vault_token = "rh_test"
        mock_status.return_value = {"sealed": True}
        assert not await vault_is_unsealed()
        with pytest.raises(VaultSealedError):
            await require_vault_unsealed()


@pytest.mark.anyio
async def test_vault_configured_unsealed():
    """When vault is configured and unsealed, guard passes."""
    from api.app.connectors.vault import (
        invalidate_cache,
        require_vault_unsealed,
        vault_is_unsealed,
    )

    invalidate_cache()
    with (
        patch("api.app.connectors.vault.settings") as mock_settings,
        patch(
            "api.app.connectors.vault._vault_status",
            new_callable=AsyncMock,
        ) as mock_status,
    ):
        mock_settings.vault_url = "http://vault:8200"
        mock_settings.vault_token = "rh_test"
        mock_status.return_value = {"sealed": False}
        assert await vault_is_unsealed()
        await require_vault_unsealed()  # should not raise


@pytest.mark.anyio
async def test_vault_unreachable():
    """When vault is configured but unreachable, treat as sealed."""
    from api.app.connectors.vault import invalidate_cache, vault_is_unsealed

    invalidate_cache()
    with (
        patch("api.app.connectors.vault.settings") as mock_settings,
        patch(
            "api.app.connectors.vault._vault_status",
            new_callable=AsyncMock,
        ) as mock_status,
    ):
        mock_settings.vault_url = "http://vault:8200"
        mock_settings.vault_token = "rh_test"
        mock_status.return_value = None
        assert not await vault_is_unsealed()


# API endpoint tests


@pytest.mark.anyio
async def test_vault_status_endpoint(client, auth):
    """GET /settings/vault/status returns vault info."""
    r = await client.get("/api/v1/settings/vault/status", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "configured" in data


@pytest.mark.anyio
async def test_trigger_pipeline_vault_sealed(client, auth):
    """Pipeline trigger returns 503 when vault is sealed."""
    with patch(
        "api.app.routes.cicd.pipelines.require_vault_unsealed",
        side_effect=__import__(
            "api.app.connectors.vault", fromlist=["VaultSealedError"]
        ).VaultSealedError("sealed"),
    ):
        r = await client.post(
            "/api/v1/cicd/pipelines/trigger",
            json={"repo_name": "test/repo", "ci_system": "woodpecker"},
            headers=auth,
        )
        assert r.status_code == 503


@pytest.mark.anyio
async def test_deployment_preflight_vault_check(client, auth):
    """Preflight includes vault_unsealed check when configured."""
    import uuid

    # Create a deployment
    r = await client.post(
        "/api/v1/deployments",
        json={
            "title": f"vault-test-{uuid.uuid4().hex[:8]}",
            "deploy_type": "container_build",
            "worker_hostname": "test-worker",
            "repo_name": "test/repo",
            "branch": "main",
        },
        headers=auth,
    )
    dep_id = r.json()["id"]

    with (
        patch("api.app.connectors.vault.vault_configured", return_value=True),
        patch(
            "api.app.connectors.vault.vault_is_unsealed",
            new_callable=AsyncMock,
            return_value=False,
        ),
    ):
        r = await client.post(
            f"/api/v1/deployments/{dep_id}/preflight",
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        vault_check = next(
            (c for c in data["checks"] if c["check"] == "vault_unsealed"), None
        )
        assert vault_check is not None
        assert vault_check["ok"] is False
