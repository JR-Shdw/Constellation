"""Vault coverage — _vault_status, vault_status_detail, secrets endpoint."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# vault connector — _vault_status with shared-memory cache


@pytest.mark.anyio
async def test_vault_status_not_configured():
    """_vault_status returns None if vault_url is empty."""
    from api.app.connectors.vault import _vault_status, invalidate_cache

    invalidate_cache()
    with patch("api.app.connectors.vault.settings") as mock_s:
        mock_s.vault_url = ""
        mock_s.vault_token = ""
        result = await _vault_status()
        assert result is None


@pytest.mark.anyio
async def test_vault_status_uses_cache():
    """_vault_status returns cached result within TTL."""
    from api.app.connectors.vault import (
        _shm_write,
        _vault_status,
        invalidate_cache,
    )

    invalidate_cache()
    data = {"sealed": False, "version": "1.0"}
    _shm_write(data, time.monotonic())
    with patch("api.app.connectors.vault.settings") as mock_s:
        mock_s.vault_url = "http://vault:8200"
        mock_s.vault_token = "test"
        result = await _vault_status()
        assert result == {"sealed": False, "version": "1.0"}
    invalidate_cache()


@pytest.mark.anyio
async def test_vault_status_fetch_success():
    """_vault_status fetches from vault API and caches."""
    from api.app.connectors.vault import _vault_status, invalidate_cache

    invalidate_cache()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"sealed": False, "version": "0.5.0"}

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("api.app.connectors.vault.settings") as mock_s,
        patch("api.app.connectors.vault.httpx.AsyncClient", return_value=mock_client),
    ):
        mock_s.vault_url = "http://vault:8200"
        mock_s.vault_token = "test"
        result = await _vault_status()
        assert result["sealed"] is False
        assert result["version"] == "0.5.0"
    invalidate_cache()


@pytest.mark.anyio
async def test_vault_status_fetch_error_returns_stale_unsealed():
    """_vault_status returns stale cache only if last state was unsealed."""
    from api.app.connectors.vault import (
        _shm_write,
        _vault_status,
        invalidate_cache,
    )

    invalidate_cache()
    # Stale unsealed cache (recent enough to be within _STALE_MAX)
    _shm_write({"sealed": False}, time.monotonic() - 400)

    with (
        patch("api.app.connectors.vault.settings") as mock_s,
        patch(
            "api.app.connectors.vault.httpx.AsyncClient",
            side_effect=Exception("conn refused"),
        ),
    ):
        mock_s.vault_url = "http://vault:8200"
        mock_s.vault_token = "test"
        mock_s.database_url = "postgresql+asyncpg://x:x@localhost/x"
        result = await _vault_status()
        assert result == {"sealed": False}  # stale unsealed cache preserved
    invalidate_cache()


@pytest.mark.anyio
async def test_vault_status_fetch_error_sealed_not_stale():
    """_vault_status returns None when stale cache was sealed (don't perpetuate)."""
    from api.app.connectors.vault import (
        _shm_write,
        _vault_status,
        invalidate_cache,
    )

    invalidate_cache()
    # Stale sealed cache — should NOT be returned
    _shm_write({"sealed": True}, 0)

    with (
        patch("api.app.connectors.vault.settings") as mock_s,
        patch(
            "api.app.connectors.vault.httpx.AsyncClient",
            side_effect=Exception("conn refused"),
        ),
    ):
        mock_s.vault_url = "http://vault:8200"
        mock_s.vault_token = "test"
        mock_s.database_url = "postgresql+asyncpg://x:x@localhost/x"
        result = await _vault_status()
        assert result is None  # sealed stale not returned
    invalidate_cache()


@pytest.mark.anyio
async def test_vault_status_fetch_error_no_cache():
    """_vault_status returns None on error with no cache."""
    from api.app.connectors.vault import _vault_status, invalidate_cache

    invalidate_cache()
    with (
        patch("api.app.connectors.vault.settings") as mock_s,
        patch(
            "api.app.connectors.vault.httpx.AsyncClient",
            side_effect=Exception("conn refused"),
        ),
    ):
        mock_s.vault_url = "http://vault:8200"
        mock_s.vault_token = "test"
        mock_s.database_url = "postgresql+asyncpg://x:x@localhost/x"
        result = await _vault_status()
        assert result is None
    invalidate_cache()


# vault_status_detail


@pytest.mark.anyio
async def test_vault_status_detail_not_configured():
    """vault_status_detail returns configured=False."""
    from api.app.connectors.vault import vault_status_detail

    with patch("api.app.connectors.vault.settings") as mock_s:
        mock_s.vault_url = ""
        mock_s.vault_token = ""
        result = await vault_status_detail()
        assert result["configured"] is False
        assert result["sealed"] is None


@pytest.mark.anyio
async def test_vault_status_detail_unsealed():
    """vault_status_detail returns sealed=False with version."""
    from api.app.connectors.vault import invalidate_cache, vault_status_detail

    invalidate_cache()
    with (
        patch("api.app.connectors.vault.settings") as mock_s,
        patch(
            "api.app.connectors.vault._vault_status",
            new_callable=AsyncMock,
            return_value={"sealed": False, "version": "0.5.0", "second_factor": True},
        ),
    ):
        mock_s.vault_url = "http://vault:8200"
        mock_s.vault_token = "rh_test"
        result = await vault_status_detail()
        assert result["configured"] is True
        assert result["sealed"] is False
        assert result["version"] == "0.5.0"
        assert result["second_factor"] is True


@pytest.mark.anyio
async def test_vault_status_detail_unreachable():
    """vault_status_detail returns error when unreachable."""
    from api.app.connectors.vault import invalidate_cache, vault_status_detail

    invalidate_cache()
    with (
        patch("api.app.connectors.vault.settings") as mock_s,
        patch(
            "api.app.connectors.vault._vault_status",
            new_callable=AsyncMock,
            return_value=None,
        ),
    ):
        mock_s.vault_url = "http://vault:8200"
        mock_s.vault_token = "rh_test"
        result = await vault_status_detail()
        assert result["configured"] is True
        assert result["sealed"] is None
        assert result["error"] == "unreachable"


# API — vault secrets endpoint


@pytest.mark.anyio
async def test_vault_secrets_endpoint_returns_secrets(client, auth):
    """GET /settings/vault/secrets returns secrets list."""
    r = await client.get("/api/v1/settings/vault/secrets", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "configured" in data
    assert "secrets" in data
    assert len(data["secrets"]) == 8


@pytest.mark.anyio
async def test_vault_check_no_url(client, auth):
    """POST /settings/vault-check with empty URL returns 400."""
    r = await client.post(
        "/api/v1/settings/vault-check",
        json={"vault_url": ""},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_vault_check_unreachable(client, auth):
    """POST /settings/vault-check with bad URL returns error."""
    r = await client.post(
        "/api/v1/settings/vault-check",
        json={"vault_url": "http://127.0.0.1:19999"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"
