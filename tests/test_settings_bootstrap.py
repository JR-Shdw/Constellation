"""Settings vault bootstrap + discover + feature toggle coverage."""

import pytest


# Vault Bootstrap

@pytest.mark.anyio
async def test_vault_bootstrap_no_url(client, auth):
    """Bootstrap without vault URL returns 400."""
    r = await client.post(
        "/api/v1/settings/vault/bootstrap",
        json={},
        headers=auth,
    )
    assert r.status_code == 400
    assert "vault_url" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_vault_bootstrap_no_token(client, auth):
    """Bootstrap with URL but no token returns 400."""
    r = await client.post(
        "/api/v1/settings/vault/bootstrap",
        json={"vault_url": "http://fake:8200"},
        headers=auth,
    )
    assert r.status_code == 400
    assert "vault_token" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_vault_bootstrap_unreachable(client, auth):
    """Bootstrap with unreachable vault returns 503."""
    r = await client.post(
        "/api/v1/settings/vault/bootstrap",
        json={
            "vault_url": "http://127.0.0.1:19999",
            "vault_token": "rh_test",
        },
        headers=auth,
    )
    assert r.status_code == 503


# Vault Discover

@pytest.mark.anyio
async def test_vault_discover_not_found(client, auth):
    """Discover when no vault reachable returns not_found."""
    r = await client.post(
        "/api/v1/settings/vault/discover",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "not_found"


# Vault Check

@pytest.mark.anyio
async def test_vault_check_missing_url(client, auth):
    """Vault check without URL returns 400."""
    r = await client.post(
        "/api/v1/settings/vault-check",
        json={},
        headers=auth,
    )
    assert r.status_code == 400


# Feature Toggle

@pytest.mark.anyio
async def test_feature_toggle_invalid(client, auth):
    """Toggle unknown feature returns 400."""
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "invalid", "enabled": True, "confirm": "ENABLE INVALID"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_feature_toggle_missing_enabled(client, auth):
    """Toggle without enabled field returns 400."""
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_feature_toggle_already_enabled(client, auth):
    """Toggle CVE when already enabled returns already-state."""
    # CVE is enabled by default
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve", "enabled": True, "confirm": "ENABLE CVE"},
        headers=auth,
    )
    assert r.status_code == 200
    assert "already" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_feature_toggle_wrong_confirm(client, auth):
    """Toggle with wrong confirmation is rejected."""
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "backup", "enabled": False, "confirm": "wrong"},
        headers=auth,
    )
    assert r.status_code == 400
    assert "confirmation" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_feature_toggle_disable_enable(client, auth):
    """Full disable then enable cycle for backup feature."""
    # Disable
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "backup", "enabled": False, "confirm": "DISABLE BACKUP"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    # Re-enable
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "backup", "enabled": True, "confirm": "ENABLE BACKUP"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is True


# Webhook test

@pytest.mark.anyio
async def test_webhook_test_not_found(client, auth):
    """Test webhook with fake ID returns 404."""
    r = await client.post(
        "/api/v1/settings/webhooks/00000000-0000-0000-0000-000000000001/test",
        headers=auth,
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_webhook_test_invalid_uuid(client, auth):
    """Test webhook with invalid UUID returns 400."""
    r = await client.post(
        "/api/v1/settings/webhooks/not-a-uuid/test",
        headers=auth,
    )
    assert r.status_code == 400


# Vault bootstrap happy path + branches (mocked httpx)


class _VRes:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data or {}

    def json(self):
        return self._data


class _VClient:
    """Mocked async httpx client — responses keyed by (method, path)."""

    def __init__(self, routes: dict):
        self._routes = routes
        self.posts: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, path, headers=None):
        return self._routes[("GET", path)]

    async def post(self, path, json=None, headers=None):
        self.posts.append((path, json or {}))
        return self._routes[("POST", path)]


@pytest.mark.anyio
async def test_vault_bootstrap_happy_path(client, auth, monkeypatch):
    """Vault healthy + one secret exists + two created."""
    import httpx

    from api.app.routes import settings as settings_mod

    # /vault/status (unsealed), 3x GET /vault/secrets/<name>, 2x POST
    routes = {
        ("GET", "/api/v1/vault/status"): _VRes(200, {"sealed": False}),
        ("GET", "/api/v1/vault/secrets/cmdb-secret-key"): _VRes(200, {}),
        ("GET", "/api/v1/vault/secrets/cmdb-collect-token"): _VRes(404),
        ("GET", "/api/v1/vault/secrets/cmdb-token-hmac-key"): _VRes(404),
        ("POST", "/api/v1/vault/secrets"): _VRes(201, {}),
    }
    fake = _VClient(routes)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)
    # Also patch the alias imported inside the handler
    monkeypatch.setattr(settings_mod, "httpx", httpx, raising=False)

    r = await client.post(
        "/api/v1/settings/vault/bootstrap",
        json={"vault_url": "http://vault:8200", "vault_token": "tok"},
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["created"] == 2
    statuses = {x["status"] for x in data["results"]}
    assert "exists" in statuses and "created" in statuses


@pytest.mark.anyio
async def test_vault_bootstrap_sealed_returns_503(client, auth, monkeypatch):
    """Vault sealed → 503 raised."""
    import httpx

    routes = {
        ("GET", "/api/v1/vault/status"): _VRes(200, {"sealed": True}),
    }
    fake = _VClient(routes)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)

    r = await client.post(
        "/api/v1/settings/vault/bootstrap",
        json={"vault_url": "http://vault:8200", "vault_token": "tok"},
        headers=auth,
    )
    assert r.status_code == 503


@pytest.mark.anyio
async def test_vault_bootstrap_post_failure_recorded(client, auth, monkeypatch):
    """POST to create secret fails → status=error with HTTP detail."""
    import httpx

    routes = {
        ("GET", "/api/v1/vault/status"): _VRes(200, {"sealed": False}),
        ("GET", "/api/v1/vault/secrets/cmdb-secret-key"): _VRes(404),
        ("GET", "/api/v1/vault/secrets/cmdb-collect-token"): _VRes(404),
        ("GET", "/api/v1/vault/secrets/cmdb-token-hmac-key"): _VRes(404),
        ("POST", "/api/v1/vault/secrets"): _VRes(
            500, {"detail": "storage backend offline"}
        ),
    }
    fake = _VClient(routes)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: fake)

    r = await client.post(
        "/api/v1/settings/vault/bootstrap",
        json={"vault_url": "http://vault:8200", "vault_token": "tok"},
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["created"] == 0
    err = [x for x in data["results"] if x["status"] == "error"]
    assert err and "500" in err[0]["detail"]


# /vault/secrets status endpoint


@pytest.mark.anyio
async def test_vault_secrets_not_configured(client, auth):
    """Vault not configured → all statuses 'not_configured'."""
    r = await client.get("/api/v1/settings/vault/secrets", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["configured"] is False
    assert all(s["status"] == "not_configured" for s in data["secrets"])


@pytest.mark.anyio
async def test_vault_secrets_mixed_statuses(client, auth, monkeypatch):
    """Vault configured → mix of loaded / missing / error."""
    import httpx

    from api.app.connectors import vault as vault_mod
    from api.app.routes import settings as settings_mod

    # Each subsequent .get() pops from this list.
    responses = [
        _VRes(200),  # cmdb-secret-key → loaded (setting has value)
        _VRes(404),  # cmdb-collect-token → missing
        _VRes(500),  # cmdb-token-hmac-key → error
        _VRes(200),  # woodpecker
        _VRes(200),  # gitea
        _VRes(200),  # gitlab
        _VRes(200),  # forgejo
        _VRes(200),  # opencve
    ]

    class _SeqClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, path, headers=None):
            return responses.pop(0)

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _SeqClient())
    monkeypatch.setattr(vault_mod, "vault_configured", lambda: True)
    from api.app.config import settings as cfg

    monkeypatch.setattr(cfg, "vault_url", "http://vault:8200", raising=False)
    monkeypatch.setattr(cfg, "vault_token", "tok", raising=False)
    # secret_key is already populated from env ("test-secret-key"),
    # so the 200 response path should yield "loaded".
    assert settings_mod  # module imported, used via route

    r = await client.get("/api/v1/settings/vault/secrets", headers=auth)
    assert r.status_code == 200
    data = r.json()
    statuses = {s["vault_name"]: s["status"] for s in data["secrets"]}
    assert statuses["cmdb-secret-key"] == "loaded"
    assert statuses["cmdb-collect-token"] == "missing"
    assert statuses["cmdb-token-hmac-key"] == "error"


@pytest.mark.anyio
async def test_vault_secrets_outer_exception(client, auth, monkeypatch):
    """httpx.AsyncClient raising outside the loop → unreachable for all."""
    import httpx

    from api.app.connectors import vault as vault_mod

    def _boom(*a, **k):
        raise RuntimeError("hostname unknown")

    monkeypatch.setattr(httpx, "AsyncClient", _boom)
    monkeypatch.setattr(vault_mod, "vault_configured", lambda: True)
    from api.app.config import settings as cfg

    monkeypatch.setattr(cfg, "vault_url", "http://vault:8200", raising=False)
    monkeypatch.setattr(cfg, "vault_token", "tok", raising=False)

    r = await client.get("/api/v1/settings/vault/secrets", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "error" in data
    assert all(s["status"] == "unreachable" for s in data["secrets"])


# Vault check — success path + 200 with sealed true

class _CheckClient:
    def __init__(self, response):
        self._r = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, *a, **k):
        return self._r


@pytest.mark.anyio
async def test_vault_check_success_sealed(client, auth, monkeypatch):
    """200 response with sealed=true → status=ok, sealed=true."""
    import httpx

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda *a, **k: _CheckClient(_VRes(200, {"sealed": True})),
    )
    r = await client.post(
        "/api/v1/settings/vault-check",
        json={"vault_url": "http://v:8200"},
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data == {"status": "ok", "sealed": True}


@pytest.mark.anyio
async def test_vault_discover_finds_url(client, auth, monkeypatch):
    """First probed URL returns 200 → status=found + url + sealed."""
    import httpx

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda *a, **k: _CheckClient(_VRes(200, {"sealed": False})),
    )
    r = await client.post("/api/v1/settings/vault/discover", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "found"
    assert data["sealed"] is False
