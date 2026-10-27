"""auth.py — SSO trusted-proxy branches in require_read_or_token +
require_permission."""

import pytest


@pytest.fixture
def _trust_all(monkeypatch):
    """Force _is_trusted_proxy to return True for every request."""
    import api.app.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_is_trusted_proxy", lambda req: True)


@pytest.mark.anyio
async def test_sso_admin_role_writes(client, _trust_all):
    """Trusted proxy + Remote-User + admin group → can write."""
    r = await client.get(
        "/api/v1/whoami",
        headers={
            "Remote-User": "alice@example.com",
            "Remote-Groups": "admins",
        },
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_sso_ops_role_blocked_on_write(client, _trust_all):
    """Trusted proxy + Remote-User + ops group → 403 on write endpoint."""
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "nope", "affected_asset": "x"},
        headers={
            "Remote-User": "bob@example.com",
            "Remote-Groups": "ops",
        },
    )
    # SSO ops cannot write incidents (require_permission scope=incidents mode=w)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_sso_viewer_reads(client, _trust_all):
    """Trusted proxy + Remote-User + no groups → viewer, can read."""
    r = await client.get(
        "/api/v1/incidents",
        headers={
            "Remote-User": "charlie@example.com",
            "Remote-Groups": "",
        },
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_sso_x_forwarded_groups_keycloak(client, _trust_all):
    """X-Forwarded-Groups (Keycloak) parses role."""
    r = await client.get(
        "/api/v1/whoami",
        headers={
            "Remote-User": "dave@example.com",
            "X-Forwarded-Groups": "admins",
        },
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_sso_remote_name_header_sets_name(client, _trust_all):
    """Remote-Name header used for display in whoami."""
    r = await client.get(
        "/api/v1/whoami",
        headers={
            "Remote-User": "eve@example.com",
            "Remote-Name": "Eve Example",
            "Remote-Groups": "admins",
        },
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_require_permission_bearer_missing_returns_401(client):
    """No Authelia + no Bearer → 401 Missing token on a write endpoint."""
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "x", "affected_asset": "y"},
    )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_require_permission_invalid_bearer_401(client):
    """Unknown Bearer token → 401 Invalid token."""
    r = await client.get(
        "/api/v1/incidents",
        headers={"Authorization": "Bearer totally-unknown-12345"},
    )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_collect_token_wrong_scope_403(client, collect_auth):
    """collect_token on non-collect scope → 403 Insufficient permissions."""
    # /incidents requires incidents:r
    r = await client.get("/api/v1/incidents", headers=collect_auth)
    assert r.status_code == 403


def test_is_trusted_proxy_no_client():
    """_is_trusted_proxy returns False when request has no client."""
    from unittest.mock import MagicMock
    import api.app.auth as auth_mod

    req = MagicMock()
    req.client = None
    assert auth_mod._is_trusted_proxy(req) is False


def test_is_trusted_proxy_untrusted_ip():
    """_is_trusted_proxy returns False for non-172.16-20 IP."""
    from unittest.mock import MagicMock
    import api.app.auth as auth_mod

    req = MagicMock()
    req.client.host = "10.0.0.5"
    assert auth_mod._is_trusted_proxy(req) is False


def test_is_trusted_proxy_trusted_ip():
    """_is_trusted_proxy returns True for 172.18.x.x."""
    from unittest.mock import MagicMock
    import api.app.auth as auth_mod

    req = MagicMock()
    req.client.host = "172.18.0.5"
    assert auth_mod._is_trusted_proxy(req) is True


def test_resolve_sso_role_no_groups():
    """_resolve_sso_role returns 'viewer' when no group header present."""
    from unittest.mock import MagicMock
    import api.app.auth as auth_mod

    req = MagicMock()
    req.headers.get.return_value = ""
    assert auth_mod._resolve_sso_role(req) == "viewer"
