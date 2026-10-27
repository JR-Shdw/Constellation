"""Auth tests — token validation, Remote-User trust."""

import pytest


@pytest.mark.anyio
async def test_collect_without_token_returns_401(client):
    r = await client.post("/api/v1/nodes/report", json={"hostname": "test"})
    assert r.status_code == 401


@pytest.mark.anyio
async def test_collect_with_bad_token_returns_401(client):
    r = await client.post(
        "/api/v1/nodes/report",
        json={"hostname": "test"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_read_without_auth_returns_401(client):
    r = await client.get("/api/v1/nodes")
    assert r.status_code == 401


@pytest.mark.anyio
async def test_read_with_bearer_token(client, auth):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200


@pytest.mark.anyio
async def test_read_with_remote_user_from_trusted_proxy():
    """Remote-User from Docker network (Traefik) is accepted."""
    from fastapi import Request

    from api.app.auth import _is_trusted_proxy

    scope = {
        "type": "http",
        "headers": [(b"remote-user", b"testuser")],
        "client": ("172.16.10.2", 54321),
    }
    request = Request(scope)
    assert _is_trusted_proxy(request) is True
    assert request.headers.get("Remote-User") == "testuser"


@pytest.mark.anyio
async def test_read_with_remote_user_from_untrusted_ip():
    """Remote-User from WireGuard direct is rejected."""
    from fastapi import Request

    from api.app.auth import _is_trusted_proxy

    scope = {
        "type": "http",
        "headers": [(b"remote-user", b"testuser")],
        "client": ("192.0.2.10", 54321),
    }
    request = Request(scope)
    assert _is_trusted_proxy(request) is False
