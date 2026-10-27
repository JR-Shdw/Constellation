"""Managers CRUD tests — create, list, get, update, delete (no Portainer needed)."""

import uuid

import pytest


@pytest.fixture
async def manager_id(client, auth):
    """Create a manager and return its ID."""
    r = await client.post(
        "/api/v1/managers",
        json={
            "name": f"test-portainer-{uuid.uuid4().hex[:8]}",
            "manager_type": "portainer",
            "url": "https://portainer.example.com:9443",
            "token": "ptr_fake_token_for_testing",
            "endpoint_id": 1,
            "tls_skip_verify": False,
        },
        headers=auth,
    )
    assert r.status_code == 200
    return r.json()["id"]


@pytest.mark.anyio
async def test_create_manager(client, auth):
    """Create a container manager."""
    r = await client.post(
        "/api/v1/managers",
        json={
            "name": "portainer-host-b",
            "manager_type": "portainer",
            "url": "https://192.0.2.20:9443",
            "token": "ptr_secret",
            "endpoint_id": 2,
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "id" in r.json()


@pytest.mark.anyio
async def test_list_managers(client, auth, manager_id):
    """List managers returns items."""
    r = await client.get("/api/v1/managers", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
    assert len(r.json()["items"]) >= 1


@pytest.mark.anyio
async def test_get_manager(client, auth, manager_id):
    """Get single manager detail with masked token."""
    r = await client.get(f"/api/v1/managers/{manager_id}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["manager_type"] == "portainer"
    assert data["token"] == "***"


@pytest.mark.anyio
async def test_get_manager_not_found(client, auth):
    """Get nonexistent manager returns 404."""
    r = await client.get(f"/api/v1/managers/{uuid.uuid4()}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_update_manager(client, auth, manager_id):
    """Update manager fields."""
    r = await client.put(
        f"/api/v1/managers/{manager_id}",
        json={
            "name": "portainer-updated",
            "url": "https://192.0.2.20:9444",
            "endpoint_id": 3,
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_manager_empty(client, auth, manager_id):
    """Update with no fields returns changed=False."""
    r = await client.put(
        f"/api/v1/managers/{manager_id}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is False


@pytest.mark.anyio
async def test_update_manager_tls(client, auth, manager_id):
    """Update TLS skip verify flag."""
    r = await client.put(
        f"/api/v1/managers/{manager_id}",
        json={"tls_skip_verify": True},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_delete_manager(client, auth):
    """Delete a manager."""
    cr = await client.post(
        "/api/v1/managers",
        json={
            "name": f"delete-me-{uuid.uuid4().hex[:8]}",
            "manager_type": "portainer",
            "url": "https://example.com:9443",
        },
        headers=auth,
    )
    mid = cr.json()["id"]
    r = await client.delete(f"/api/v1/managers/{mid}", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_delete_manager_not_found(client, auth):
    """Delete nonexistent manager returns 404."""
    r = await client.delete(f"/api/v1/managers/{uuid.uuid4()}", headers=auth)
    assert r.status_code == 404
