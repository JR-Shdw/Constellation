"""Token CRUD tests — get, update, bulk revoke."""

import uuid

import pytest


@pytest.fixture
async def token_id(client, auth):
    """Create a token and return its ID."""
    name = f"crud-test-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/tokens",
        json={"name": name, "permissions": {"read": "r", "backup": "rw"}},
        headers=auth,
    )
    return r.json()["id"]


@pytest.mark.anyio
async def test_get_token(client, auth, token_id):
    """Get a single token by ID."""
    r = await client.get(f"/api/v1/tokens/{token_id}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == token_id
    assert "token_hint" in data
    assert "token_hash" not in data


@pytest.mark.anyio
async def test_get_token_not_found(client, auth):
    """Get nonexistent token returns 404."""
    fake = str(uuid.uuid4())
    r = await client.get(f"/api/v1/tokens/{fake}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_update_token_permissions(client, auth, token_id):
    """Update token permissions."""
    r = await client.put(
        f"/api/v1/tokens/{token_id}",
        json={"permissions": {"read": "rw", "cicd": "r"}},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_token_description(client, auth, token_id):
    """Update token description."""
    r = await client.put(
        f"/api/v1/tokens/{token_id}",
        json={"description": "Updated description"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_token_active(client, auth, token_id):
    """Toggle token active status."""
    r = await client.put(
        f"/api/v1/tokens/{token_id}",
        json={"active": False},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_token_empty(client, auth, token_id):
    """Update with no fields returns changed=False."""
    r = await client.put(
        f"/api/v1/tokens/{token_id}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is False


@pytest.mark.anyio
async def test_bulk_revoke_by_prefix(client, auth):
    """Bulk revoke tokens by name prefix."""
    prefix = f"bulk-{uuid.uuid4().hex[:6]}"
    for i in range(3):
        await client.post(
            "/api/v1/tokens",
            json={"name": f"{prefix}-{i}", "permissions": {"read": "r"}},
            headers=auth,
        )
    r = await client.post(
        "/api/v1/tokens/bulk/revoke",
        json={"prefix": prefix},
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 3
    assert data["action"] == "revoked"


@pytest.mark.anyio
async def test_bulk_revoke_no_filter_rejected(client, auth):
    """Bulk revoke without prefix or expired returns 400."""
    r = await client.post(
        "/api/v1/tokens/bulk/revoke",
        json={},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_bulk_delete_by_prefix(client, auth):
    """Bulk delete tokens (hard delete)."""
    prefix = f"del-{uuid.uuid4().hex[:6]}"
    for i in range(2):
        await client.post(
            "/api/v1/tokens",
            json={"name": f"{prefix}-{i}", "permissions": {"read": "r"}},
            headers=auth,
        )
    r = await client.post(
        "/api/v1/tokens/bulk/revoke",
        json={"prefix": prefix, "delete": True},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["action"] == "deleted"
