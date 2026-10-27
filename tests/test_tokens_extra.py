"""Extra token tests — full CRUD lifecycle."""

import pytest


@pytest.mark.anyio
async def test_token_full_lifecycle(client, auth):
    """Create, list, deactivate, activate, regenerate, delete token."""
    # Create
    r = await client.post(
        "/api/v1/tokens",
        json={
            "name": "lifecycle-test",
            "permissions": {"read": "r", "backup": "r"},
        },
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "lifecycle-test"
    token_id = data["id"]
    raw_token = data["token"]

    # List
    r = await client.get("/api/v1/tokens", headers=auth)
    assert r.status_code == 200
    tokens = r.json()["items"]
    found = [t for t in tokens if t["id"] == token_id]
    assert len(found) == 1
    assert found[0]["active"] is True
    # Token value should NOT be in list response
    assert "token" not in found[0] or found[0].get("token") is None

    # Use the token for a read
    r = await client.get(
        "/api/v1/nodes/list",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code == 200

    # Revoke (deactivate)
    r = await client.post(f"/api/v1/tokens/{token_id}/revoke", headers=auth)
    assert r.status_code == 200

    # Revoked token should fail
    r = await client.get(
        "/api/v1/nodes/list",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code == 401

    # Activate
    r = await client.post(f"/api/v1/tokens/{token_id}/activate", headers=auth)
    assert r.status_code == 200

    # Regenerate
    r = await client.post(f"/api/v1/tokens/{token_id}/regenerate", headers=auth)
    assert r.status_code == 200
    new_token = r.json()["token"]
    assert new_token != raw_token

    # Old token should fail
    r = await client.get(
        "/api/v1/nodes/list",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code == 401

    # New token should work
    r = await client.get(
        "/api/v1/nodes/list",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert r.status_code == 200

    # Delete
    r = await client.delete(f"/api/v1/tokens/{token_id}", headers=auth)
    assert r.status_code == 200

    # Verify deleted
    r = await client.get("/api/v1/tokens", headers=auth)
    tokens = r.json()["items"]
    assert token_id not in [t["id"] for t in tokens]


@pytest.mark.anyio
async def test_token_permission_enforcement(client, auth):
    """Token with limited scope cannot access other scopes."""
    # Create token with only backup read access
    r = await client.post(
        "/api/v1/tokens",
        json={
            "name": "scope-test",
            "permissions": {"backup": "r"},
        },
        headers=auth,
    )
    raw_token = r.json()["token"]
    token_id = r.json()["id"]
    tok_auth = {"Authorization": f"Bearer {raw_token}"}

    # Can read backup
    r = await client.get("/api/v1/backup/summary", headers=tok_auth)
    assert r.status_code == 200

    # Cannot read nodes (no 'read' scope)
    r = await client.get("/api/v1/nodes/list", headers=tok_auth)
    assert r.status_code in (401, 403)

    # Cannot write backup (only 'r' mode)
    r = await client.post(
        "/api/v1/backup/report",
        json={"hostname": "x", "repo_name": "x", "status": "success"},
        headers=tok_auth,
    )
    assert r.status_code in (401, 403)

    # Cleanup
    await client.delete(f"/api/v1/tokens/{token_id}", headers=auth)
