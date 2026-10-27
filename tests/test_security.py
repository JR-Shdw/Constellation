"""Security tests — auth bypass, permission escalation, input validation,
token lifecycle, injection, header security, crypto."""

import pytest

# Auth Bypass Attempts


@pytest.mark.anyio
async def test_no_auth_header(client):
    """Endpoints reject requests without auth header."""
    endpoints = [
        ("GET", "/api/v1/nodes"),
        ("GET", "/api/v1/exposure"),
        ("GET", "/api/v1/compliance"),
        ("GET", "/api/v1/settings/alerts"),
        ("GET", "/api/v1/tokens"),
    ]
    for method, url in endpoints:
        r = await getattr(client, method.lower())(url)
        assert r.status_code == 401, f"{method} {url} should require auth"


@pytest.mark.anyio
async def test_empty_bearer(client):
    """Empty Bearer token is rejected."""
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": "Bearer "},
    )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_wrong_auth_scheme(client):
    """Basic auth scheme is rejected (only Bearer accepted)."""
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": "Basic dGVzdDp0ZXN0"},
    )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_forged_token(client):
    """Random token is rejected."""
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": "Bearer cmdb_totallyFakeToken12345"},
    )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_collect_token_cannot_read(client, collect_auth):
    """collect_token (.env) cannot access read endpoints."""
    r = await client.get("/api/v1/nodes", headers=collect_auth)
    assert r.status_code in (401, 403)


@pytest.mark.anyio
async def test_remote_user_from_untrusted_ip_rejected(client):
    """Remote-User header from non-Docker network is ignored."""
    r = await client.get(
        "/api/v1/nodes",
        headers={"Remote-User": "attacker"},
    )
    # httpx ASGITransport uses 127.0.0.1 — not in trusted proxies
    assert r.status_code == 401


# Permission Escalation


@pytest.mark.anyio
async def test_db_token_read_only(client, auth):
    """Create a read-only token, verify it cannot write."""
    # Create a reader token
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-reader", "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r.status_code == 200
    reader_token = r.json()["token"]
    reader_headers = {"Authorization": f"Bearer {reader_token}"}

    # Can read nodes
    r = await client.get("/api/v1/nodes", headers=reader_headers)
    assert r.status_code == 200

    # Cannot access settings (different scope)
    r = await client.get("/api/v1/settings/alerts", headers=reader_headers)
    assert r.status_code == 403

    # Cannot access tokens (different scope)
    r = await client.get("/api/v1/tokens", headers=reader_headers)
    assert r.status_code == 403

    # Cannot collect (write scope)
    r = await client.post(
        "/api/v1/nodes/report",
        json={"hostname": "evil"},
        headers=reader_headers,
    )
    assert r.status_code in (401, 403)


@pytest.mark.anyio
async def test_collect_token_scope_isolation(client, auth):
    """Collect-only token cannot read data or manage tokens."""
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-collector", "permissions": {"collect": "w"}},
        headers=auth,
    )
    assert r.status_code == 200
    collect_token = r.json()["token"]
    headers = {"Authorization": f"Bearer {collect_token}"}

    # Can collect
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "scope-test",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1",
            "packages": [],
            "containers": [],
        },
        headers=headers,
    )
    assert r.status_code == 200

    # Cannot read nodes
    r = await client.get("/api/v1/nodes", headers=headers)
    assert r.status_code == 403

    # Cannot manage tokens
    r = await client.get("/api/v1/tokens", headers=headers)
    assert r.status_code == 403


# Token Lifecycle Security


@pytest.mark.anyio
async def test_revoked_token_rejected(client, auth):
    """Revoked token cannot authenticate."""
    # Create
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-revokable", "permissions": {"read": "r"}},
        headers=auth,
    )
    token = r.json()["token"]
    token_id = r.json()["id"]

    # Works before revoke
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200

    # Revoke
    r = await client.post(f"/api/v1/tokens/{token_id}/revoke", headers=auth)
    assert r.status_code == 200

    # Rejected after revoke
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


@pytest.mark.anyio
async def test_regenerated_token_old_rejected(client, auth):
    """Old token value is invalid after regeneration."""
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-regen", "permissions": {"read": "r"}},
        headers=auth,
    )
    old_token = r.json()["token"]
    token_id = r.json()["id"]

    # Regenerate
    r = await client.post(f"/api/v1/tokens/{token_id}/regenerate", headers=auth)
    assert r.status_code == 200
    new_token = r.json()["token"]
    assert new_token != old_token

    # Old token rejected
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert r.status_code == 401

    # New token works
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_token_hash_never_exposed(client, auth):
    """Token hash is masked in all list/get responses."""
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-hash-check", "permissions": {"read": "r"}},
        headers=auth,
    )
    token_id = r.json()["id"]

    # List tokens
    r = await client.get("/api/v1/tokens", headers=auth)
    for item in r.json()["items"]:
        assert "token_hash" not in item
        if "token_hint" in item:
            assert item["token_hint"].endswith("...")

    # Get single token
    r = await client.get(f"/api/v1/tokens/{token_id}", headers=auth)
    data = r.json()
    assert "token_hash" not in data
    assert data["token_hint"].endswith("...")


@pytest.mark.anyio
async def test_duplicate_token_name_rejected(client, auth):
    """Cannot create two tokens with the same name."""
    name = "sec-unique-name"
    r = await client.post(
        "/api/v1/tokens",
        json={"name": name, "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r.status_code == 200

    r = await client.post(
        "/api/v1/tokens",
        json={"name": name, "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r.status_code == 409


# Input Validation


@pytest.mark.anyio
async def test_invalid_uuid_rejected(client, auth):
    """Non-UUID IDs return 400, not 500."""
    r = await client.get("/api/v1/nodes/not-a-uuid", headers=auth)
    assert r.status_code == 400


@pytest.mark.anyio
async def test_nonexistent_uuid_returns_empty(client, auth):
    """Valid UUID that doesn't exist returns 200 with empty/null data."""
    fake_uuid = "00000000-0000-0000-0000-000000000000"
    r = await client.get(f"/api/v1/nodes/{fake_uuid}", headers=auth)
    # Endpoint returns 200 with empty data (not 404)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_empty_token_name_rejected(client, auth):
    """Empty token name is rejected."""
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "", "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_invalid_permission_scope(client, auth):
    """Unknown permission scope is rejected."""
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-bad-scope", "permissions": {"hack": "rw"}},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_invalid_permission_mode(client, auth):
    """Invalid permission mode is rejected."""
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-bad-mode", "permissions": {"read": "x"}},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_no_permissions_rejected(client, auth):
    """Token with zero permissions is rejected."""
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-no-perms", "permissions": {}},
        headers=auth,
    )
    assert r.status_code == 400


# Security Headers


@pytest.mark.anyio
async def test_security_headers_present(client, auth):
    """API responses include security headers."""
    r = await client.get("/api/v1/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "strict-origin" in r.headers.get("Referrer-Policy", "")
    assert r.headers.get("Cache-Control") == "no-store"


@pytest.mark.anyio
async def test_swagger_disabled(client):
    """Swagger/ReDoc endpoints are disabled."""
    r = await client.get("/api/docs")
    assert r.status_code == 404

    r = await client.get("/api/redoc")
    assert r.status_code == 404

    r = await client.get("/api/v1/openapi.json")
    # FastAPI serves openapi.json at /openapi.json, not /api/v1/openapi.json
    # but /api/docs should be gone
    assert r.status_code in (404, 405)


# Settings Secret Masking


@pytest.mark.anyio
async def test_settings_secrets_masked(client, auth):
    """Secret keys in settings are masked in GET response."""
    from api.app.routes.settings import _SECRET_KEYS

    r = await client.get("/api/v1/settings/alerts", headers=auth)
    assert r.status_code == 200
    data = r.json()
    for key in _SECRET_KEYS:
        if key in data and data[key]:
            assert data[key] == "********", f"{key} should be masked"


@pytest.mark.anyio
async def test_settings_masked_value_not_overwritten(client, auth):
    """Sending '********' back doesn't overwrite the actual secret."""
    # Set a value first
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"matrix_token": "real-secret-token-123"},
        headers=auth,
    )
    assert r.status_code == 200

    # Now send masked value (simulates user saving without changing)
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"matrix_token": "********"},
        headers=auth,
    )
    assert r.status_code == 200

    # Verify internal value is still the real one (not "********")
    from sqlalchemy import text

    from api.app.crypto import decrypt_setting
    from api.app.database import async_session

    async with async_session() as db:
        row = await db.execute(
            text("SELECT value FROM alert_settings WHERE key = 'matrix_token'")
        )
        stored = row.scalar_one_or_none()
        if stored:
            decrypted = decrypt_setting(stored)
            assert decrypted == "real-secret-token-123"
            assert decrypted != "********"


# Crypto — Settings Encryption


@pytest.mark.anyio
async def test_settings_secrets_encrypted_in_db(client, auth):
    """Secret values are stored encrypted (enc: prefix) in DB."""
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"gitea_token": "ghp_test_token_12345"},
        headers=auth,
    )
    assert r.status_code == 200

    from sqlalchemy import text

    from api.app.database import async_session

    async with async_session() as db:
        row = await db.execute(
            text("SELECT value FROM alert_settings WHERE key = 'gitea_token'")
        )
        stored = row.scalar_one_or_none()
        assert stored is not None
        assert stored.startswith("enc:"), "Secret should be encrypted in DB"
        assert "ghp_test_token_12345" not in stored


@pytest.mark.anyio
async def test_crypto_encrypt_decrypt_roundtrip():
    """Encrypt then decrypt returns original value."""
    from api.app.crypto import decrypt_setting, encrypt_setting

    original = "super-secret-api-key-42"
    encrypted = encrypt_setting(original)
    assert encrypted.startswith("enc:")
    assert original not in encrypted

    decrypted = decrypt_setting(encrypted)
    assert decrypted == original


@pytest.mark.anyio
async def test_crypto_plaintext_passthrough():
    """decrypt_setting handles legacy plaintext (no enc: prefix)."""
    from api.app.crypto import decrypt_setting

    plaintext = "old-unencrypted-value"
    assert decrypt_setting(plaintext) == plaintext


@pytest.mark.anyio
async def test_crypto_empty_values():
    """Empty and None-like values pass through without error."""
    from api.app.crypto import decrypt_setting, encrypt_setting

    assert encrypt_setting("") == ""
    assert encrypt_setting("********") == ""  # masked value must never be stored
    assert decrypt_setting("") == ""


# SSO Role Resolution


@pytest.mark.anyio
async def test_sso_no_groups_defaults_to_viewer():
    """SSO user with no groups gets viewer role (least privilege)."""
    from unittest.mock import MagicMock

    from api.app.auth import _resolve_sso_role

    request = MagicMock()
    request.headers = MagicMock()
    request.headers.get = MagicMock(return_value="")

    role = _resolve_sso_role(request)
    assert role == "viewer"


@pytest.mark.anyio
async def test_sso_admin_group():
    """SSO user in 'admin' group gets admin role."""
    from unittest.mock import MagicMock

    from api.app.auth import _resolve_sso_role

    headers = {"Remote-Groups": "admin"}
    request = MagicMock()
    request.headers = MagicMock()
    request.headers.get = MagicMock(side_effect=lambda k, d="": headers.get(k, d))

    role = _resolve_sso_role(request)
    assert role == "admin"


@pytest.mark.anyio
async def test_sso_viewer_cannot_write(client, auth):
    """SSO viewer role cannot access write endpoints.

    Note: We test the permission check logic directly since
    ASGITransport uses 127.0.0.1 which is not a trusted proxy.
    """
    from api.app.auth import _check_permission

    # viewer has no write access
    assert _check_permission({"read": "r"}, "settings", "w") is False
    assert _check_permission({"read": "r"}, "read", "w") is False

    # admin has all access
    assert _check_permission({"admin": "rw"}, "settings", "w") is True
    assert _check_permission({"admin": "rw"}, "tokens", "w") is True


@pytest.mark.anyio
async def test_sso_highest_role_wins():
    """When user has multiple groups, highest priority role wins."""
    from unittest.mock import MagicMock

    from api.app.auth import _resolve_sso_role

    headers = {"Remote-Groups": "viewer,ops,admin"}
    request = MagicMock()
    request.headers = MagicMock()
    request.headers.get = MagicMock(side_effect=lambda k, d="": headers.get(k, d))

    role = _resolve_sso_role(request)
    assert role == "admin"


# HMAC Token Security


@pytest.mark.anyio
async def test_token_hash_deterministic():
    """Same token always produces same hash (HMAC consistency)."""
    from api.app.auth import hash_token

    token = "cmdb_test_deterministic_token"
    hash1 = hash_token(token)
    hash2 = hash_token(token)
    assert hash1 == hash2
    assert len(hash1) == 128  # SHA-512 hex = 128 chars


@pytest.mark.anyio
async def test_different_tokens_different_hashes():
    """Different tokens produce different hashes."""
    from api.app.auth import hash_token

    h1 = hash_token("cmdb_token_aaa")
    h2 = hash_token("cmdb_token_bbb")
    assert h1 != h2


# Audit Logging


@pytest.mark.anyio
async def test_audit_log_records_actions(client, auth):
    """Token creation is recorded in audit log."""
    # Create a token (generates audit entry)
    r = await client.post(
        "/api/v1/tokens",
        json={"name": "sec-audit-test", "permissions": {"read": "r"}},
        headers=auth,
    )
    assert r.status_code == 200

    # Check audit log
    from sqlalchemy import text

    from api.app.database import async_session

    async with async_session() as db:
        row = await db.execute(
            text("""
                SELECT action, target_type FROM audit_log
                WHERE action = 'create_token'
                ORDER BY created_at DESC LIMIT 1
            """)
        )
        entry = row.mappings().first()
        assert entry is not None
        assert entry["action"] == "create_token"
        assert entry["target_type"] == "api_token"


# Webhook URL Masking


@pytest.mark.anyio
async def test_webhook_url_masked_in_list(client, auth):
    """Webhook URLs are masked in GET responses."""
    # Create a webhook
    r = await client.post(
        "/api/v1/settings/webhooks",
        json={
            "name": "sec-wh-test",
            "platform": "generic",
            "webhook_url": "https://hooks.example.com/secret123",
        },
        headers=auth,
    )
    assert r.status_code == 200

    # List webhooks — URL should be masked
    r = await client.get("/api/v1/settings/webhooks", headers=auth)
    assert r.status_code == 200
    for item in r.json()["items"]:
        if item.get("webhook_url"):
            assert item["webhook_url"] == "********"


# Feature Toggle Safety


@pytest.mark.anyio
async def test_feature_toggle_requires_confirmation(client, auth):
    """Feature toggle requires typed confirmation string."""
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve", "enabled": False},
        headers=auth,
    )
    assert r.status_code == 400
    assert "Confirmation required" in r.json()["detail"]


@pytest.mark.anyio
async def test_feature_toggle_invalid_feature(client, auth):
    """Invalid feature name is rejected."""
    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "hack", "enabled": True, "confirm": "ENABLE HACK"},
        headers=auth,
    )
    assert r.status_code == 400


# Health Endpoint


@pytest.mark.anyio
async def test_health_no_auth_required(client):
    """Health endpoint works without authentication."""
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_health_no_sensitive_info(client):
    """Health endpoint doesn't leak sensitive information."""
    r = await client.get("/api/v1/health")
    data = r.json()
    # Should only return status, not DB details, config, or secrets
    assert set(data.keys()) == {"status"}
