"""ITSM integrations CRUD + inbound webhook HMAC verification."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.anyio
async def test_create_integration_generates_webhook_secret_when_inbound(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "glpi-test",
            "platform": "glpi",
            "base_url": "https://glpi.example.com",
            "auth_config": {"app_token": "a", "user_token": "u"},
            "sync_inbound": True,
        },
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["webhook_secret"] is not None
    assert len(data["webhook_secret"]) >= 20


@pytest.mark.anyio
async def test_list_integrations_masks_secret(client, auth):
    await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "jira-test",
            "platform": "jira",
            "base_url": "https://example.atlassian.net",
            "auth_config": {"email": "a@b.c", "api_token": "t"},
            "project_key": "INC",
            "sync_inbound": True,
        },
        headers=auth,
    )
    r = await client.get("/api/v1/itsm/integrations", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    it = items[0]
    assert "webhook_secret" not in it
    assert it["has_webhook_secret"] is True


@pytest.mark.anyio
async def test_unknown_platform_rejected(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "bad",
            "platform": "servicenow",
            "base_url": "https://x",
            "auth_config": {},
        },
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_patch_integration(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "zammad-test",
            "platform": "zammad",
            "base_url": "https://zammad.example.com",
            "auth_config": {"token": "z"},
        },
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.patch(
        f"/api/v1/itsm/integrations/{iid}",
        json={"enabled": False},
        headers=auth,
    )
    assert r2.status_code == 200
    r3 = await client.get(f"/api/v1/itsm/integrations/{iid}", headers=auth)
    assert r3.json()["enabled"] is False


@pytest.mark.anyio
async def test_delete_integration(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "todel",
            "platform": "glpi",
            "base_url": "https://x",
            "auth_config": {},
        },
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.delete(f"/api/v1/itsm/integrations/{iid}", headers=auth)
    assert r2.status_code == 200
    r3 = await client.get(f"/api/v1/itsm/integrations/{iid}", headers=auth)
    assert r3.status_code == 404


@pytest.mark.anyio
async def test_inbound_rejects_without_signature(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "jira-inbound",
            "platform": "jira",
            "base_url": "https://example.atlassian.net",
            "auth_config": {"email": "a@b.c", "api_token": "t"},
            "project_key": "INC",
            "sync_inbound": True,
        },
        headers=auth,
    )
    iid = r.json()["id"]
    payload = {"issue": {"key": "INC-1", "fields": {"status": {"name": "Done"}}}}
    r2 = await client.post(
        f"/api/v1/webhooks/itsm/{iid}",
        content=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )
    assert r2.status_code == 401


@pytest.mark.anyio
async def test_inbound_rejects_when_sync_inbound_off(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "outbound-only",
            "platform": "jira",
            "base_url": "https://x",
            "auth_config": {"email": "a@b.c", "api_token": "t"},
            "project_key": "INC",
            "sync_inbound": False,
        },
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.post(
        f"/api/v1/webhooks/itsm/{iid}",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "X-CMDB-Signature": "sha256=deadbeef",
        },
    )
    assert r2.status_code == 403


@pytest.mark.anyio
async def test_inbound_accepts_valid_hmac_but_no_ticket(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "jira-valid",
            "platform": "jira",
            "base_url": "https://example.atlassian.net",
            "auth_config": {"email": "a@b.c", "api_token": "t"},
            "project_key": "INC",
            "sync_inbound": True,
        },
        headers=auth,
    )
    iid = r.json()["id"]
    secret = r.json()["webhook_secret"]

    body = json.dumps(
        {"issue": {"key": "INC-UNLINKED", "fields": {"status": {"name": "Done"}}}}
    ).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    r2 = await client.post(
        f"/api/v1/webhooks/itsm/{iid}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-CMDB-Signature": f"sha256={sig}",
        },
    )
    assert r2.status_code == 200
    data = r2.json()
    assert data["ok"] is False
    assert "not linked" in data["error"].lower()


@pytest.mark.anyio
async def test_get_integration_returns_masked_secret(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "glpi-detail",
            "platform": "glpi",
            "base_url": "https://glpi.example.com",
            "auth_config": {"app_token": "a", "user_token": "u"},
            "sync_inbound": True,
        },
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.get(f"/api/v1/itsm/integrations/{iid}", headers=auth)
    assert r2.status_code == 200
    body = r2.json()
    assert "webhook_secret" not in body
    assert body["has_webhook_secret"] is True


@pytest.mark.anyio
async def test_get_integration_not_found(client, auth):
    import uuid

    r = await client.get(f"/api/v1/itsm/integrations/{uuid.uuid4()}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_patch_integration_not_found(client, auth):
    import uuid

    r = await client.patch(
        f"/api/v1/itsm/integrations/{uuid.uuid4()}",
        json={"enabled": False},
        headers=auth,
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_patch_integration_empty_body_rejected(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "to-patch",
            "platform": "glpi",
            "base_url": "https://x",
            "auth_config": {},
        },
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.patch(f"/api/v1/itsm/integrations/{iid}", json={}, headers=auth)
    assert r2.status_code == 400


@pytest.mark.anyio
async def test_delete_integration_not_found(client, auth):
    import uuid

    r = await client.delete(f"/api/v1/itsm/integrations/{uuid.uuid4()}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_test_integration_endpoint_ok(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "jira-test-ok",
            "platform": "jira",
            "base_url": "https://x",
            "auth_config": {"email": "a@b.c", "api_token": "t"},
            "project_key": "INC",
        },
        headers=auth,
    )
    iid = r.json()["id"]

    with patch(
        "api.app.connectors.jira.JiraConnector.test_connection",
        new=AsyncMock(return_value={"status": "ok", "info": "ok"}),
    ):
        r2 = await client.post(f"/api/v1/itsm/integrations/{iid}/test", headers=auth)
    assert r2.status_code == 200
    assert r2.json()["ok"] is True


@pytest.mark.anyio
async def test_test_integration_endpoint_failure(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "jira-test-fail",
            "platform": "jira",
            "base_url": "https://x",
            "auth_config": {"email": "a@b.c", "api_token": "t"},
            "project_key": "INC",
        },
        headers=auth,
    )
    iid = r.json()["id"]

    with patch(
        "api.app.connectors.jira.JiraConnector.test_connection",
        new=AsyncMock(side_effect=RuntimeError("auth failed")),
    ):
        r2 = await client.post(f"/api/v1/itsm/integrations/{iid}/test", headers=auth)
    assert r2.status_code == 200
    body = r2.json()
    assert body["ok"] is False
    assert "auth failed" in body["error"]


@pytest.mark.anyio
async def test_test_integration_not_found(client, auth):
    import uuid

    r = await client.post(
        f"/api/v1/itsm/integrations/{uuid.uuid4()}/test", headers=auth
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_inbound_invalid_json_rejected(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "glpi-inbound-bad",
            "platform": "glpi",
            "base_url": "https://x",
            "auth_config": {"app_token": "a", "user_token": "u"},
            "sync_inbound": True,
        },
        headers=auth,
    )
    iid = r.json()["id"]
    secret = r.json()["webhook_secret"]

    body = b"not-json{"
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    r2 = await client.post(
        f"/api/v1/webhooks/itsm/{iid}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-CMDB-Signature": f"sha256={sig}",
        },
    )
    assert r2.status_code == 400


@pytest.mark.anyio
async def test_inbound_integration_not_found(client):
    import uuid

    body = b"{}"
    r = await client.post(
        f"/api/v1/webhooks/itsm/{uuid.uuid4()}",
        content=body,
        headers={"X-CMDB-Signature": "sha256=00"},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_inbound_payload_without_id_returns_ok_false(client, auth):
    r = await client.post(
        "/api/v1/itsm/integrations",
        json={
            "name": "glpi-no-id",
            "platform": "glpi",
            "base_url": "https://x",
            "auth_config": {"app_token": "a", "user_token": "u"},
            "sync_inbound": True,
        },
        headers=auth,
    )
    iid = r.json()["id"]
    secret = r.json()["webhook_secret"]

    body = json.dumps({"foo": "bar"}).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    r2 = await client.post(
        f"/api/v1/webhooks/itsm/{iid}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-CMDB-Signature": f"sha256={sig}",
        },
    )
    assert r2.status_code == 200
    assert r2.json()["ok"] is False
