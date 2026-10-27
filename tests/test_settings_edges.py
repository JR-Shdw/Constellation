"""settings.py — small uncovered branches: webhook 404, empty body,
   vault-check HTTP non-200, feature-toggle notify failure."""

import uuid

import pytest


@pytest.mark.anyio
async def test_update_webhook_empty_body_returns_not_changed(client, auth):
    """Empty PUT → {status: ok, changed: False} (line 329)."""
    # Create a webhook first
    r0 = await client.post(
        "/api/v1/settings/webhooks",
        json={
            "name": f"wh-{uuid.uuid4().hex[:8]}",
            "platform": "mattermost",
            "webhook_url": "http://mm.example/hooks/abc",
        },
        headers=auth,
    )
    assert r0.status_code == 200
    wid = r0.json()["id"]

    r = await client.put(
        f"/api/v1/settings/webhooks/{wid}", json={}, headers=auth
    )
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "changed": False}


@pytest.mark.anyio
async def test_delete_webhook_404(client, auth):
    """DELETE non-existent webhook → 404 (line 371)."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.delete(
        f"/api/v1/settings/webhooks/{fake}", headers=auth
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_test_webhook_sends_message(client, auth, monkeypatch):
    """POST /webhooks/{id}/test hits _send_webhook (lines 401-407)."""
    import api.app.routes.settings as smod

    sent = []

    async def _fake_send(url, msg, platform, channel):
        sent.append((url, msg, platform, channel))

    monkeypatch.setattr(smod, "_send_webhook", _fake_send)

    r0 = await client.post(
        "/api/v1/settings/webhooks",
        json={
            "name": f"wh-t-{uuid.uuid4().hex[:8]}",
            "platform": "mattermost",
            "webhook_url": "http://mm.example/hooks/def",
            "default_channel": "ops",
        },
        headers=auth,
    )
    wid = r0.json()["id"]

    r = await client.post(
        f"/api/v1/settings/webhooks/{wid}/test", headers=auth
    )
    assert r.status_code == 200
    assert sent and "test" in sent[0][1].lower() or sent[0][1].startswith("[CMDB]")


@pytest.mark.anyio
async def test_test_webhook_404(client, auth):
    """POST test on non-existent webhook → 404 (line 399-400)."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.post(
        f"/api/v1/settings/webhooks/{fake}/test", headers=auth
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_vault_check_http_non_200(client, auth, monkeypatch):
    """Vault returns non-200 → last_err='HTTP ...' (line 544). Retries 3×."""
    import httpx

    class _Resp:
        status_code = 500

        def json(self):
            return {}

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    # Skip the sleeps between attempts
    import asyncio

    async def _nosleep(_):
        return None

    monkeypatch.setattr(asyncio, "sleep", _nosleep)

    r = await client.post(
        "/api/v1/settings/vault-check",
        json={"vault_url": "http://fake-vault"},
        headers=auth,
    )
    # Should return non-ok status after retries
    assert r.status_code in (200, 503)
    data = r.json()
    # detail mentions HTTP error
    if r.status_code == 200:
        assert "HTTP" in str(data) or "error" in str(data).lower()


@pytest.mark.anyio
async def test_feature_toggle_notification_error_swallowed(
    client, auth, monkeypatch
):
    """send_automation_notification raising during feature toggle → logged
    but toggle still returns OK (lines 500-501).

    Uses backup feature: disable → re-enable. Disable truncates backup tables;
    other tests in this suite don't depend on backup state, so this is safe.
    """
    import api.app.routes.settings as smod

    async def _boom(trigger, msg, db, **kw):
        raise RuntimeError("notif dead")

    monkeypatch.setattr(smod, "send_automation_notification", _boom)

    r = await client.post(
        "/api/v1/settings/features/toggle",
        json={
            "feature": "backup",
            "enabled": False,
            "confirm": "DISABLE BACKUP",
        },
        headers=auth,
    )
    assert r.status_code == 200
    r2 = await client.post(
        "/api/v1/settings/features/toggle",
        json={
            "feature": "backup",
            "enabled": True,
            "confirm": "ENABLE BACKUP",
        },
        headers=auth,
    )
    assert r2.status_code == 200
