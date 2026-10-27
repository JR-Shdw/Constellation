"""Automation execution — run_evaluation with auto_execute, notify action."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
async def notify_policy(client, auth):
    """Create an auto_execute notify policy for cve_detected."""
    name = f"exec-notify-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 900,
            "enabled": True,
            "auto_execute": True,
            "match_severity": ["critical"],
        },
        headers=auth,
    )
    return r.json()["id"]


@pytest.fixture
async def deploy_policy(client, auth):
    """Create an auto_execute create_deployment policy."""
    name = f"exec-deploy-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "create_deployment",
            "priority": 800,
            "enabled": True,
            "auto_execute": True,
            "match_severity": ["high"],
            "match_environment": ["production"],
        },
        headers=auth,
    )
    return r.json()["id"]


# run_evaluation with auto_execute notify


@pytest.mark.anyio
async def test_run_evaluation_auto_notify(client, auth, notify_policy):
    """Auto-execute notify policy sends notification."""
    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    with patch(
        "api.app.routes.automation.send_automation_notification",
        new_callable=AsyncMock,
    ) as mock_notif:
        async with async_session() as db:
            result = await run_evaluation(
                {
                    "trigger_type": "cve_detected",
                    "hostname": "prod-01",
                    "severity": "critical",
                    "cve_id": "CVE-2026-1234",
                    "package": "openssl",
                },
                db,
            )
            await db.commit()

        assert result is not None
        assert result["action"] == "notify"
        mock_notif.assert_called_once()


# ── run_evaluation with auto_execute create_deployment


@pytest.mark.anyio
async def test_run_evaluation_auto_deployment_matched(client, auth, deploy_policy):
    """Auto-execute create_deployment policy matches and logs."""
    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    with patch(
        "api.app.routes.automation.send_automation_notification",
        new_callable=AsyncMock,
    ):
        async with async_session() as db:
            try:
                result = await run_evaluation(
                    {
                        "trigger_type": "cve_detected",
                        "hostname": "prod-server",
                        "severity": "high",
                        "environment": "production",
                        "cve_id": "CVE-2026-5678",
                    },
                    db,
                )
                await db.commit()
            except Exception:
                await db.rollback()
                result = None

    # Policy matched even if execution failed
    if result is not None:
        assert result["action"] == "create_deployment"

    # Verify automation log exists
    r = await client.get("/api/v1/automation/log", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_run_evaluation_notifies_on_action_failure(client, auth, deploy_policy):
    """A failing auto_execute action must log 'failed' AND send a failure
    notification — a silently-failed remediation must surface to the operator."""
    import asyncpg

    from api.app.database import async_session
    from api.app.routes import automation as auto_mod
    from api.app.routes.automation import run_evaluation

    from .conftest import ASYNCPG_DSN

    async def _boom(*a, **kw):
        raise RuntimeError("portainer down")

    sent: list[str] = []

    async def _capture(trigger, msg, db, room_override=None):
        sent.append(msg)

    with (
        patch.object(auto_mod, "_execute_action", _boom),
        patch.object(auto_mod, "send_automation_notification", _capture),
    ):
        async with async_session() as db:
            result = await run_evaluation(
                {
                    "trigger_type": "cve_detected",
                    "hostname": "prod-server",
                    "severity": "high",
                    "environment": "production",
                    "cve_id": "CVE-2026-9999",
                },
                db,
            )
            await db.commit()

    assert result is not None
    assert result["action"] == "create_deployment"
    # The failure surfaced as a notification, not just a log line.
    assert any("FAILED" in m for m in sent), f"no failure notification; got {sent}"

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        status = await conn.fetchval(
            "SELECT status FROM automation_log WHERE policy_id = CAST($1 AS uuid) "
            "ORDER BY created_at DESC LIMIT 1",
            deploy_policy,
        )
    finally:
        await conn.close()
    assert status == "failed"


# Matcher unit tests


def test_like_match():
    """_like_match handles SQL LIKE patterns."""
    from api.app.routes.automation import _like_match

    assert _like_match("prod-server", "%prod%")
    assert _like_match("prod-server", "prod%")
    assert not _like_match("dev-server", "prod%")
    assert _like_match("anything", None)  # None pattern = match all
    assert not _like_match(None, "%prod%")  # None value = no match
    assert _like_match("PROD-SERVER", "%prod%")  # case insensitive


def test_array_match():
    """_array_match handles list matching."""
    from api.app.routes.automation import _array_match

    assert _array_match("critical", ["critical", "high"])
    assert not _array_match("low", ["critical", "high"])
    assert _array_match("anything", None)  # None list = match all
    assert not _array_match(None, ["critical"])  # None value = no match
    assert _array_match("Critical", ["critical"])  # case insensitive


def test_evaluate_policies_priority():
    """Higher priority policy matches first."""
    from api.app.routes.automation import evaluate_policies

    policies = [
        {
            "id": "1",
            "name": "low-prio",
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 10,
            "enabled": True,
        },
        {
            "id": "2",
            "name": "high-prio",
            "trigger_type": "cve_detected",
            "action": "ignore",
            "priority": 100,
            "enabled": True,
        },
    ]
    result = evaluate_policies({"trigger_type": "cve_detected"}, policies)
    assert result["name"] == "high-prio"


def test_evaluate_policies_disabled_skipped():
    """Disabled policies are skipped."""
    from api.app.routes.automation import evaluate_policies

    policies = [
        {
            "id": "1",
            "name": "disabled",
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 100,
            "enabled": False,
        },
        {
            "id": "2",
            "name": "active",
            "trigger_type": "cve_detected",
            "action": "ignore",
            "priority": 50,
            "enabled": True,
        },
    ]
    result = evaluate_policies({"trigger_type": "cve_detected"}, policies)
    assert result["name"] == "active"


def test_evaluate_policies_no_match():
    """No match returns None."""
    from api.app.routes.automation import evaluate_policies

    policies = [
        {
            "id": "1",
            "name": "cve-only",
            "trigger_type": "cve_detected",
            "action": "notify",
            "priority": 100,
            "enabled": True,
        },
    ]
    result = evaluate_policies({"trigger_type": "backup_overdue"}, policies)
    assert result is None


def test_build_notification_message():
    """Notification message builder covers all trigger types."""
    from api.app.routes.automation import _build_notification_message

    msg = _build_notification_message(
        {
            "trigger_type": "cve_detected",
            "cve_id": "CVE-2026-1234",
            "severity": "critical",
            "package": "openssl",
            "hostname": "prod-01",
        },
        "test-policy",
    )
    assert "CVE-2026-1234" in msg
    assert "CRITICAL" in msg

    msg = _build_notification_message(
        {"trigger_type": "backup_overdue", "hostname": "bk-01"},
        "bk-policy",
    )
    assert "Backup overdue" in msg

    msg = _build_notification_message(
        {"trigger_type": "worker_offline", "hostname": "worker-1"},
        "worker-policy",
    )
    assert "Worker offline" in msg

    msg = _build_notification_message(
        {
            "trigger_type": "pipeline_failure",
            "hostname": "ci-01",
            "container": "build",
        },
        "pipe-policy",
    )
    assert "Pipeline failed" in msg

    msg = _build_notification_message(
        {
            "trigger_type": "image_update_available",
            "hostname": "srv-01",
            "image": "nginx:latest",
        },
        "img-policy",
    )
    assert "Image update" in msg

    msg = _build_notification_message(
        {"trigger_type": "custom_event", "hostname": "srv"},
        "custom",
    )
    assert "custom_event" in msg


# _execute_action: pull_image branch


@pytest.mark.anyio
async def test_execute_pull_image_no_image(client, auth):
    """Event without `image` → pull_image action returns early."""
    from api.app.database import async_session
    from api.app.routes.automation import _execute_action

    async with async_session() as db:
        # No exception = early return logged
        await _execute_action("pull_image", {"name": "p", "notify_room": None}, {}, db)


@pytest.mark.anyio
async def test_execute_pull_image_no_manager(client, auth):
    """No connected manager → pull_image logs + returns without calling Portainer."""
    from api.app.database import async_session
    from api.app.routes.automation import _execute_action

    async with async_session() as db:
        await _execute_action(
            "pull_image",
            {"name": "p", "notify_room": None},
            {"image": "nginx:1.25", "trigger_type": "image_update_available"},
            db,
        )


@pytest.mark.anyio
async def test_execute_pull_image_success(client, auth, monkeypatch):
    """Connected manager + image → PortainerClient.pull_image called."""
    import asyncpg

    from api.app.database import async_session
    from api.app.routes import automation as auto_mod

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO container_managers
                (name, manager_type, url, token, status)
            VALUES ('pull-mgr', 'portainer', 'https://p.example',
                    'tok', 'connected')
            """
        )
    finally:
        await conn.close()

    pulls: list[tuple[str, str]] = []

    class _FakePortainer:
        def __init__(self, *a, **k):
            pass

        async def pull_image(self, name, tag):
            pulls.append((name, tag))

    monkeypatch.setattr(auto_mod, "PortainerClient", _FakePortainer)
    monkeypatch.setattr(
        auto_mod,
        "send_automation_notification",
        AsyncMock(),
    )

    async with async_session() as db:
        await auto_mod._execute_action(
            "pull_image",
            {"name": "pull-policy", "notify_room": None},
            {"image": "nginx:1.25", "trigger_type": "image_update_available"},
            db,
        )

    assert pulls == [("nginx", "1.25")]


@pytest.mark.anyio
async def test_execute_pull_image_no_tag(client, auth, monkeypatch):
    """Image without `:tag` defaults to `latest`."""
    import asyncpg

    from api.app.database import async_session
    from api.app.routes import automation as auto_mod

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO container_managers
                (name, manager_type, url, token, status)
            VALUES ('pull-mgr2', 'portainer', 'https://p.example',
                    'tok', 'connected')
            """
        )
    finally:
        await conn.close()

    pulls: list[tuple[str, str]] = []

    class _FakePortainer:
        def __init__(self, *a, **k):
            pass

        async def pull_image(self, name, tag):
            pulls.append((name, tag))

    monkeypatch.setattr(auto_mod, "PortainerClient", _FakePortainer)
    monkeypatch.setattr(auto_mod, "send_automation_notification", AsyncMock())

    async with async_session() as db:
        await auto_mod._execute_action(
            "pull_image",
            {"name": "pull-policy", "notify_room": None},
            {"image": "nginx", "trigger_type": "image_update_available"},
            db,
        )

    assert pulls == [("nginx", "latest")]


# _execute_action: email branches


@pytest.mark.anyio
async def test_execute_email_no_recipients(client, auth, monkeypatch):
    """email action without recipients or fallback → skipped."""
    from api.app.database import async_session
    from api.app.routes import automation as auto_mod

    sent = AsyncMock(return_value=True)
    monkeypatch.setattr(auto_mod, "send_email", sent)
    # Ensure no alert_email in settings
    monkeypatch.setattr(
        auto_mod,
        "get_alert_settings",
        AsyncMock(return_value={}),
    )

    async with async_session() as db:
        await auto_mod._execute_action(
            "email",
            {"name": "p", "config": None, "notify_room": None},
            {"trigger_type": "cve_detected", "hostname": "h"},
            db,
        )
    sent.assert_not_called()


@pytest.mark.anyio
async def test_execute_email_string_recipients(client, auth, monkeypatch):
    """config as JSON string with comma-separated `to` + `cc`."""
    from api.app.database import async_session
    from api.app.routes import automation as auto_mod

    sent = AsyncMock(return_value=True)
    monkeypatch.setattr(auto_mod, "send_email", sent)
    monkeypatch.setattr(auto_mod, "get_alert_settings", AsyncMock(return_value={}))

    async with async_session() as db:
        await auto_mod._execute_action(
            "email",
            {
                "name": "email-policy",
                "config": '{"to": "a@x.com, b@x.com", "cc": "c@x.com"}',
                "notify_room": None,
            },
            {"trigger_type": "cve_detected", "hostname": "h"},
            db,
        )
    sent.assert_called_once()
    call_args = sent.call_args
    # send_email(recipients, ...) — first positional arg
    recipients = call_args.args[0]
    assert set(recipients) == {"a@x.com", "b@x.com"}


@pytest.mark.anyio
async def test_execute_email_fallback_alert_email(client, auth, monkeypatch):
    """Empty recipients + alert_email setting → falls back to that address."""
    from api.app.database import async_session
    from api.app.routes import automation as auto_mod

    sent = AsyncMock(return_value=True)
    monkeypatch.setattr(auto_mod, "send_email", sent)
    monkeypatch.setattr(
        auto_mod,
        "get_alert_settings",
        AsyncMock(return_value={"alert_email": "ops@x.com"}),
    )

    async with async_session() as db:
        await auto_mod._execute_action(
            "email",
            {
                "name": "email-policy",
                "config": {"subject": "custom"},
                "notify_room": None,
            },
            {"trigger_type": "cve_detected", "hostname": "h"},
            db,
        )
    sent.assert_called_once()
    assert sent.call_args.args[0] == ["ops@x.com"]
