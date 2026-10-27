"""Email first-class action — notify.send_email + automation 'email' action."""

import uuid
from unittest.mock import MagicMock, patch

import pytest


# notify.send_email


@pytest.mark.anyio
async def test_send_email_no_host_returns_false():
    """Without smtp_host configured, send_email returns False without error."""
    from api.app.notify import send_email

    ok = await send_email(["a@b.c"], "subj", "body", {})
    assert ok is False


@pytest.mark.anyio
async def test_send_email_no_recipients_returns_false():
    """Empty recipient list returns False."""
    from api.app.notify import send_email

    ok = await send_email([], "subj", "body", {"smtp_host": "mail.example.org"})
    assert ok is False


@pytest.mark.anyio
async def test_send_email_starttls_path():
    """STARTTLS flow: SMTP + ehlo + starttls + login + send_message."""
    from api.app.notify import send_email

    fake = MagicMock()
    with patch("smtplib.SMTP", return_value=fake):
        ok = await send_email(
            ["ops@example.org"],
            "Hi",
            "body",
            {
                "smtp_host": "mail.example.org",
                "smtp_port": "587",
                "smtp_use_starttls": "true",
                "smtp_use_ssl": "false",
                "smtp_user": "u",
                "smtp_password": "p",
                "smtp_from": "cmdb@example.org",
                "smtp_from_name": "Constellation",
            },
        )
    assert ok is True
    fake.starttls.assert_called_once()
    fake.login.assert_called_once_with("u", "p")
    fake.send_message.assert_called_once()
    # From header includes display name when provided
    sent = fake.send_message.call_args[0][0]
    assert "Constellation" in sent["From"]
    assert "cmdb@example.org" in sent["From"]


@pytest.mark.anyio
async def test_send_email_implicit_tls_path():
    """Implicit TLS uses SMTP_SSL, skips starttls."""
    from api.app.notify import send_email

    fake = MagicMock()
    with patch("smtplib.SMTP_SSL", return_value=fake) as ssl_ctor:
        ok = await send_email(
            "ops@example.org",
            "Hi",
            "body",
            {
                "smtp_host": "mail.example.org",
                "smtp_port": "465",
                "smtp_use_starttls": "true",  # ignored when SSL on
                "smtp_use_ssl": "true",
            },
        )
    assert ok is True
    ssl_ctor.assert_called_once()
    fake.starttls.assert_not_called()
    fake.send_message.assert_called_once()


@pytest.mark.anyio
async def test_send_email_failure_returns_false_not_raise():
    """SMTP exceptions are swallowed — returns False."""
    from api.app.notify import send_email

    with patch("smtplib.SMTP", side_effect=OSError("connection refused")):
        ok = await send_email(
            ["a@b.c"],
            "s",
            "b",
            {"smtp_host": "dead.example.org"},
        )
    assert ok is False


@pytest.mark.anyio
async def test_send_email_cc_header():
    """cc list is set on the message when provided."""
    from api.app.notify import send_email

    fake = MagicMock()
    with patch("smtplib.SMTP", return_value=fake):
        await send_email(
            ["a@b.c"],
            "s",
            "b",
            {"smtp_host": "m.example.org", "smtp_use_starttls": "false"},
            cc=["c@b.c"],
        )
    sent = fake.send_message.call_args[0][0]
    assert "c@b.c" in sent["Cc"]


# automation 'email' action


@pytest.fixture
async def email_policy(client, auth):
    name = f"email-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "email",
            "priority": 950,
            "enabled": True,
            "auto_execute": True,
            "match_severity": ["critical"],
            "config": {
                "to": ["oncall@example.org"],
                "subject": "[{severity}] {cve_id} on {hostname}",
            },
        },
        headers=auth,
    )
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


@pytest.mark.anyio
async def test_email_action_dispatches_send_email(client, auth, email_policy):
    """run_evaluation dispatches to notify.send_email with templated subject."""
    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    with patch(
        "api.app.routes.automation.send_email",
        return_value=True,
    ) as mock_send:
        async with async_session() as db:
            result = await run_evaluation(
                {
                    "trigger_type": "cve_detected",
                    "hostname": "host-a",
                    "severity": "critical",
                    "cve_id": "CVE-2026-9999",
                    "package": "openssl",
                },
                db,
            )
            await db.commit()

    assert result is not None
    assert result["action"] == "email"
    mock_send.assert_called_once()
    args, kwargs = mock_send.call_args
    # Positional: recipients, subject, body, settings
    recipients, subject, body, settings_dict = args[:4]
    assert recipients == ["oncall@example.org"]
    assert "host-a" in subject
    assert "CVE-2026-9999" in subject
    assert "CRITICAL" in subject
    assert "host-a" in body or "CVE-2026-9999" in body


@pytest.mark.anyio
async def test_email_action_falls_back_to_alert_email(client, auth):
    """When policy.config omits recipients, fall back to global alert_email."""
    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    # Ensure a global alert_email is set
    await client.put(
        "/api/v1/settings/alerts",
        json={"alert_email": "global@example.org", "smtp_host": "m.example.org"},
        headers=auth,
    )

    name = f"email-fb-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "email",
            "priority": 990,
            "enabled": True,
            "auto_execute": True,
            "match_package": "openssl",
        },
        headers=auth,
    )

    with patch(
        "api.app.routes.automation.send_email",
        return_value=True,
    ) as mock_send:
        async with async_session() as db:
            await run_evaluation(
                {
                    "trigger_type": "cve_detected",
                    "hostname": "host-a",
                    "severity": "high",
                    "cve_id": "CVE-2026-1111",
                    "package": "openssl",
                },
                db,
            )
            await db.commit()

    # At least one call used the global alert_email
    assert mock_send.called
    found = False
    for call in mock_send.call_args_list:
        if call.args[0] == ["global@example.org"]:
            found = True
            break
    assert found, "expected fallback to global alert_email"
