"""Incidents — automation branch: policy fires create_incident action."""

from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.anyio
async def test_create_incident_action_via_automation(client, auth, seeded_ruleset):
    """Policy action=create_incident must produce an incident on matching event."""
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "auto-incident-critical",
            "trigger_type": "cve_detected",
            "action": "create_incident",
            "priority": 50,
            "enabled": True,
            "auto_execute": True,
            "match_severity": ["critical"],
        },
        headers=auth,
    )

    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    with patch(
        "api.app.routes.automation.send_automation_notification",
        new_callable=AsyncMock,
    ) as mock_notify:
        async with async_session() as db:
            result = await run_evaluation(
                {
                    "trigger_type": "cve_detected",
                    "cve_id": "CVE-2024-AAAA",
                    "hostname": "host-a",
                    "package": "openssl",
                    "severity": "critical",
                    "environment": "production",
                    "exposure": "internet",
                    "cvss": 9.8,
                    "in_kev": True,
                },
                db,
            )
            await db.commit()

    assert result is not None
    assert result["action"] == "create_incident"

    # Incident visible via API
    r = await client.get("/api/v1/incidents", headers=auth)
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["cve_id"] == "CVE-2024-AAAA"
    assert items[0]["affected_asset"] == "host-a"
    assert items[0]["affected_package"] == "openssl"

    # Notification routed as "incident_created"
    assert mock_notify.called
    trigger_arg = mock_notify.call_args.args[0]
    assert trigger_arg == "incident_created"


@pytest.mark.anyio
async def test_automation_dedup_single_incident(client, auth, seeded_ruleset):
    """Second evaluation with same tuple hits dedup — still one incident."""
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "auto-incident-dedup",
            "trigger_type": "cve_detected",
            "action": "create_incident",
            "priority": 10,
            "enabled": True,
            "auto_execute": True,
        },
        headers=auth,
    )

    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    event = {
        "trigger_type": "cve_detected",
        "cve_id": "CVE-2024-DEDUP",
        "hostname": "host-c",
        "package": "curl",
        "severity": "high",
    }

    with patch(
        "api.app.routes.automation.send_automation_notification",
        new_callable=AsyncMock,
    ):
        async with async_session() as db:
            await run_evaluation(event, db)
            await run_evaluation(event, db)
            await db.commit()

    r = await client.get("/api/v1/incidents", headers=auth)
    items = r.json()["items"]
    assert len(items) == 1


@pytest.mark.anyio
async def test_automation_log_records_create_incident(client, auth, seeded_ruleset):
    """Execution is logged in automation_log."""
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": "auto-log-test",
            "trigger_type": "cve_detected",
            "action": "create_incident",
            "priority": 10,
            "enabled": True,
            "auto_execute": True,
        },
        headers=auth,
    )

    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    with patch(
        "api.app.routes.automation.send_automation_notification",
        new_callable=AsyncMock,
    ):
        async with async_session() as db:
            await run_evaluation(
                {
                    "trigger_type": "cve_detected",
                    "cve_id": "CVE-LOG-1",
                    "hostname": "h1",
                    "package": "p1",
                    "severity": "critical",
                },
                db,
            )
            await db.commit()

    r = await client.get("/api/v1/automation/log", headers=auth)
    entries = r.json()["items"]
    assert any(e["policy_name"] == "auto-log-test" for e in entries)
