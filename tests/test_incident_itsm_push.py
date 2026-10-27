"""Incident → ITSM push (outbound) + inbound status update flow."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import asyncpg
import pytest

from tests.conftest import ASYNCPG_DSN


async def _insert_integration(
    name: str,
    platform: str = "jira",
    *,
    sync_outbound: bool = True,
    sync_inbound: bool = False,
    webhook_secret: str | None = None,
    status_map: dict | None = None,
) -> str:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO itsm_integrations
                (name, platform, base_url, auth_config, project_key,
                 enabled, sync_outbound, sync_inbound, webhook_secret, status_map)
            VALUES ($1, $2, 'https://x', $3::jsonb, 'INC',
                    true, $4, $5, $6, $7::jsonb)
            RETURNING id
            """,
            name,
            platform,
            json.dumps({"email": "a@b.c", "api_token": "t"}),
            sync_outbound,
            sync_inbound,
            webhook_secret,
            json.dumps(status_map or {}),
        )
        return str(row["id"])
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_outbound_push_creates_ticket(client, auth, seeded_ruleset):
    await _insert_integration("jira-out")

    with patch(
        "api.app.connectors.jira.JiraConnector.create_ticket",
        new=AsyncMock(return_value=("INC-42", "https://x/browse/INC-42")),
    ):
        r = await client.post(
            "/api/v1/incidents",
            json={
                "title": "outbound push test",
                "cve_id": "CVE-ITSM-1",
                "affected_asset": "host-a",
                "affected_package": "openssl",
                "severity": "critical",
            },
            headers=auth,
        )
    assert r.status_code == 200
    iid = r.json()["id"]

    r2 = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    tickets = r2.json()["tickets"]
    assert len(tickets) == 1
    assert tickets[0]["external_id"] == "INC-42"
    assert tickets[0]["external_url"] == "https://x/browse/INC-42"
    assert tickets[0]["platform"] == "jira"


@pytest.mark.anyio
async def test_outbound_skipped_when_sync_off(client, auth, seeded_ruleset):
    await _insert_integration("jira-off", sync_outbound=False)

    with patch(
        "api.app.connectors.jira.JiraConnector.create_ticket",
        new=AsyncMock(return_value=("X", "Y")),
    ) as mock_ct:
        await client.post(
            "/api/v1/incidents",
            json={"title": "t", "affected_asset": "h", "cve_id": "CVE-X"},
            headers=auth,
        )
    assert not mock_ct.called


@pytest.mark.anyio
async def test_outbound_connector_failure_does_not_break_incident(
    client, auth, seeded_ruleset
):
    await _insert_integration("jira-fail")

    with patch(
        "api.app.connectors.jira.JiraConnector.create_ticket",
        new=AsyncMock(side_effect=RuntimeError("ITSM down")),
    ):
        r = await client.post(
            "/api/v1/incidents",
            json={"title": "still works", "affected_asset": "h", "cve_id": "CVE-Y"},
            headers=auth,
        )
    # Incident creation must succeed even if ITSM push fails
    assert r.status_code == 200
    iid = r.json()["id"]
    r2 = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    assert r2.json()["tickets"] == []


@pytest.mark.anyio
async def test_inbound_maps_status_and_closes_incident(client, auth, seeded_ruleset):
    secret = "s3cret-for-hmac"
    integ_id = await _insert_integration(
        "jira-closer",
        sync_inbound=True,
        sync_outbound=True,
        webhook_secret=secret,
        status_map={"Done": "closed"},
    )

    with patch(
        "api.app.connectors.jira.JiraConnector.create_ticket",
        new=AsyncMock(return_value=("INC-99", "https://x/browse/INC-99")),
    ):
        r = await client.post(
            "/api/v1/incidents",
            json={"title": "to be closed by ITSM", "affected_asset": "h"},
            headers=auth,
        )
    iid = r.json()["id"]

    body = json.dumps(
        {"issue": {"key": "INC-99", "fields": {"status": {"name": "Done"}}}}
    ).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    r2 = await client.post(
        f"/api/v1/webhooks/itsm/{integ_id}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-CMDB-Signature": f"sha256={sig}",
        },
    )
    assert r2.status_code == 200
    assert r2.json()["applied"] == "closed"

    r3 = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    assert r3.json()["incident"]["status"] == "closed"


@pytest.mark.anyio
async def test_inbound_unmapped_status_logs_event_without_transition(
    client, auth, seeded_ruleset
):
    secret = "another-secret"
    integ_id = await _insert_integration(
        "jira-unmapped",
        sync_inbound=True,
        webhook_secret=secret,
        status_map={"Done": "closed"},
    )

    with patch(
        "api.app.connectors.jira.JiraConnector.create_ticket",
        new=AsyncMock(return_value=("INC-77", "https://x/browse/INC-77")),
    ):
        r = await client.post(
            "/api/v1/incidents",
            json={"title": "unmapped status", "affected_asset": "h2"},
            headers=auth,
        )
    iid = r.json()["id"]

    body = json.dumps(
        {"issue": {"key": "INC-77", "fields": {"status": {"name": "In Review"}}}}
    ).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    r2 = await client.post(
        f"/api/v1/webhooks/itsm/{integ_id}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-CMDB-Signature": f"sha256={sig}",
        },
    )
    assert r2.status_code == 200
    assert r2.json()["applied"] is None

    r3 = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    assert r3.json()["incident"]["status"] == "new"
    kinds = [e["event_type"] for e in r3.json()["events"]]
    assert "action_executed" in kinds
