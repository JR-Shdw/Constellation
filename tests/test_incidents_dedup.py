"""Incidents — dedup tuple (cve_id, asset, package) while open."""

import pytest


@pytest.mark.anyio
async def test_dedup_hit_same_tuple(client, auth, seeded_ruleset):
    payload = {
        "title": "openssl cve",
        "cve_id": "CVE-2024-1234",
        "affected_asset": "host-a",
        "affected_package": "openssl",
        "severity": "high",
    }

    r1 = await client.post("/api/v1/incidents", json=payload, headers=auth)
    first = r1.json()
    assert first.get("deduped") is False

    r2 = await client.post("/api/v1/incidents", json=payload, headers=auth)
    second = r2.json()
    assert second.get("deduped") is True
    assert second["uid"] == first["uid"]
    assert second["id"] == first["id"]


@pytest.mark.anyio
async def test_dedup_miss_different_asset(client, auth, seeded_ruleset):
    base = {
        "title": "cve",
        "cve_id": "CVE-2024-9999",
        "affected_package": "nginx",
    }

    r1 = await client.post(
        "/api/v1/incidents", json={**base, "affected_asset": "hostA"}, headers=auth
    )
    r2 = await client.post(
        "/api/v1/incidents", json={**base, "affected_asset": "hostB"}, headers=auth
    )
    assert r1.json()["id"] != r2.json()["id"]
    assert r2.json().get("deduped") is False


@pytest.mark.anyio
async def test_dedup_emits_action_executed_event(client, auth, seeded_ruleset):
    payload = {
        "title": "dedup event test",
        "cve_id": "CVE-2024-7777",
        "affected_asset": "host-c",
        "affected_package": "curl",
    }

    r1 = await client.post("/api/v1/incidents", json=payload, headers=auth)
    iid = r1.json()["id"]

    # Trigger dedup
    await client.post("/api/v1/incidents", json=payload, headers=auth)

    r = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    kinds = [e["event_type"] for e in r.json()["events"]]
    assert "created" in kinds
    assert "action_executed" in kinds


@pytest.mark.anyio
async def test_resolved_does_not_dedup(client, auth, seeded_ruleset):
    payload = {
        "title": "resolved dedup",
        "cve_id": "CVE-2024-5555",
        "affected_asset": "host-b",
        "affected_package": "bash",
    }

    r1 = await client.post("/api/v1/incidents", json=payload, headers=auth)
    iid = r1.json()["id"]

    # Move to resolved via in_progress
    await client.patch(
        f"/api/v1/incidents/{iid}", json={"status": "in_progress"}, headers=auth
    )
    await client.patch(
        f"/api/v1/incidents/{iid}", json={"status": "resolved"}, headers=auth
    )

    # New report with same tuple should create a NEW incident
    r2 = await client.post("/api/v1/incidents", json=payload, headers=auth)
    assert r2.json().get("deduped") is False
    assert r2.json()["id"] != iid
