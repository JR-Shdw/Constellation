"""Incidents — CRUD + UID + 404."""

import pytest


@pytest.mark.anyio
async def test_create_incident(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={
            "title": "OpenSSL critical on host-a",
            "description": "test",
            "cve_id": "CVE-2024-0001",
            "affected_asset": "host-a",
            "affected_package": "openssl",
            "severity": "critical",
            "environment": "production",
            "exposure": "internet",
            "cvss": 9.8,
            "in_kev": True,
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["uid"].startswith("INC-")
    assert data["priority"] in ("P1", "P2", "P3", "P4")
    assert data["status"] == "new"
    assert data.get("deduped") is False


@pytest.mark.anyio
async def test_uid_monotonic(client, auth, seeded_ruleset):
    uids = []
    for i in range(3):
        r = await client.post(
            "/api/v1/incidents",
            json={"title": f"inc {i}", "affected_asset": f"host-{i}"},
            headers=auth,
        )
        assert r.status_code == 200
        uids.append(r.json()["uid"])
    # Monotonic increase
    nums = [int(u.split("-")[1]) for u in uids]
    assert nums == sorted(nums)
    assert len(set(nums)) == 3


@pytest.mark.anyio
async def test_list_and_filter(client, auth, seeded_ruleset):
    for env, sev in [("production", "critical"), ("lab", "low")]:
        await client.post(
            "/api/v1/incidents",
            json={
                "title": f"t-{env}",
                "affected_asset": f"a-{env}",
                "environment": env,
                "severity": sev,
            },
            headers=auth,
        )

    r = await client.get("/api/v1/incidents?q=production", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    assert any("production" in (it["title"] or "") for it in items)


@pytest.mark.anyio
async def test_get_incident_detail(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "detail test", "affected_asset": "host-x"},
        headers=auth,
    )
    iid = r.json()["id"]

    r2 = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    assert r2.status_code == 200
    body = r2.json()
    assert body["incident"]["id"] == iid
    # Timeline has at least the "created" event
    assert len(body["events"]) >= 1
    assert body["events"][0]["event_type"] == "created"


@pytest.mark.anyio
async def test_404_on_missing(client, auth):
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.get(f"/api/v1/incidents/{fake}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_comment(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "comment test", "affected_asset": "c-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    r2 = await client.post(
        f"/api/v1/incidents/{iid}/comment",
        json={"body": "looking into this"},
        headers=auth,
    )
    assert r2.status_code == 200

    r3 = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    events = r3.json()["events"]
    assert any(e["event_type"] == "commented" for e in events)


@pytest.mark.anyio
async def test_patch_assignee_and_description(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "patch test", "affected_asset": "p-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"assignee": "alice", "description": "updated desc"},
        headers=auth,
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["assignee"] == "alice"
    assert body["description"] == "updated desc"
