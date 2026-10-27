"""Incidents — list filter branches + comment/rule 404."""

import pytest


@pytest.mark.anyio
async def test_list_filter_status(client, auth, seeded_ruleset):
    """status filter exercises the `clauses.append("status = ...")` branch."""
    await client.post(
        "/api/v1/incidents",
        json={"title": "filt-status", "affected_asset": "fh1"},
        headers=auth,
    )
    r = await client.get("/api/v1/incidents?status=new", headers=auth)
    assert r.status_code == 200
    for it in r.json()["items"]:
        assert it["status"] == "new"


@pytest.mark.anyio
async def test_list_filter_priority(client, auth, seeded_ruleset):
    """priority filter branch."""
    await client.post(
        "/api/v1/incidents",
        json={"title": "filt-pri", "affected_asset": "fh2"},
        headers=auth,
    )
    r = await client.get("/api/v1/incidents?priority=P4", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_list_filter_assignee(client, auth, seeded_ruleset):
    """assignee filter branch."""
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "filt-assignee", "affected_asset": "fh3"},
        headers=auth,
    )
    iid = r.json()["id"]
    await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"assignee": "bob"},
        headers=auth,
    )
    r = await client.get("/api/v1/incidents?assignee=bob", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(it["assignee"] == "bob" for it in items)
    assert len(items) >= 1


@pytest.mark.anyio
async def test_list_filter_cve_id(client, auth, seeded_ruleset):
    """cve_id filter branch."""
    await client.post(
        "/api/v1/incidents",
        json={
            "title": "filt-cve",
            "affected_asset": "fh4",
            "cve_id": "CVE-2025-1234",
        },
        headers=auth,
    )
    r = await client.get(
        "/api/v1/incidents?cve_id=CVE-2025-1234", headers=auth
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(it["cve_id"] == "CVE-2025-1234" for it in items)


@pytest.mark.anyio
async def test_comment_on_missing_incident(client, auth):
    """POST comment on non-existent incident → 404."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.post(
        f"/api/v1/incidents/{fake}/comment",
        json={"body": "hi"},
        headers=auth,
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_priority_rule_detail(client, auth, seeded_ruleset):
    """GET /priority-rules/{id} returns the rule."""
    r = await client.get("/api/v1/priority-rules?active_only=true", headers=auth)
    items = r.json()["items"]
    assert items, "seeded_ruleset should populate priority_rule_sets"
    rid = items[0]["id"]
    r2 = await client.get(f"/api/v1/priority-rules/{rid}", headers=auth)
    assert r2.status_code == 200
    assert r2.json()["id"] == rid


@pytest.mark.anyio
async def test_priority_rule_detail_404(client, auth):
    """Unknown rule id → 404."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.get(f"/api/v1/priority-rules/{fake}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_priority_rule_activate_404(client, auth):
    """Unknown rule id on activate → 404."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.post(
        f"/api/v1/priority-rules/{fake}/activate", headers=auth
    )
    assert r.status_code == 404
