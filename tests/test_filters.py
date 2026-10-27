"""Saved filters — CRUD tests."""

import pytest


@pytest.mark.anyio
async def test_create_filter(client, auth):
    r = await client.post(
        "/api/v1/filters",
        json={"name": "my-filter", "view": "cves", "filters": {"severity": "critical"}},
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["name"] == "my-filter"
    assert "id" in data


@pytest.mark.anyio
async def test_create_filter_missing_name(client, auth):
    r = await client.post(
        "/api/v1/filters",
        json={"name": "", "view": "cves", "filters": {}},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_list_filters(client, auth):
    await client.post(
        "/api/v1/filters",
        json={"name": "list-test", "view": "nodes", "filters": {"type": "vm"}},
        headers=auth,
    )
    r = await client.get("/api/v1/filters", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_list_filters_by_view(client, auth):
    await client.post(
        "/api/v1/filters",
        json={"name": "view-filter", "view": "containers", "filters": {}},
        headers=auth,
    )
    r = await client.get("/api/v1/filters?view=containers", headers=auth)
    assert r.status_code == 200
    names = [f["name"] for f in r.json()["items"]]
    assert "view-filter" in names


@pytest.mark.anyio
async def test_update_filter(client, auth):
    cr = await client.post(
        "/api/v1/filters",
        json={"name": "upd-filter", "view": "cves", "filters": {"sev": "high"}},
        headers=auth,
    )
    fid = cr.json()["id"]
    r = await client.put(
        f"/api/v1/filters/{fid}",
        json={"name": "upd-filter-renamed"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_update_filter_empty(client, auth):
    cr = await client.post(
        "/api/v1/filters",
        json={"name": "upd-noop", "view": "cves", "filters": {}},
        headers=auth,
    )
    fid = cr.json()["id"]
    r = await client.put(f"/api/v1/filters/{fid}", json={}, headers=auth)
    assert r.status_code == 200
    assert r.json()["changed"] is False


@pytest.mark.anyio
async def test_delete_filter(client, auth):
    cr = await client.post(
        "/api/v1/filters",
        json={"name": "del-filter", "view": "cves", "filters": {}},
        headers=auth,
    )
    fid = cr.json()["id"]
    r = await client.delete(f"/api/v1/filters/{fid}", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_delete_filter_not_found(client, auth):
    r = await client.delete(
        "/api/v1/filters/00000000-0000-0000-0000-000000000000", headers=auth
    )
    assert r.status_code == 404
