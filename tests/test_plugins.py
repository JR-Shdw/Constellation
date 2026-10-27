"""Plugin catalogue — static shape + live counts from DB."""

import json

import asyncpg
import pytest

from tests.conftest import ASYNCPG_DSN


@pytest.mark.anyio
async def test_plugins_returns_catalogue(client, auth):
    # Clear the route cache so changes made by other tests don't leak
    from api.app.routes.plugins import _cache

    _cache["data"] = None

    r = await client.get("/api/v1/plugins", headers=auth)
    assert r.status_code == 200
    data = r.json()

    assert "summary" in data
    assert "categories" in data
    cats = data["categories"]
    assert len(cats) >= 10

    ids = {c["id"] for c in cats}
    for expected in ("forge", "ci", "itsm", "notification", "scanner"):
        assert expected in ids

    for c in cats:
        assert c["providers"], f"category {c['id']} has no providers"
        for p in c["providers"]:
            assert p["status"] in ("supported", "planned")
            assert "configured_count" in p


@pytest.mark.anyio
async def test_plugins_counts_itsm_configured(client, auth):
    from api.app.routes.plugins import _cache

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO itsm_integrations
                (name, platform, base_url, auth_config, enabled)
            VALUES ('plugin-cnt-jira', 'jira', 'https://x',
                    $1::jsonb, true)
            ON CONFLICT (name) DO NOTHING
            """,
            json.dumps({"email": "a@b.c", "api_token": "t"}),
        )
    finally:
        await conn.close()

    _cache["data"] = None
    r = await client.get("/api/v1/plugins", headers=auth)
    assert r.status_code == 200
    data = r.json()

    itsm = next(c for c in data["categories"] if c["id"] == "itsm")
    jira = next(p for p in itsm["providers"] if p["id"] == "jira")
    assert jira["configured_count"] >= 1
    assert data["summary"]["providers_configured"] >= 1


@pytest.mark.anyio
async def test_plugins_summary_counts_match(client, auth):
    from api.app.routes.plugins import _cache

    _cache["data"] = None
    r = await client.get("/api/v1/plugins", headers=auth)
    data = r.json()

    total = sum(len(c["providers"]) for c in data["categories"])
    supported = sum(
        1 for c in data["categories"]
        for p in c["providers"] if p["status"] == "supported"
    )
    planned = sum(
        1 for c in data["categories"]
        for p in c["providers"] if p["status"] == "planned"
    )
    assert data["summary"]["providers_total"] == total
    assert data["summary"]["providers_supported"] == supported
    assert data["summary"]["providers_planned"] == planned
