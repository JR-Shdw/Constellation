"""Incidents — /stats: counts + MTTA/MTTR from timestamps."""

import asyncpg
import pytest

from tests.conftest import ASYNCPG_DSN


@pytest.mark.anyio
async def test_stats_counts_by_status_priority(client, auth, seeded_ruleset):
    from api.app.routes.incidents import _stats_cache

    _stats_cache.clear()
    # Seed a handful of incidents with different statuses
    iids = []
    for _ in range(3):
        r = await client.post(
            "/api/v1/incidents",
            json={
                "title": "s-test",
                "cve_id": f"CVE-S-{_}",
                "affected_asset": f"host-{_}",
            },
            headers=auth,
        )
        iids.append(r.json()["id"])

    # Triage one, resolve another
    await client.patch(
        f"/api/v1/incidents/{iids[0]}", json={"status": "triaged"}, headers=auth
    )
    await client.patch(
        f"/api/v1/incidents/{iids[1]}", json={"status": "in_progress"}, headers=auth
    )
    await client.patch(
        f"/api/v1/incidents/{iids[1]}", json={"status": "resolved"}, headers=auth
    )

    r = await client.get("/api/v1/incidents/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["by_status"]["new"] == 1
    assert data["by_status"]["triaged"] == 1
    assert data["by_status"]["resolved"] == 1
    # total_open: new + triaged = 2
    assert data["total_open"] == 2


@pytest.mark.anyio
async def test_stats_mtta_mttr(client, auth, seeded_ruleset):
    """MTTA/MTTR populated when timestamps exist — DB backdate for determinism."""
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "mtta test", "affected_asset": "ma-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    # Backdate created_at, set triaged/resolved directly via DB
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            UPDATE incidents SET
                created_at = NOW() - INTERVAL '60 minutes',
                triaged_at = NOW() - INTERVAL '50 minutes',
                resolved_at = NOW() - INTERVAL '10 minutes'
             WHERE id = $1::uuid
            """,
            iid,
        )
    finally:
        await conn.close()

    # Bust the 30s stats cache by waiting? No — stats_cache is on route module.
    # Call stats, it will be cached. Flush module-level cache.
    from api.app.routes.incidents import _stats_cache

    _stats_cache.clear()

    r2 = await client.get("/api/v1/incidents/stats", headers=auth)
    data = r2.json()
    # ~10 minutes triage gap, ~50 minutes resolve gap
    assert data["mtta_p50_seconds"] is not None
    assert data["mttr_p50_seconds"] is not None
    assert 500 < data["mtta_p50_seconds"] < 700  # ~600s
    assert 2900 < data["mttr_p50_seconds"] < 3100  # ~3000s


@pytest.mark.anyio
async def test_stats_empty_db(client, auth):
    from api.app.routes.incidents import _stats_cache

    _stats_cache.clear()
    r = await client.get("/api/v1/incidents/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["by_status"] == {}
    assert data["by_priority"] == {}
    assert data["total_open"] == 0
    assert data["mtta_p50_seconds"] is None
    assert data["mttr_p50_seconds"] is None
