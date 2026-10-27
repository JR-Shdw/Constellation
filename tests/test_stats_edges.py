"""read/stats.py — CVE severity-exclude filters, feature-disabled zeroing,
trends cache hit."""

import pytest


@pytest.mark.anyio
async def test_trends_automation_uses_canonical_statuses(client, auth):
    """The automation trend must count completed/failed.

    Regression: it filtered status='executed'/'error', which the engine never
    writes (it uses completed/failed), so the sparkline was permanently zero.
    """
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO automation_log (trigger_type, action, status, created_at)
            VALUES ('backup_overdue', 'notify', 'completed', NOW()),
                   ('backup_overdue', 'notify', 'failed', NOW())
            """
        )
    finally:
        await conn.close()

    import api.app.routes.read as rmod

    rmod._cache.clear()

    r = await client.get("/api/v1/stats/trends?days=1", headers=auth)
    assert r.status_code == 200
    auto = r.json()["automation"]
    assert sum(d["executed"] for d in auto) >= 1
    assert sum(d["errors"] for d in auto) >= 1


@pytest.mark.anyio
async def test_stats_with_cve_exclude_medium_low(client, auth):
    """Toggle alert_settings cve_count_exclude_medium/low → exercise filter
    branches lines 30 and 32."""
    # Set both flags via /alerts (string values, per route convention)
    r = await client.put(
        "/api/v1/settings/alerts",
        json={
            "cve_count_exclude_medium": "true",
            "cve_count_exclude_low": "true",
        },
        headers=auth,
    )
    assert r.status_code == 200

    # Bust the in-memory stats cache so the next call recomputes
    import api.app.routes.read as rmod
    rmod._cache.clear()

    # Hit /stats — must execute the sev_filter '!= medium' AND '!= low' paths
    r2 = await client.get("/api/v1/stats", headers=auth)
    assert r2.status_code == 200
    data = r2.json()
    assert data.get("cve_count_exclude_medium") is True
    assert data.get("cve_count_exclude_low") is True

    # Reset for hygiene
    await client.put(
        "/api/v1/settings/alerts",
        json={
            "cve_count_exclude_medium": "false",
            "cve_count_exclude_low": "false",
        },
        headers=auth,
    )


@pytest.mark.anyio
async def test_stats_cve_feature_disabled_zeros_cve_keys(client, auth):
    """Toggle CVE feature off → counts zeroed out (lines 122-126)."""
    import api.app.routes.read as rmod

    # Disable CVE feature
    r0 = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve", "enabled": False, "confirm": "DISABLE CVE"},
        headers=auth,
    )
    assert r0.status_code == 200

    # Bust cache
    rmod._cache.clear()

    r = await client.get("/api/v1/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data.get("feature_cve_enabled") is False
    # All cve_* counters should be zero (excl_keys preserved as bools)
    for k, v in data.items():
        if k.startswith("cves_"):
            assert v == 0, f"{k} should be 0 when CVE disabled, got {v}"

    # Re-enable CVE feature
    r2 = await client.post(
        "/api/v1/settings/features/toggle",
        json={"feature": "cve", "enabled": True, "confirm": "ENABLE CVE"},
        headers=auth,
    )
    assert r2.status_code == 200
    rmod._cache.clear()


@pytest.mark.anyio
async def test_stats_backup_feature_disabled_zeros(client, auth):
    """Backup disabled → backups_* zeroed (lines 131-133)."""
    import api.app.routes.read as rmod

    r0 = await client.post(
        "/api/v1/settings/features/toggle",
        json={
            "feature": "backup",
            "enabled": False,
            "confirm": "DISABLE BACKUP",
        },
        headers=auth,
    )
    assert r0.status_code == 200

    rmod._cache.clear()

    r = await client.get("/api/v1/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data.get("feature_backup_enabled") is False
    assert data["backups_ok"] == 0
    assert data["backups_failed"] == 0
    assert data["backups_overdue"] == 0

    # Re-enable
    await client.post(
        "/api/v1/settings/features/toggle",
        json={
            "feature": "backup",
            "enabled": True,
            "confirm": "ENABLE BACKUP",
        },
        headers=auth,
    )
    rmod._cache.clear()


@pytest.mark.anyio
async def test_stats_trends_cache_hit(client, auth):
    """Second call to /stats/trends serves from cache (line 150-151)."""
    r1 = await client.get("/api/v1/stats/trends?days=7", headers=auth)
    assert r1.status_code == 200
    r2 = await client.get("/api/v1/stats/trends?days=7", headers=auth)
    assert r2.status_code == 200
    # Same payload
    assert r1.json() == r2.json()
