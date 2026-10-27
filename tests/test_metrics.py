"""Prometheus metrics endpoint tests."""

import pytest


@pytest.mark.anyio
async def test_metrics_endpoint(client, auth):
    """Metrics returns Prometheus text format."""
    # Clear module-level cache to force DB queries
    from api.app.routes.metrics import _metrics_cache

    _metrics_cache.clear()
    r = await client.get("/api/v1/metrics", headers=auth)
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "cmdb_nodes_total" in body
    assert "cmdb_packages_total" in body
    assert "# HELP" in body
    assert "# TYPE" in body


@pytest.mark.anyio
async def test_metrics_cached(client, auth):
    """Second call returns cached metrics (same content)."""
    r1 = await client.get("/api/v1/metrics", headers=auth)
    r2 = await client.get("/api/v1/metrics", headers=auth)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.text == r2.text


@pytest.mark.anyio
async def test_metrics_automation_executed_counts_completed(client, auth):
    """cmdb_automation_24h{status="executed"} reflects 'completed' log rows.

    Regression: the gauge filtered status='executed'/'error' which the engine
    never writes (completed/failed), so it was permanently zero.
    """
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "INSERT INTO automation_log (trigger_type, action, status, created_at) "
            "VALUES ('backup_overdue', 'notify', 'completed', NOW())"
        )
    finally:
        await conn.close()

    from api.app.routes.metrics import _metrics_cache

    _metrics_cache.clear()
    body = (await client.get("/api/v1/metrics", headers=auth)).text
    line = next(
        ln
        for ln in body.splitlines()
        if ln.startswith('cmdb_automation_24h{status="executed"}')
    )
    assert float(line.rsplit(" ", 1)[1]) >= 1


@pytest.mark.anyio
async def test_metrics_contains_sections(client, auth):
    """Metrics covers all major sections."""
    r = await client.get("/api/v1/metrics", headers=auth)
    body = r.text
    for key in (
        "cmdb_nodes_total",
        "cmdb_nodes_active",
        "cmdb_nodes_heartbeat",
        "cmdb_cves_host_total",
        "cmdb_cves_container_total",
        "cmdb_containers_total",
        "cmdb_backup_repos_total",
        "cmdb_scan_nodes_scanned",
        "cmdb_repos_total",
        "cmdb_automation_pending",
        "cmdb_sca_checks_total",
        "cmdb_packages_total",
    ):
        assert key in body, f"missing metric: {key}"
