"""Retention cleanup tests."""

import asyncpg
import pytest

from .conftest import ASYNCPG_DSN


@pytest.mark.anyio
async def test_retention_run(client, auth):
    r = await client.post("/api/v1/retention/run", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "total_purged" in data
    assert "purged" in data
    assert "thresholds" in data
    for key in (
        "audit_log",
        "cicd_pipelines",
        "automation_log",
        "scheduler_runs",
        "alert_sent",
        "cve_status_resolved",
        "stale_images",
    ):
        assert key in data["purged"]


@pytest.mark.anyio
async def test_retention_settings(client, auth):
    r = await client.get("/api/v1/retention/settings", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "retention_audit_days" in data
    assert "retention_pipeline_days" in data
    assert "retention_resolved_cve_days" in data
    assert "retention_stale_image_days" in data
    assert data["retention_audit_days"] == 90
    assert data["retention_stale_image_days"] == 7


async def _seed_stale_image(last_updated_days_ago: int, scan_days_ago: int):
    """Insert a stale container_image + matching CVE row, no live container.

    `scan_days_ago` controls MAX(scanned_at) on cve_containers — the
    safeguard gate that decides whether the purge runs.
    """
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('retention-host', 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """
        )
        img_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag, last_updated)
            VALUES ('ghost/oneuptime', 'v1',
                    NOW() - make_interval(days => $1))
            RETURNING id
            """,
            last_updated_days_ago,
        )
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ('CVE-2099-7777', 'stale test')
            ON CONFLICT (cve_id) DO NOTHING
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status, scanned_at)
            VALUES ($1, 'CVE-2099-7777', 'high', 'libssl', '1.0.0',
                    'ghost/oneuptime:v1', 'open',
                    NOW() - make_interval(days => $2))
            """,
            node_id,
            scan_days_ago,
        )
        return img_id, node_id
    finally:
        await conn.close()


async def _image_exists(img_id) -> bool:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        return bool(
            await conn.fetchval("SELECT 1 FROM container_images WHERE id = $1", img_id)
        )
    finally:
        await conn.close()


async def _cve_status_for(node_id, cve_id) -> tuple[str | None, str | None]:
    """Return (scan_status, workflow_status) for a given CVE."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        scan = await conn.fetchval(
            "SELECT status FROM cve_containers WHERE node_id = $1 AND cve_id = $2",
            node_id,
            cve_id,
        )
        wf = await conn.fetchval(
            "SELECT status FROM cve_status WHERE node_id = $1 AND cve_id = $2",
            node_id,
            cve_id,
        )
        return scan, wf
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_retention_stale_image_purged(client, auth):
    """Image unused for 10 days + fresh scan activity → purged, CVE resolved."""
    img_id, node_id = await _seed_stale_image(last_updated_days_ago=10, scan_days_ago=0)

    r = await client.post("/api/v1/retention/run", headers=auth)
    assert r.status_code == 200
    data = r.json()

    assert data["purged"]["stale_images"] == 1
    assert data["purged"]["stale_image_cves_resolved"] == 1
    assert not await _image_exists(img_id)

    scan, wf = await _cve_status_for(node_id, "CVE-2099-7777")
    # Image row was deleted so scan row is gone via no cascade (container_id
    # was NULL). The workflow decision must remain for audit trail.
    assert wf == "resolved"


@pytest.mark.anyio
async def test_retention_stale_image_safeguard_no_recent_scan(client, auth):
    """No Trivy activity for >2 days → purge skipped (fail-safe)."""
    img_id, _ = await _seed_stale_image(last_updated_days_ago=10, scan_days_ago=5)

    r = await client.post("/api/v1/retention/run", headers=auth)
    assert r.status_code == 200
    data = r.json()

    assert data["purged"]["stale_images"] == 0
    assert await _image_exists(img_id), "Image must NOT be purged when scanner is down"


@pytest.mark.anyio
async def test_retention_stale_image_skipped_if_container_exists(client, auth):
    """Image with a live container → not considered stale even if old."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('retention-live', 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """
        )
        img_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag, last_updated)
            VALUES ('live/app', 'v1', NOW() - make_interval(days => 10))
            RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO containers (node_id, image_id, name, status)
            VALUES ($1, $2, 'live-app', 'running')
            """,
            node_id,
            img_id,
        )
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ('CVE-2099-8888', 'live test')
            ON CONFLICT DO NOTHING
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status, scanned_at)
            VALUES ($1, 'CVE-2099-8888', 'high', 'libx', '1',
                    'live/app:v1', 'open', NOW())
            """,
            node_id,
        )
    finally:
        await conn.close()

    r = await client.post("/api/v1/retention/run", headers=auth)
    assert r.status_code == 200
    assert r.json()["purged"]["stale_images"] == 0
    assert await _image_exists(img_id)


@pytest.mark.anyio
async def test_retention_resolved_cve_rows_purged(client, auth):
    """Resolved CVE row older than the slider threshold gets deleted."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('retention-cve-rows', 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ('CVE-2099-RR01', 'old resolved row')
            ON CONFLICT (cve_id) DO NOTHING
            """
        )
        # Old resolved row — must be purged.
        await conn.execute(
            """
            INSERT INTO cve_host_packages
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 status, scanned_at, source)
            VALUES ($1, 'CVE-2099-RR01', 'high', 'libold', '1',
                    'resolved', NOW() - make_interval(days => 200), 'trivy')
            """,
            node_id,
        )
        # Recent resolved row — must stay (default threshold 90 days).
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ('CVE-2099-RR02', 'recent resolved row')
            ON CONFLICT (cve_id) DO NOTHING
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_host_packages
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 status, scanned_at, source)
            VALUES ($1, 'CVE-2099-RR02', 'high', 'libnew', '1',
                    'resolved', NOW() - make_interval(days => 30), 'trivy')
            """,
            node_id,
        )
        # Old open row — must stay.
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ('CVE-2099-RR03', 'old open row')
            ON CONFLICT (cve_id) DO NOTHING
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_host_packages
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 status, scanned_at, source)
            VALUES ($1, 'CVE-2099-RR03', 'high', 'libopen', '1',
                    'open', NOW() - make_interval(days => 200), 'trivy')
            """,
            node_id,
        )
    finally:
        await conn.close()

    r = await client.post("/api/v1/retention/run", headers=auth)
    assert r.status_code == 200
    assert r.json()["purged"]["resolved_cve_rows"] >= 1

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        purged = await conn.fetchval(
            "SELECT 1 FROM cve_host_packages "
            "WHERE node_id = $1 AND cve_id = 'CVE-2099-RR01'",
            node_id,
        )
        recent = await conn.fetchval(
            "SELECT 1 FROM cve_host_packages "
            "WHERE node_id = $1 AND cve_id = 'CVE-2099-RR02'",
            node_id,
        )
        open_old = await conn.fetchval(
            "SELECT 1 FROM cve_host_packages "
            "WHERE node_id = $1 AND cve_id = 'CVE-2099-RR03'",
            node_id,
        )
    finally:
        await conn.close()

    assert purged is None, "old resolved row must be purged"
    assert recent == 1, "recent resolved row must stay"
    assert open_old == 1, "open row must stay regardless of age"


@pytest.mark.anyio
async def test_retention_resolved_cve_rows_slider_clamp(client, auth):
    """Slider value out of the 30-365 range gets clamped on save."""
    r = await client.put(
        "/api/v1/settings/alerts",
        json={"retention_resolved_cve_days": 9999},
        headers=auth,
    )
    assert r.status_code == 200

    r = await client.get("/api/v1/settings/alerts", headers=auth)
    val = int(r.json()["retention_resolved_cve_days"])
    assert val == 365

    r = await client.put(
        "/api/v1/settings/alerts",
        json={"retention_resolved_cve_days": 1},
        headers=auth,
    )
    assert r.status_code == 200
    r = await client.get("/api/v1/settings/alerts", headers=auth)
    val = int(r.json()["retention_resolved_cve_days"])
    assert val == 30
