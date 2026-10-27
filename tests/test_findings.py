"""Findings tests — patch, cleanup preview/list/execute, auto-resolve, score."""

import uuid

import asyncpg
import pytest

from .conftest import ASYNCPG_DSN


@pytest.fixture
async def cve_finding(client, collect_auth, auth):
    """Create a node with CVEs and return a host finding ID.

    Uses a unique hostname per call so ON CONFLICT upserts don't inherit
    stale status from previous tests sharing the same DB.
    """
    suffix = uuid.uuid4().hex[:8]
    hostname = f"findings-{suffix}"
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "type": "bare_metal",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["openssl\t3.0.11\tamd64"],
            "containers": [],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": hostname,
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-1001",
                    "Severity": "CRITICAL",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "FixedVersion": "3.0.12",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
                {
                    "VulnerabilityID": "CVE-2099-1002",
                    "Severity": "LOW",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "CVSS": {"nvd": {"V3Score": 2.1}},
                },
            ],
        },
        headers=collect_auth,
    )
    # Get a finding ID from the CVE list (need read auth, not collect)
    r = await client.get(
        "/api/v1/findings/cleanup/list?status=open&pkg_name=openssl",
        headers=auth,
    )
    items = r.json()["items"]
    host_ids = [
        i["id"]
        for i in items
        if i.get("target_type") == "package" and i.get("hostname") == hostname
    ]
    assert host_ids, f"fixture failed: no open findings for {hostname}"
    return host_ids[0]


# Patch finding


@pytest.mark.anyio
async def test_patch_host_finding(client, auth, cve_finding):
    """Patch a host finding status."""
    r = await client.patch(
        f"/api/v1/findings/host/{cve_finding}",
        json={"status": "mitigated"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["updated"] >= 1


@pytest.mark.anyio
async def test_patch_finding_invalid_field(client, auth, cve_finding):
    """Patch with no valid fields returns error."""
    r = await client.patch(
        f"/api/v1/findings/host/{cve_finding}",
        json={},
        headers=auth,
    )
    assert r.status_code == 200
    assert "error" in r.json()


@pytest.mark.anyio
async def test_patch_finding_fix_status(client, auth, cve_finding):
    """Patch fix_status field."""
    r = await client.patch(
        f"/api/v1/findings/host/{cve_finding}",
        json={"fix_status": "fixed_available"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["updated"] >= 1


@pytest.mark.anyio
async def test_patch_finding_exploited(client, auth, cve_finding):
    """Patch exploited flag."""
    r = await client.patch(
        f"/api/v1/findings/host/{cve_finding}",
        json={"exploited": True},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["updated"] >= 1


# Cleanup preview


@pytest.mark.anyio
async def test_cleanup_preview(client, auth, cve_finding):
    """Cleanup preview returns counts and breakdowns."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?status=open",
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "host_count" in data
    assert "container_count" in data
    assert "by_severity" in data
    assert "by_fix_status" in data


@pytest.mark.anyio
async def test_cleanup_preview_filter_severity(client, auth, cve_finding):
    """Cleanup preview with severity filter."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?severity=critical&status=open",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["total"] >= 0


@pytest.mark.anyio
async def test_cleanup_preview_target_type(client, auth, cve_finding):
    """Cleanup preview with target type filter."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?target_type=package&status=open",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["container_count"] == 0


# Cleanup list


@pytest.mark.anyio
async def test_cleanup_list(client, auth, cve_finding):
    """Cleanup list returns paginated findings."""
    r = await client.get(
        "/api/v1/findings/cleanup/list?status=open",
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data


@pytest.mark.anyio
async def test_cleanup_list_filter_severity(client, auth, cve_finding):
    """Cleanup list filtered by severity."""
    r = await client.get(
        "/api/v1/findings/cleanup/list?severity=critical&status=open",
        headers=auth,
    )
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["severity"] == "critical"


# Cleanup execute


@pytest.mark.anyio
async def test_cleanup_execute_resolve_by_filter(client, auth, cve_finding):
    """Bulk resolve CVEs by severity filter."""
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "resolve", "severity": "low", "status": "open"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["action"] == "resolve"
    assert "affected" in r.json()


@pytest.mark.anyio
async def test_cleanup_execute_resolve_with_os_filter(client, auth, cve_finding):
    """resolve + os filter must not corrupt the os subquery's own WHERE.

    Regression: where.replace('WHERE', ...) also rewrote the
    'SELECT id FROM nodes WHERE os ILIKE ...' subquery into
    '... WHERE status != :new_st AND os ILIKE ...' — nodes has no status
    column, so the bulk resolve/ignore 500'd whenever an os/arch/exploited
    filter was set.
    """
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "resolve", "os": "debian", "status": "open"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["action"] == "resolve"


@pytest.mark.anyio
async def test_cleanup_execute_ignore_with_exploited_filter(client, auth, cve_finding):
    """ignore + exploited filter exercises the cve_catalog subquery WHERE."""
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "ignore", "exploited": True, "status": "open"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["action"] == "ignore"


@pytest.mark.anyio
async def test_cleanup_execute_ignore_by_ids(client, auth, cve_finding):
    """Ignore specific finding by ID."""
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "ignore", "ids": [cve_finding]},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["action"] == "ignore"


@pytest.mark.anyio
async def test_cleanup_execute_no_filter_rejected(client, auth, cve_finding):
    """Execute without any meaningful filter returns error."""
    # status defaults to "open" in CleanupExecute which generates a WHERE clause,
    # so use an invalid status to get an empty WHERE and trigger the guard.
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "resolve", "status": "nonexistent"},
        headers=auth,
    )
    assert r.status_code == 200
    assert "error" in r.json()


@pytest.mark.anyio
async def test_cleanup_execute_invalid_action(client, auth, cve_finding):
    """Invalid action returns error."""
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "nuke", "severity": "low"},
        headers=auth,
    )
    assert r.status_code == 200
    assert "error" in r.json()


# Auto resolve


@pytest.mark.anyio
async def test_auto_resolve(client, auth, cve_finding):
    """Auto-resolve runs without error."""
    r = await client.post("/api/v1/findings/auto-resolve", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "resolved" in data
    assert "breakdown" in data


# Orphan CVE purge — when an image has no row in container_images


async def _seed_orphan_cve(image: str = "ghost/oneuptime:v1"):
    """Insert a node + cve_containers row whose image has no container_images row."""
    suffix = uuid.uuid4().hex[:8]
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """,
            f"orphan-host-{suffix}",
        )
        cve_id = f"CVE-2099-O{suffix.upper()}"
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ($1, 'orphan test')
            ON CONFLICT (cve_id) DO NOTHING
            """,
            cve_id,
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status)
            VALUES ($1, $2, 'high', 'libssl', '1.0.0', $3, 'open')
            """,
            node_id,
            cve_id,
            image,
        )
        return node_id, cve_id
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_orphan_cves_preview_counts(client, auth):
    """Orphan CVEs (image not in container_images) appear in preview."""
    await _seed_orphan_cve()
    r = await client.get("/api/v1/findings/orphan-cves/preview", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["cves_total"] >= 1
    assert data["image_count"] >= 1
    assert any(i["image"] == "ghost/oneuptime:v1" for i in data["images"])


@pytest.mark.anyio
async def test_orphan_cves_purge_resolves(client, auth):
    """Purge marks orphan CVEs resolved + persists cve_status decision."""
    node_id, cve_id = await _seed_orphan_cve(image="ghost/orphan-purge:42")

    r = await client.post("/api/v1/findings/orphan-cves/purge", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["cves_resolved"] >= 1

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
        just = await conn.fetchval(
            "SELECT justification FROM cve_status WHERE node_id = $1 AND cve_id = $2",
            node_id,
            cve_id,
        )
    finally:
        await conn.close()

    assert scan == "resolved"
    assert wf == "resolved"
    assert just == "image_orphan_manual_purge"


@pytest.mark.anyio
async def test_orphan_cves_skipped_for_registry_port_image(client, auth):
    """Regression : an image hosted on a registry-with-port (e.g.
    'localhost:5000/myapp:v1') used to be falsely flagged as orphan because
    the WHERE clause split on the FIRST colon while the collector splits on
    the LAST. A live container with a registry:port reference must not be
    swept by Purge orphan CVEs."""
    suffix = uuid.uuid4().hex[:8]
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """,
            f"reg-port-host-{suffix}",
        )
        # Collector path : rsplit(':', 1) → image='localhost:5000/myapp', tag='v1'
        img_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag)
            VALUES ('localhost:5000/myapp', 'v1')
            ON CONFLICT (image, tag) DO UPDATE SET last_updated = NOW()
            RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO containers (node_id, image_id, name)
            VALUES ($1, $2, $3)
            ON CONFLICT (node_id, name) DO NOTHING
            """,
            node_id,
            img_id,
            f"reg-port-live-{suffix}",
        )
        cve_id = f"CVE-2099-R{suffix.upper()}"
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description) VALUES ($1, 'rp')"
            " ON CONFLICT (cve_id) DO NOTHING",
            cve_id,
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status)
            VALUES ($1, $2, 'critical', 'libssl', '1.0.0',
                    'localhost:5000/myapp:v1', 'open')
            """,
            node_id,
            cve_id,
        )
    finally:
        await conn.close()

    await client.post("/api/v1/findings/orphan-cves/purge", headers=auth)

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        scan = await conn.fetchval(
            "SELECT status FROM cve_containers WHERE node_id = $1 AND cve_id = $2",
            node_id,
            cve_id,
        )
    finally:
        await conn.close()
    assert scan == "open", "registry:port image must not be classified as orphan"


@pytest.mark.anyio
async def test_orphan_cves_skipped_when_container_active(client, auth):
    """CVE whose image:tag still has a live container is left alone."""
    suffix = uuid.uuid4().hex[:8]
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """,
            f"keep-host-{suffix}",
        )
        img_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag)
            VALUES ('keepme/app', 'latest')
            ON CONFLICT (image, tag) DO UPDATE SET last_updated = NOW()
            RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO containers (node_id, image_id, name)
            VALUES ($1, $2, 'keepme-live')
            ON CONFLICT (node_id, name) DO NOTHING
            """,
            node_id,
            img_id,
        )
        cve_id = f"CVE-2099-K{suffix.upper()}"
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description) VALUES ($1, 'keep')"
            " ON CONFLICT (cve_id) DO NOTHING",
            cve_id,
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status)
            VALUES ($1, $2, 'high', 'libssl', '1.0.0',
                    'keepme/app:latest', 'open')
            """,
            node_id,
            cve_id,
        )
    finally:
        await conn.close()

    await client.post("/api/v1/findings/orphan-cves/purge", headers=auth)

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        scan = await conn.fetchval(
            "SELECT status FROM cve_containers WHERE node_id = $1 AND cve_id = $2",
            node_id,
            cve_id,
        )
    finally:
        await conn.close()
    assert scan == "open"


@pytest.mark.anyio
async def test_orphan_cves_purges_ghost_image(client, auth):
    """Ghost = container_images row with 0 containers → CVEs resolved + row dropped."""
    suffix = uuid.uuid4().hex[:8]
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """,
            f"ghost-host-{suffix}",
        )
        ghost_image = f"ghosty/app-{suffix}"
        img_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag)
            VALUES ($1, '1.0')
            ON CONFLICT (image, tag) DO UPDATE SET last_updated = NOW()
            RETURNING id
            """,
            ghost_image,
        )
        # Note : NO row inserted in containers — ghost.
        cve_id = f"CVE-2099-G{suffix.upper()}"
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description) VALUES ($1, 'ghost')"
            " ON CONFLICT (cve_id) DO NOTHING",
            cve_id,
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status)
            VALUES ($1, $2, 'high', 'libssl', '1.0.0', $3, 'open')
            """,
            node_id,
            cve_id,
            f"{ghost_image}:1.0",
        )
    finally:
        await conn.close()

    r = await client.post("/api/v1/findings/orphan-cves/purge", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["cves_resolved"] >= 1
    assert data["ghost_images_dropped"] >= 1

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        scan = await conn.fetchval(
            "SELECT status FROM cve_containers WHERE node_id = $1 AND cve_id = $2",
            node_id,
            cve_id,
        )
        ghost_left = await conn.fetchval(
            "SELECT 1 FROM container_images WHERE id = $1", img_id
        )
    finally:
        await conn.close()
    assert scan == "resolved"
    assert ghost_left is None


@pytest.mark.anyio
async def test_orphan_cves_purge_preserves_unrelated_ghost(client, auth):
    """Regression : Purge orphan CVEs used to run an unbounded
    DELETE FROM container_images that swept every ghost row in the table,
    not just the ones it had just resolved. A ghost image with NO orphan
    CVE/secret must survive the purge."""
    suffix = uuid.uuid4().hex[:8]
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """,
            f"keep-ghost-host-{suffix}",
        )
        # 1) Touched ghost — has an orphan CVE.
        touched_image = f"touched/app-{suffix}"
        touched_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag)
            VALUES ($1, '1.0')
            ON CONFLICT (image, tag) DO UPDATE SET last_updated = NOW()
            RETURNING id
            """,
            touched_image,
        )
        cve_id = f"CVE-2099-T{suffix.upper()}"
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description) VALUES ($1, 't')"
            " ON CONFLICT (cve_id) DO NOTHING",
            cve_id,
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status)
            VALUES ($1, $2, 'high', 'libssl', '1.0.0', $3, 'open')
            """,
            node_id,
            cve_id,
            f"{touched_image}:1.0",
        )

        # 2) Untouched ghost — no orphan CVE references it.
        spared_image = f"spared/app-{suffix}"
        spared_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag)
            VALUES ($1, '2.0')
            ON CONFLICT (image, tag) DO UPDATE SET last_updated = NOW()
            RETURNING id
            """,
            spared_image,
        )
    finally:
        await conn.close()

    r = await client.post("/api/v1/findings/orphan-cves/purge", headers=auth)
    assert r.status_code == 200

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        touched_left = await conn.fetchval(
            "SELECT 1 FROM container_images WHERE id = $1", touched_id
        )
        spared_left = await conn.fetchval(
            "SELECT 1 FROM container_images WHERE id = $1", spared_id
        )
    finally:
        await conn.close()
    assert touched_left is None, "touched ghost must be dropped"
    assert spared_left == 1, "ghost without any orphan finding must be preserved"


# Score


@pytest.mark.anyio
async def test_host_finding_score(client, auth, cve_finding):
    """Compute score for a host finding."""
    r = await client.get(
        f"/api/v1/findings/host/{cve_finding}/score",
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert "score" in data
    assert "inputs" in data
    assert "cve_id" in data
