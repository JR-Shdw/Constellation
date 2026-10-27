"""findings.py — cleanup filter branches, delete-by-id, delete-by-filter,
   container patch + score, invalid enum continues."""

import uuid

import asyncpg
import pytest

from .conftest import ASYNCPG_DSN


async def _seed_host_finding(cve_id: str | None = None) -> tuple[str, str]:
    """Insert a host CVE finding, return (finding_id, node_id)."""
    cve_id = cve_id or f"CVE-2099-{uuid.uuid4().int % 9000}"
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description, cvss_score, "
            "exploited, exploitability_context) "
            "VALUES ($1, 'd', 9.1, false, 'unclear') "
            "ON CONFLICT (cve_id) DO UPDATE SET cvss_score = 9.1",
            cve_id,
        )
        host = f"find-host-{uuid.uuid4().hex[:6]}"
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'x86_64')
            RETURNING id
            """,
            host,
        )
        fid = await conn.fetchval(
            """
            INSERT INTO cve_host_packages
                (node_id, cve_id, severity, pkg_name, installed_ver, fixed_ver,
                 source, fix_status, status)
            VALUES ($1, $2, 'critical', 'openssl', '3.0.11', '3.0.12',
                    'trivy', 'fixed_available', 'open')
            RETURNING id
            """,
            node_id,
            cve_id,
        )
        return str(fid), str(node_id)
    finally:
        await conn.close()


async def _seed_container_finding(cve_id: str, image: str = "findings-ctr:v1"):
    """Insert a cve_catalog + node + cve_containers row, return finding id."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description, cvss_score, "
            "exploited, exploitability_context) "
            "VALUES ($1, 'd', 7.5, false, 'unclear') "
            "ON CONFLICT (cve_id) DO UPDATE SET cvss_score = 7.5",
            cve_id,
        )
        host = f"find-edge-{uuid.uuid4().hex[:6]}"
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """,
            host,
        )
        fid = await conn.fetchval(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver, fixed_ver,
                 image, target, fix_status, status)
            VALUES ($1, $2, 'high', 'libfoo', '1.0', '1.1', $3, 'app',
                    'fixed_available', 'open')
            RETURNING id
            """,
            node_id,
            cve_id,
            image,
        )
        return str(fid), str(node_id)
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_patch_finding_invalid_enum_value_is_skipped(client, auth):
    """status='bogus' not in _ALLOWED_STATUS → skipped (line 72). No updates → error."""
    fid, _ = await _seed_host_finding()
    r = await client.patch(
        f"/api/v1/findings/host/{fid}",
        json={"status": "bogus_value_xyz"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json() == {"error": "no valid fields"}


@pytest.mark.anyio
async def test_patch_container_finding(client, auth):
    """PATCH /findings/container/{id} exercises container branch (line 136)."""
    fid, _ = await _seed_container_finding(f"CVE-2099-{uuid.uuid4().int % 9000}")
    r = await client.patch(
        f"/api/v1/findings/container/{fid}",
        json={"status": "resolved"},
        headers=auth,
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert body.get("updated") == 1


@pytest.mark.anyio
async def test_cleanup_preview_fix_status_filter(client, auth):
    """fix_status filter branch (lines 161-162)."""
    await _seed_host_finding()
    r = await client.get(
        "/api/v1/findings/cleanup/preview?fix_status=fixed_available",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cleanup_preview_os_arch_node_filters(client, auth):
    """os / arch / node_id filters (lines 175-184)."""
    _, node_id = await _seed_host_finding()
    r = await client.get(
        f"/api/v1/findings/cleanup/preview?os=debian&arch=x86_64&node_id={node_id}",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cleanup_preview_empty_where_triggers_severity_fix_breakdown(
    client, auth
):
    """status='notanenum' → filter skipped → `where` empty →
    breakdown builds 'WHERE severity=' / 'WHERE fix_status=' (lines 242, 266)."""
    await _seed_host_finding()
    r = await client.get(
        "/api/v1/findings/cleanup/preview?status=notanenum",
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert "by_severity" in data or "host_count" in data


@pytest.mark.anyio
async def test_cleanup_execute_delete_by_ids(client, auth):
    """action=delete + ids branch (line 306)."""
    fid, _ = await _seed_host_finding()
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "delete", "ids": [fid]},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_cleanup_execute_delete_by_filter(client, auth):
    """action=delete + filter (no ids) branch (line 355)."""
    r = await client.post(
        "/api/v1/findings/cleanup/execute",
        json={"action": "delete", "pkg_name": "nonexistent-zzz-pkg"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_host_finding_score_invalid_listen_fallback(client, auth):
    """listen='bogus' not in _ALLOWED_LISTEN → fallback (line 547)."""
    fid, _ = await _seed_host_finding()
    r = await client.get(
        f"/api/v1/findings/host/{fid}/score?listen=bogus_listen",
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["inputs"]["listen"] == "docker_internal"


@pytest.mark.anyio
async def test_container_finding_score(client, auth):
    """GET /findings/container/{id}/score covers lines 604-614."""
    fid, _ = await _seed_container_finding(
        f"CVE-2099-{uuid.uuid4().int % 9000}",
        image="cscore:v1",
    )
    r = await client.get(
        f"/api/v1/findings/container/{fid}/score",
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["finding_id"] == fid
    assert "score" in data
    assert "inputs" in data


@pytest.mark.anyio
async def test_container_finding_score_invalid_listen_fallback(client, auth):
    """listen='bogus' on container score → uses repo_listen fallback (604-605)."""
    fid, _ = await _seed_container_finding(
        f"CVE-2099-{uuid.uuid4().int % 9000}",
        image="cscore-fb:v1",
    )
    r = await client.get(
        f"/api/v1/findings/container/{fid}/score?listen=nope",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_container_finding_score_404(client, auth):
    """Unknown id → error."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.get(
        f"/api/v1/findings/container/{fake}/score",
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json() == {"error": "not found"}
