"""GET /cves/{id} — container finding branches + image_cves aggregation."""

import asyncpg
import pytest

from .conftest import ASYNCPG_DSN


async def _seed_container_cve(cve_id: str, image: str = "fooapp:v1"):
    """Seed a node + container cve + image_cve neighbor."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description, cvss_score, "
            "exploited, exploitability_context, kev) "
            "VALUES ($1, 'det', 7.5, false, 'unclear', false) "
            "ON CONFLICT (cve_id) DO UPDATE SET cvss_score = 7.5",
            cve_id,
        )
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('cve-det-node', 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver, fixed_ver,
                 image, target, fix_status, status)
            VALUES ($1, $2, 'high', 'libx', '1.0', '1.1', $3, 'foo',
                    'fixed_available', 'open')
            """,
            node_id,
            cve_id,
            image,
        )
        # Another CVE on the same image → exercises image_cves aggregation
        alt_cve = "CVE-2099-9999"
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description, cvss_score) "
            "VALUES ($1, 'alt', 6.1) ON CONFLICT (cve_id) DO NOTHING",
            alt_cve,
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver, fixed_ver,
                 image, target, fix_status, status)
            VALUES ($1, $2, 'medium', 'liby', '0.9', '1.0', $3, 'foo',
                    'fixed_available', 'open')
            """,
            node_id,
            alt_cve,
            image,
        )
        return node_id
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_cve_detail_includes_containers_and_image_cves(client, auth):
    """Container findings + sibling CVEs aggregated per image."""
    cve_id = "CVE-2099-5050"
    image = "cve-det-repo:v1"
    node_id = await _seed_container_cve(cve_id, image)
    assert node_id is not None

    r = await client.get(f"/api/v1/cves/{cve_id}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    containers = data["containers"]
    assert len(containers) >= 1
    c0 = containers[0]
    assert c0["image"] == image
    # score computed from compute_score
    assert "score" in c0
    # workflow_status defaults to open
    assert c0["workflow_status"] == "open"
    # trivy source added because containers is truthy
    assert "trivy" in data["sources"]
    # image_cves aggregates the sibling CVE
    assert image in data["image_cves"]
    alt_ids = {x["cve_id"] for x in data["image_cves"][image]}
    assert "CVE-2099-9999" in alt_ids


@pytest.mark.anyio
async def test_cve_detail_worst_severity_tracks_container(client, auth):
    """worst_sev walks containers too — critical container beats high host."""
    cve_id = "CVE-2099-7777"
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "INSERT INTO cve_catalog (cve_id, description, cvss_score) "
            "VALUES ($1, 'x', 9.8) ON CONFLICT (cve_id) DO NOTHING",
            cve_id,
        )
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('cve-worst-node', 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status)
            VALUES ($1, $2, 'critical', 'libz', '1',
                    'worst-app:v1', 'open')
            """,
            node_id,
            cve_id,
        )
    finally:
        await conn.close()

    r = await client.get(f"/api/v1/cves/{cve_id}", headers=auth)
    assert r.status_code == 200
    assert r.json()["severity"] == "critical"
