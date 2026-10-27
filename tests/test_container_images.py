"""Manual container-image cleanup tests."""

import asyncpg
import pytest

from .conftest import ASYNCPG_DSN


async def _seed_ghost_image():
    """Image with past CVEs but no live container — the 'ghost' case."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('manual-host', 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """
        )
        img_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag)
            VALUES ('ghost/oneuptime', 'v1') RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ('CVE-2099-1111', 'test') ON CONFLICT DO NOTHING
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 image, status)
            VALUES ($1, 'CVE-2099-1111', 'high', 'libx', '1',
                    'ghost/oneuptime:v1', 'open')
            """,
            node_id,
        )
        return node_id, img_id
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_delete_ghost_image_resolves_cves(client, auth):
    node_id, img_id = await _seed_ghost_image()

    r = await client.delete(f"/api/v1/container-images/{img_id}", headers=auth)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "ok"
    assert data["image"] == "ghost/oneuptime:v1"
    assert data["cves_resolved"] == 1

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        assert (
            await conn.fetchval("SELECT 1 FROM container_images WHERE id = $1", img_id)
        ) is None
        wf = await conn.fetchval(
            "SELECT status FROM cve_status WHERE node_id = $1 AND cve_id = $2",
            node_id,
            "CVE-2099-1111",
        )
        assert wf == "resolved"
        just = await conn.fetchval(
            "SELECT justification FROM cve_status WHERE node_id = $1 AND cve_id = $2",
            node_id,
            "CVE-2099-1111",
        )
        assert just.startswith("image_removed_manual_")
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_delete_image_refuses_if_container_exists(client, auth):
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('live-host', 'vm', 'debian', '12', 'amd64') RETURNING id
            """
        )
        img_id = await conn.fetchval(
            """
            INSERT INTO container_images (image, tag)
            VALUES ('live/app', 'v1') RETURNING id
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
    finally:
        await conn.close()

    r = await client.delete(f"/api/v1/container-images/{img_id}", headers=auth)
    assert r.status_code == 409
    assert "container" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_delete_image_not_found(client, auth):
    r = await client.delete(
        "/api/v1/container-images/00000000-0000-0000-0000-000000000000",
        headers=auth,
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_containers_hosts_exposes_image_id_and_tags(client, auth):
    """UI needs image_id + tags to offer the cleanup button."""
    await _seed_ghost_image()

    r = await client.get("/api/v1/containers/hosts?image=ghost/oneuptime", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "images" in data
    assert len(data["images"]) == 1
    row = data["images"][0]
    assert row["tag"] == "v1"
    assert row["container_count"] == 0
    assert row["id"]  # UUID string


@pytest.mark.anyio
async def test_grouped_exposure_reports_most_exposed(client, auth):
    """Grouped containers must report the WORST exposure, not lexicographic MAX.

    Regression: MAX(c.exposure) returned 'localhost' for a group that also had
    an 'internet' instance ('internet' < 'localhost' lexically), masking the
    most-exposed instance in the security-critical exposure column.
    """
    import uuid

    name = f"grp-ctr-{uuid.uuid4().hex[:8]}"
    img = f"acme/grp-{uuid.uuid4().hex[:8]}"
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        n1 = await conn.fetchval(
            "INSERT INTO nodes (hostname) VALUES ($1) RETURNING id", f"{name}-h1"
        )
        n2 = await conn.fetchval(
            "INSERT INTO nodes (hostname) VALUES ($1) RETURNING id", f"{name}-h2"
        )
        img_id = await conn.fetchval(
            "INSERT INTO container_images (image, tag) VALUES ($1, 'latest') "
            "RETURNING id",
            img,
        )
        await conn.execute(
            "INSERT INTO containers (node_id, image_id, name, exposure) "
            "VALUES ($1, $2, $3, 'localhost')",
            n1,
            img_id,
            name,
        )
        await conn.execute(
            "INSERT INTO containers (node_id, image_id, name, exposure) "
            "VALUES ($1, $2, $3, 'internet')",
            n2,
            img_id,
            name,
        )
    finally:
        await conn.close()

    r = await client.get(
        f"/api/v1/containers?group=true&search={name}", headers=auth
    )
    assert r.status_code == 200
    items = [i for i in r.json()["items"] if i["name"] == name]
    assert items, "grouped container not found"
    assert items[0]["exposure"] == "internet"
