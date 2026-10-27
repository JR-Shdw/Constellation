"""Package updates tests — list and summary."""

import pytest


@pytest.mark.anyio
async def test_pkg_updates_list(client, auth):
    """List package updates returns paginated results."""
    r = await client.get("/api/v1/pkg-updates", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data


@pytest.mark.anyio
async def test_pkg_updates_summary(client, auth):
    """Package updates summary returns stats."""
    r = await client.get("/api/v1/pkg-updates/summary", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "packages_with_cves" in data
    assert "total_cves" in data
    assert "fixable" in data
    assert "critical" in data
    assert "exploited" in data


@pytest.mark.anyio
async def test_pkg_updates_filter_severity(client, auth):
    """List with severity filter."""
    r = await client.get("/api/v1/pkg-updates?severity=critical", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_pkg_updates_filter_search(client, auth):
    """List with search filter."""
    r = await client.get("/api/v1/pkg-updates?search=openssl", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_pkg_updates_filter_fix_status(client, auth):
    """List with fix_status filter."""
    r = await client.get("/api/v1/pkg-updates?fix_status=fixed_available", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_pkg_updates_search_matches_cve_id(client, auth, collect_auth):
    """?search= now matches CVE id, not just package name."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession

    from api.app.database import engine

    # Seed a node + a host_packages entry with a known pkg_name + cve_id.
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "pkg-search-host",
            "type": "vm",
            "os": "debian",
            "packages": [],
        },
        headers=collect_auth,
    )
    async with AsyncSession(engine) as db:
        node_row = (
            await db.execute(
                text("SELECT id FROM nodes WHERE hostname = :h"),
                {"h": "pkg-search-host"},
            )
        ).scalar_one()
        # cve_catalog row required by FK
        await db.execute(
            text("""
            INSERT INTO cve_catalog (cve_id)
            VALUES ('CVE-2099-77777')
            ON CONFLICT (cve_id) DO NOTHING
            """)
        )
        await db.execute(
            text("""
            INSERT INTO cve_host_packages
                (node_id, pkg_name, installed_ver, fixed_ver, cve_id, severity)
            VALUES
                (CAST(:nid AS uuid), 'curl-search', '7.0', '7.1',
                 'CVE-2099-77777', 'high')
            """),
            {"nid": str(node_row)},
        )
        await db.commit()

    # Match by CVE id (response groups by pkg_name with cve_ids[] array)
    r = await client.get("/api/v1/pkg-updates?search=CVE-2099-77777", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    cve_ids = {cve for item in items for cve in (item.get("cve_ids") or [])}
    assert "CVE-2099-77777" in cve_ids

    # Still matches by pkg_name
    r = await client.get("/api/v1/pkg-updates?search=curl-search", headers=auth)
    pkgs = {item.get("pkg_name") for item in r.json()["items"]}
    assert "curl-search" in pkgs
