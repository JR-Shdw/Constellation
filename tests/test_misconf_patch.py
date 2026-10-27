"""Misconfigurations — PATCH /misconfigurations/{id}."""

import pytest


@pytest.fixture
async def _seeded_misconf(client, collect_auth):
    """Create a node + misconf, return its DB id."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "mc-patch-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/misconfigurations/report",
        json={
            "hostname": "mc-patch-node",
            "source": "trivy",
            "misconfigurations": [
                {
                    "ID": "PATCH-001",
                    "Title": "Patchable misconf",
                    "Severity": "HIGH",
                    "Target": "etc/foo",
                    "Message": "msg",
                    "Resolution": "fix it",
                    "Status": "FAIL",
                }
            ],
        },
        headers=collect_auth,
    )
    # Fetch the created row id via the list endpoint
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        row = await conn.fetchrow(
            "SELECT id::text AS id FROM misconfigurations "
            "WHERE rule_id = 'PATCH-001' LIMIT 1"
        )
    finally:
        await conn.close()
    return row["id"]


@pytest.mark.anyio
async def test_patch_misconf_status_ok(client, auth, _seeded_misconf):
    """Valid status transition returns ok."""
    r = await client.patch(
        f"/api/v1/misconfigurations/{_seeded_misconf}",
        json={"status": "mitigated"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_patch_misconf_status_invalid(client, auth, _seeded_misconf):
    """Invalid status returns 400."""
    r = await client.patch(
        f"/api/v1/misconfigurations/{_seeded_misconf}",
        json={"status": "garbage"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_patch_misconf_status_missing(client, auth, _seeded_misconf):
    """Empty body (status unset) → 400 (empty string is not a valid status)."""
    r = await client.patch(
        f"/api/v1/misconfigurations/{_seeded_misconf}",
        json={},
        headers=auth,
    )
    assert r.status_code == 400
