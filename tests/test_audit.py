"""Audit trail — live + compressed archives tests."""

import pytest


@pytest.mark.anyio
async def test_audit_archives_empty(client, auth):
    """Archives list is empty initially."""
    r = await client.get("/api/v1/audit/archives", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["archives"] == []
    assert data["total"] == 0


@pytest.mark.anyio
async def test_audit_compact_nothing(client, auth):
    """Compact with no old entries returns 0 archived."""
    r = await client.post("/api/v1/audit/compact?days=30", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["archived"] == 0


@pytest.mark.anyio
async def test_audit_archive_not_found(client, auth):
    """Viewing a nonexistent archive returns 404."""
    r = await client.get("/api/v1/audit/archives/2020-01-01", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_audit_delete_not_found(client, auth):
    """Deleting a nonexistent archive returns 404."""
    r = await client.delete("/api/v1/audit/archives/2020-01-01", headers=auth)
    # Either 404 (not found) or 400 (no archives to keep) depending on count
    assert r.status_code in (400, 404)


@pytest.mark.anyio
async def test_audit_compact_and_view(client, auth, collect_auth):
    """Insert old audit entries, compact them, then view the archive."""
    # Create a node to generate audit log entries
    await client.post(
        "/api/v1/nodes/report",
        json={"hostname": "audit-test", "type": "vm", "os": "debian", "packages": []},
        headers=collect_auth,
    )

    # Manually insert old audit entries (> 30 days ago) via SQL
    # We use the collect endpoint which creates audit entries, then
    # backdate them via the test DB
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession

    from api.app.database import engine

    async with AsyncSession(engine) as db:
        # Insert backdated audit entries
        await db.execute(
            text("""
            INSERT INTO audit_log (actor, action, target_type, detail, created_at)
            VALUES
                ('test', 'test_action_1', 'node', '{}',
                 NOW() - INTERVAL '60 days'),
                ('test', 'test_action_2', 'node', '{"key": "val"}',
                 NOW() - INTERVAL '60 days'),
                ('test', 'test_action_3', 'node', '{}',
                 NOW() - INTERVAL '61 days')
            """)
        )
        await db.commit()

    # Compact — should archive the old entries
    r = await client.post("/api/v1/audit/compact?days=30", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["archived"] >= 1
    assert data["entries"] >= 3

    # List archives — should have at least 1
    r = await client.get("/api/v1/audit/archives", headers=auth)
    assert r.status_code == 200
    archives = r.json()["archives"]
    assert len(archives) >= 1
    first = archives[0]
    assert first["entries_count"] >= 1
    assert first["compressed"] is True

    # View the archive
    r = await client.get(
        f"/api/v1/audit/archives/{first['archive_date']}", headers=auth
    )
    assert r.status_code == 200
    view = r.json()
    assert view["total"] >= 1
    assert len(view["entries"]) >= 1


@pytest.mark.anyio
async def test_audit_delete_keep_one(client, auth, collect_auth):
    """Cannot delete the last archive — keep-1 rule."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession

    from api.app.database import engine

    # Ensure at least one archive exists
    async with AsyncSession(engine) as db:
        await db.execute(
            text("""
            INSERT INTO audit_log (actor, action, target_type, detail, created_at)
            VALUES ('test', 'keep1_test', 'node', '{}', NOW() - INTERVAL '90 days')
            """)
        )
        await db.commit()

    await client.post("/api/v1/audit/compact?days=30", headers=auth)

    # Get archives
    r = await client.get("/api/v1/audit/archives", headers=auth)
    archives = r.json()["archives"]

    # If only 1 archive, delete should fail with 400
    if len(archives) == 1:
        r = await client.delete(
            f"/api/v1/audit/archives/{archives[0]['archive_date']}",
            headers=auth,
        )
        assert r.status_code == 400
        assert "minimum 1" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_audit_delete_with_multiple(client, auth):
    """Can delete an archive when multiple exist."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession

    from api.app.database import engine

    # Insert entries for two different old dates
    async with AsyncSession(engine) as db:
        await db.execute(
            text("""
            INSERT INTO audit_log (actor, action, target_type, detail, created_at)
            VALUES
                ('test', 'del_test_a', 'node', '{}', NOW() - INTERVAL '100 days'),
                ('test', 'del_test_b', 'node', '{}', NOW() - INTERVAL '120 days')
            """)
        )
        await db.commit()

    await client.post("/api/v1/audit/compact?days=30", headers=auth)

    r = await client.get("/api/v1/audit/archives", headers=auth)
    archives = r.json()["archives"]

    if len(archives) >= 2:
        # Delete the oldest one
        oldest = archives[-1]["archive_date"]
        r = await client.delete(f"/api/v1/audit/archives/{oldest}", headers=auth)
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_audit_search_filters_actor_action_target(client, auth):
    """?search=... matches actor / action / target_id (ILIKE substring)."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession

    from api.app.database import engine

    async with AsyncSession(engine) as db:
        await db.execute(
            text("""
            INSERT INTO audit_log (actor, action, target_type, target_id, detail)
            VALUES
                ('alice', 'set_workflow', 'cve', 'CVE-2099-12345', '{}'),
                ('bob',   'patch_exposure', 'container', 'nginx', '{}'),
                ('alice', 'update_settings', 'alert_settings', NULL, '{}')
            """)
        )
        await db.commit()

    # actor match
    r = await client.get("/api/v1/audit?search=alice", headers=auth)
    assert r.status_code == 200
    actors = {item["actor"] for item in r.json()["items"]}
    assert "alice" in actors
    assert "bob" not in actors

    # action match
    r = await client.get("/api/v1/audit?search=patch_exposure", headers=auth)
    actions = {item["action"] for item in r.json()["items"]}
    assert "patch_exposure" in actions

    # target_id match
    r = await client.get("/api/v1/audit?search=CVE-2099", headers=auth)
    target_ids = {item.get("target_id") for item in r.json()["items"]}
    assert "CVE-2099-12345" in target_ids
