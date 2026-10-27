"""Backup report — orphan/linked merge + error branches + automation failure."""

import asyncpg
import pytest

from .conftest import ASYNCPG_DSN


async def _seed_node(hostname: str) -> str:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        nid = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id::text
            """,
            hostname,
        )
        return nid
    finally:
        await conn.close()


async def _insert_orphan_repo(name: str) -> str:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        rid = await conn.fetchval(
            """
            INSERT INTO backup_repositories (node_id, name, repo_path)
            VALUES (NULL, $1, '/tmp/orphan')
            RETURNING id::text
            """,
            name,
        )
        return rid
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_backup_report_adopts_orphan(client, collect_auth, auth):
    """Orphan repo exists → gets adopted (node_id set) on new report."""
    hostname = "adopt-host"
    await _seed_node(hostname)
    orphan_id = await _insert_orphan_repo("sys-adopt")

    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": hostname,
            "repo_name": "sys-adopt",
            "repo_path": "/backups/adopt",
            "status": "success",
            "files_new": 1,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 1024,
            "duration_secs": 5,
            "source": "restic",
            "started_at": None,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    # The adopted orphan keeps the same id
    assert data["repo_id"] == orphan_id
    assert data["node_linked"] is True


@pytest.mark.anyio
async def test_backup_report_merges_orphan_into_linked(client, collect_auth):
    """Both linked + orphan exist → runs merge, orphan deleted."""
    hostname = "merge-host"
    node_id = await _seed_node(hostname)

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        linked_id = await conn.fetchval(
            """
            INSERT INTO backup_repositories (node_id, name, repo_path)
            VALUES (CAST($1 AS uuid), 'sys-merge', '/tmp/linked')
            RETURNING id::text
            """,
            node_id,
        )
        orphan_id = await conn.fetchval(
            """
            INSERT INTO backup_repositories (node_id, name, repo_path)
            VALUES (NULL, 'sys-merge', '/tmp/orphan')
            RETURNING id::text
            """
        )
    finally:
        await conn.close()

    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": hostname,
            "repo_name": "sys-merge",
            "repo_path": "/backups/merge",
            "status": "success",
            "files_new": 0,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 0,
            "duration_secs": 1,
            "source": "restic",
            "started_at": None,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["repo_id"] == linked_id

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        remaining = await conn.fetchval(
            "SELECT 1 FROM backup_repositories WHERE id = CAST($1 AS uuid)",
            orphan_id,
        )
        assert remaining is None
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_backup_report_short_hostname_fallback(client, collect_auth):
    """hostname with FQDN → falls back to short name before first dot."""
    await _seed_node("short-host")

    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "short-host.example.lan",
            "repo_name": "sys",
            "repo_path": "/p",
            "status": "success",
            "files_new": 0,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 0,
            "duration_secs": 1,
            "source": "restic",
            "started_at": None,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    # Should resolve to the short-name node
    assert r.json()["node_linked"] is True


@pytest.mark.anyio
async def test_backup_report_fires_automation_failure_swallowed(
    client, collect_auth, monkeypatch
):
    """Failed backup status fires automation — exception is swallowed."""
    import api.app.routes.backup as bmod

    async def _boom(*a, **kw):
        raise RuntimeError("automation boom")

    monkeypatch.setattr(bmod, "run_evaluation", _boom)

    await _seed_node("auto-fail-host")
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "auto-fail-host",
            "repo_name": "sys-autofail",
            "repo_path": "/p",
            "status": "error",
            "files_new": 0,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 0,
            "duration_secs": 1,
            "source": "restic",
            "started_at": None,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_backup_report_run_insert_failure(
    client, collect_auth, monkeypatch
):
    """DB error during run insert → status=error response, not raise."""
    import api.app.routes.backup as bmod

    original_execute = bmod.AsyncSession.execute

    call_count = {"n": 0}
    sentinel_sql = "INSERT INTO backup_runs"

    async def _execute(self, stmt, *a, **kw):
        text_str = getattr(stmt, "text", str(stmt))
        if sentinel_sql in str(text_str):
            call_count["n"] += 1
            raise RuntimeError("simulated run insert failure")
        return await original_execute(self, stmt, *a, **kw)

    monkeypatch.setattr(bmod.AsyncSession, "execute", _execute)

    await _seed_node("insert-fail-host")
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "insert-fail-host",
            "repo_name": "sys-ifail",
            "repo_path": "/p",
            "status": "success",
            "files_new": 0,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 0,
            "duration_secs": 1,
            "source": "restic",
            "started_at": None,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "error"
    assert "run insert failed" in data["detail"]
    assert call_count["n"] >= 1
