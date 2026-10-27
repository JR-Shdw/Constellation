"""Backup full tests — report, summary, history, alerts, patch repo."""

import pytest


@pytest.fixture
async def backup_node(client, collect_auth):
    """Create a node for backup tests."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "backup-full-node",
            "type": "bare_metal",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )


@pytest.fixture
async def backup_repo(client, collect_auth, backup_node):
    """Report a backup and return the repo_id."""
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "backup-full-node",
            "repo_name": "full-test-repo",
            "repo_path": "/backup/full-test",
            "status": "success",
            "files_new": 10,
            "files_changed": 5,
            "files_unmodified": 100,
            "size_added": 1024000,
            "size_total": 50000000,
            "snapshots_total": 30,
            "duration_secs": 120,
            "source": "restic",
            "started_at": "2026-04-07T10:00:00Z",
        },
        headers=collect_auth,
    )
    return r.json()["repo_id"]


# Report


@pytest.mark.anyio
async def test_backup_report_success(client, collect_auth, backup_node):
    """Report a successful backup."""
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "backup-full-node",
            "repo_name": "report-test",
            "status": "success",
            "files_new": 5,
            "files_changed": 2,
            "files_unmodified": 50,
            "size_added": 512000,
            "size_total": 10000000,
            "snapshots_total": 10,
            "duration_secs": 60,
            "source": "restic",
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["node_linked"] is True


@pytest.mark.anyio
async def test_backup_report_unknown_host(client, collect_auth):
    """Report backup for unknown host stores without node link."""
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "unknown-backup-host",
            "repo_name": "orphan-repo",
            "status": "success",
            "files_new": 0,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 0,
            "size_total": 0,
            "snapshots_total": 1,
            "duration_secs": 10,
            "source": "restic",
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["node_linked"] is False


# Summary


@pytest.mark.anyio
async def test_backup_summary(client, auth, backup_repo):
    """Backup summary returns items."""
    r = await client.get("/api/v1/backup/summary", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# History


@pytest.mark.anyio
async def test_backup_history(client, auth, backup_repo):
    """Backup history returns runs for a repo."""
    r = await client.get(f"/api/v1/backup/history/{backup_repo}", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
    assert len(r.json()["items"]) >= 1


# Alerts


@pytest.mark.anyio
async def test_backup_alerts(client, auth, backup_repo):
    """Backup alerts returns items."""
    r = await client.get("/api/v1/backup/alerts", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
