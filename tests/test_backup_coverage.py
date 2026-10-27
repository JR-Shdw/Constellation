"""Backup coverage — report variations, history filters, repo management."""

import pytest


@pytest.fixture
async def backup_node(client, collect_auth):
    """Create a node for backup tests."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "backup-cov-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    return "backup-cov-node"


@pytest.mark.anyio
async def test_backup_report_with_stats(client, collect_auth, backup_node):
    """Backup report with full stats (size, files, duration)."""
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": backup_node,
            "repo_name": "repo-full-stats",
            "status": "success",
            "snapshot_id": "abc123def456",
            "size_bytes": 1073741824,
            "files_new": 150,
            "files_changed": 42,
            "files_unmodified": 9800,
            "duration_seconds": 345,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_backup_report_failure(client, collect_auth, backup_node):
    """Backup report with failure status."""
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": backup_node,
            "repo_name": "repo-failure-test",
            "status": "failure",
            "error_message": "repository lock held by PID 1234",
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_backup_report_partial(client, collect_auth, backup_node):
    """Backup report with partial status."""
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": backup_node,
            "repo_name": "repo-partial-test",
            "status": "partial",
            "error_message": "some files could not be read",
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_backup_summary_all(client, auth):
    """Backup summary returns all repos."""
    r = await client.get("/api/v1/backup/summary", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_backup_history_with_repo(client, auth, collect_auth, backup_node):
    """Backup history filtered by repo name."""
    # Create some data
    await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": backup_node,
            "repo_name": "history-repo",
            "status": "success",
        },
        headers=collect_auth,
    )
    # Get repo_id from summary
    r = await client.get("/api/v1/backup/summary", headers=auth)
    repos = r.json()["items"]
    repo_id = None
    for repo in repos:
        if repo.get("repo_name") == "history-repo":
            repo_id = str(repo["repo_id"])
            break
    assert repo_id, "repo not found in summary"
    r = await client.get(f"/api/v1/backup/history/{repo_id}", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_backup_alerts(client, auth):
    """Backup alerts returns failed/overdue/unconfigured."""
    r = await client.get("/api/v1/backup/alerts", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()
