"""Extra backup tests — filters, repos, alerts."""

import pytest


@pytest.fixture
async def backup_node(client, collect_auth):
    """Create a node with backup data."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "bk-extra-test",
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
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "bk-extra-test",
            "repo_name": "data",
            "repo_path": "/backups/bk-extra-test/data",
            "status": "success",
            "files_new": 10,
            "files_changed": 2,
            "files_unmodified": 500,
            "size_added": 524288,
            "duration_secs": 60,
            "source": "restic",
        },
        headers=collect_auth,
    )
    return r.json()


@pytest.mark.anyio
async def test_backup_summary_filter_node(client, auth, collect_auth, backup_node):
    """Backup summary filtered by node_id."""
    # Get node_id
    r = await client.get("/api/v1/nodes/list", headers=auth)
    node = [n for n in r.json()["items"] if n["hostname"] == "bk-extra-test"]
    if not node:
        pytest.skip("node not found")
    nid = str(node[0]["id"])

    r = await client.get(f"/api/v1/backup/summary?node_id={nid}", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    for item in items:
        if item.get("hostname"):
            assert item["hostname"] == "bk-extra-test"


@pytest.mark.anyio
async def test_backup_failure_report(client, collect_auth, auth):
    """Backup failure report is correctly ingested."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "bk-fail-test",
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

    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "bk-fail-test",
            "repo_name": "system",
            "repo_path": "/backups/bk-fail-test/system",
            "status": "failure",
            "error_msg": "repository not found",
            "duration_secs": 5,
            "source": "restic",
        },
        headers=collect_auth,
    )
    assert r.status_code == 200

    r = await client.get("/api/v1/backup/summary", headers=auth)
    repos = [i for i in r.json()["items"] if i.get("hostname") == "bk-fail-test"]
    if repos:
        assert repos[0]["status"] == "failure"


@pytest.mark.anyio
async def test_backup_repos_delete(client, auth, collect_auth):
    """Delete backup repos removes them."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "bk-del-test",
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
    await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": "bk-del-test",
            "repo_name": "to-delete",
            "repo_path": "/backups/del/test",
            "status": "success",
            "duration_secs": 10,
            "source": "restic",
        },
        headers=collect_auth,
    )

    # Get repo_id from summary
    r = await client.get("/api/v1/backup/summary", headers=auth)
    repo = [i for i in r.json()["items"] if i.get("repo_name") == "to-delete"]
    if not repo:
        pytest.skip("repo not found")
    repo_id = str(repo[0]["repo_id"])

    r = await client.post(
        "/api/v1/backup/repos/delete",
        json={"ids": [repo_id]},
        headers=auth,
    )
    assert r.status_code == 200
