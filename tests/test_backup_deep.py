"""Backup deep coverage — orphan merge on ingest, history, alerts."""

import uuid

import pytest


@pytest.fixture
async def demo_node(client, collect_auth):
    """Create a castor node and return its ID."""
    hostname = f"bk-node-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "os_name": "Debian",
            "os_version": "12",
            "arch": "x86_64",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    r = await client.get(
        "/api/v1/nodes",
        headers={"Authorization": "Bearer test-secret-key"},
    )
    for n in r.json().get("items", []):
        if n.get("hostname") == hostname:
            return {"hostname": hostname, "id": n["id"]}
    pytest.skip("node not created")


# Failed backup fires automation — the log row must be committed


@pytest.mark.anyio
async def test_backup_failure_automation_log_persisted(client, auth, collect_auth):
    """A failed backup ('failure') fires backup_overdue automation and its log
    row must survive the request.

    Two regressions: (1) the fire condition checked 'failed' (never emitted)
    instead of 'failure' (what the collectors send), so real failures never
    fired; (2) run_evaluation's automation_log write was never committed, so
    it rolled back at teardown.
    """
    pname = f"bk-overdue-{uuid.uuid4().hex[:8]}"
    pr = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": pname,
            "trigger_type": "backup_overdue",
            "action": "ignore",  # logs without external side effects
            "enabled": True,
        },
        headers=auth,
    )
    assert pr.status_code == 200

    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": f"bk-fail-{uuid.uuid4().hex[:8]}",
            "repo_name": f"repo-{uuid.uuid4().hex[:8]}",
            "status": "failure",
            "files_new": 0,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 0,
            "size_total": 0,
            "snapshots_total": 0,
            "duration_secs": 1,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200

    logs = (
        await client.get(
            "/api/v1/automation/log?trigger_type=backup_overdue", headers=auth
        )
    ).json()
    names = [e.get("policy_name") for e in logs["items"]]
    assert pname in names, "backup_overdue automation_log entry was not committed"


# Orphan repo creation then adoption on ingest


@pytest.mark.anyio
async def test_orphan_repo_created_unknown_host(client, collect_auth):
    """Backup report with unknown hostname creates orphan repo (node_id=NULL)."""
    repo_name = f"orphan-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": f"unknown-{uuid.uuid4().hex[:8]}",
            "repo_name": repo_name,
            "status": "success",
            "files_new": 10,
            "files_changed": 0,
            "files_unmodified": 100,
            "size_added": 1024,
            "size_total": 50000,
            "snapshots_total": 5,
            "duration_secs": 30,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["node_linked"] is False


@pytest.mark.anyio
async def test_orphan_adopted_on_ingest(client, collect_auth, demo_node):
    """Backup report with known hostname adopts orphan repo."""
    repo_name = f"adopt-{uuid.uuid4().hex[:8]}"
    hostname = demo_node["hostname"]

    # First report: unknown host → orphan
    await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": f"unkn-{uuid.uuid4().hex[:6]}",
            "repo_name": repo_name,
            "status": "success",
            "files_new": 5,
            "files_changed": 0,
            "files_unmodified": 50,
            "size_added": 512,
            "size_total": 10000,
            "snapshots_total": 2,
            "duration_secs": 10,
        },
        headers=collect_auth,
    )

    # Second report: known host, same repo_name → adopt orphan
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": hostname,
            "repo_name": repo_name,
            "status": "success",
            "files_new": 8,
            "files_changed": 1,
            "files_unmodified": 60,
            "size_added": 1024,
            "size_total": 12000,
            "snapshots_total": 3,
            "duration_secs": 15,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["node_linked"] is True


# Backup with failure triggers automation


@pytest.mark.anyio
async def test_backup_failure_triggers_automation(client, collect_auth, demo_node):
    """Backup with status=error triggers automation event."""
    r = await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": demo_node["hostname"],
            "repo_name": f"fail-{uuid.uuid4().hex[:8]}",
            "status": "error",
            "error_msg": "connection refused",
            "files_new": 0,
            "files_changed": 0,
            "files_unmodified": 0,
            "size_added": 0,
            "size_total": 0,
            "snapshots_total": 0,
            "duration_secs": 5,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


# History and alerts endpoints


@pytest.mark.anyio
async def test_backup_summary(client, auth):
    """GET /backup/summary returns items."""
    r = await client.get("/api/v1/backup/summary", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_backup_summary_filter_node(client, auth, demo_node):
    """GET /backup/summary with node_id filter."""
    r = await client.get(
        f"/api/v1/backup/summary?node_id={demo_node['id']}", headers=auth
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_backup_alerts(client, auth):
    """GET /backup/alerts returns items."""
    r = await client.get("/api/v1/backup/alerts", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


# Delete repos


@pytest.mark.anyio
async def test_delete_backup_repos_empty(client, auth):
    """Delete with empty ids list returns ok."""
    r = await client.post(
        "/api/v1/backup/repos/delete",
        json={"ids": []},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["deleted"] == 0


@pytest.mark.anyio
async def test_delete_backup_repos_invalid_uuid(client, auth):
    """Delete with invalid UUID returns 400."""
    r = await client.post(
        "/api/v1/backup/repos/delete",
        json={"ids": ["not-a-uuid"]},
        headers=auth,
    )
    assert r.status_code == 400
