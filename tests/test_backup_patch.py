"""Backup patch coverage — assign node, merge repos, patch_backup_repo."""

import uuid

import pytest


@pytest.fixture
async def backup_node(client, collect_auth, auth):
    """Create a node with a backup repo and return IDs."""
    hostname = f"bk-patch-{uuid.uuid4().hex[:8]}"
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
    # Get node_id
    r = await client.get("/api/v1/nodes", headers=auth)
    node = next(
        (n for n in r.json()["items"] if n["hostname"] == hostname),
        None,
    )
    if not node:
        pytest.skip("node not created")

    # Create a backup repo linked to this node
    repo_name = f"repo-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": hostname,
            "repo_name": repo_name,
            "status": "success",
            "files_new": 5,
            "files_changed": 1,
            "files_unmodified": 100,
            "size_added": 1024,
            "size_total": 50000,
            "snapshots_total": 3,
            "duration_secs": 30,
        },
        headers=collect_auth,
    )

    # Get repo_id from summary
    r = await client.get(f"/api/v1/backup/summary?node_id={node['id']}", headers=auth)
    items = r.json().get("items", [])
    repo_id = items[0]["repo_id"] if items else None

    return {
        "hostname": hostname,
        "node_id": node["id"],
        "repo_name": repo_name,
        "repo_id": str(repo_id) if repo_id else None,
    }


@pytest.fixture
async def orphan_repo(client, collect_auth, auth):
    """Create an orphan backup repo (no node_id)."""
    repo_name = f"orphan-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": f"unknown-{uuid.uuid4().hex[:6]}",
            "repo_name": repo_name,
            "status": "success",
            "files_new": 2,
            "files_changed": 0,
            "files_unmodified": 50,
            "size_added": 512,
            "size_total": 10000,
            "snapshots_total": 1,
            "duration_secs": 10,
        },
        headers=collect_auth,
    )
    # Find orphan repo in summary
    r = await client.get("/api/v1/backup/summary", headers=auth)
    items = r.json().get("items", [])
    repo = next(
        (i for i in items if i.get("repo_name") == repo_name),
        None,
    )
    return {
        "repo_name": repo_name,
        "repo_id": str(repo["repo_id"]) if repo else None,
    }


# Patch: assign node to orphan repo


@pytest.mark.anyio
async def test_patch_assign_node(client, auth, backup_node, orphan_repo):
    """Assign a node_id to an orphan backup repo."""
    if not orphan_repo["repo_id"]:
        pytest.skip("orphan repo not found")

    r = await client.patch(
        f"/api/v1/backup/repos/{orphan_repo['repo_id']}",
        json={"node_id": backup_node["node_id"]},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# Patch: merge duplicate repos


@pytest.mark.anyio
async def test_patch_merge_duplicate(client, auth, collect_auth):
    """Assigning node creates merge when duplicate name exists."""
    hostname = f"merge-{uuid.uuid4().hex[:8]}"
    repo_name = f"shared-{uuid.uuid4().hex[:8]}"

    # Create node
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

    # Create linked repo (known host)
    await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": hostname,
            "repo_name": repo_name,
            "status": "success",
            "files_new": 1,
            "files_changed": 0,
            "files_unmodified": 10,
            "size_added": 100,
            "size_total": 1000,
            "snapshots_total": 1,
            "duration_secs": 5,
        },
        headers=collect_auth,
    )

    # Create orphan repo with same name
    await client.post(
        "/api/v1/backup/report",
        json={
            "hostname": f"unknown-{uuid.uuid4().hex[:6]}",
            "repo_name": repo_name,
            "status": "success",
            "files_new": 2,
            "files_changed": 0,
            "files_unmodified": 20,
            "size_added": 200,
            "size_total": 2000,
            "snapshots_total": 2,
            "duration_secs": 8,
        },
        headers=collect_auth,
    )

    # Get node_id
    r = await client.get("/api/v1/nodes", headers=auth)
    node = next(
        (n for n in r.json()["items"] if n["hostname"] == hostname),
        None,
    )
    if not node:
        pytest.skip("node not found")

    # Find orphan repo
    r = await client.get("/api/v1/backup/summary", headers=auth)
    orphan = next(
        (
            i
            for i in r.json()["items"]
            if i.get("repo_name") == repo_name and not i.get("node_id")
        ),
        None,
    )
    if not orphan:
        pytest.skip("orphan not found")

    # Patch: assign node → should merge
    r = await client.patch(
        f"/api/v1/backup/repos/{orphan['repo_id']}",
        json={"node_id": node["id"]},
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "merged_into" in data


# History endpoint


@pytest.mark.anyio
async def test_backup_history(client, auth, backup_node):
    """GET /backup/history/{repo_id} returns runs."""
    if not backup_node["repo_id"]:
        pytest.skip("no repo")

    r = await client.get(
        f"/api/v1/backup/history/{backup_node['repo_id']}",
        headers=auth,
    )
    assert r.status_code == 200
    assert "items" in r.json()
    assert len(r.json()["items"]) >= 1
