"""Deployments — preflight checks, approve, reject, execute coverage."""

import uuid

import pytest


async def _create_deployment(client, auth, **overrides):
    """Helper: create a basic deployment and return its id."""
    data = {
        "title": f"deploy-{uuid.uuid4().hex[:8]}",
        "deploy_type": "image_pull",
    }
    data.update(overrides)
    r = await client.post("/api/v1/deployments", json=data, headers=auth)
    assert r.status_code == 200, f"create failed: {r.text}"
    return r.json()["id"]


# Preflight


@pytest.mark.anyio
async def test_preflight_draft(client, auth):
    """Preflight on draft deployment (no worker/repo set)."""
    dep_id = await _create_deployment(client, auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "checks" in data


@pytest.mark.anyio
async def test_preflight_not_found(client, auth):
    """Preflight on non-existent deployment returns 404."""
    fake_id = "00000000-0000-0000-0000-000000000001"
    r = await client.post(f"/api/v1/deployments/{fake_id}/preflight", headers=auth)
    assert r.status_code == 404


# Submit


@pytest.mark.anyio
async def test_submit_deployment(client, auth):
    """Submit a draft deployment transitions to pending."""
    dep_id = await _create_deployment(client, auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    assert r.status_code == 200
    assert r.json()["new_status"] == "pending"


@pytest.mark.anyio
async def test_submit_non_draft(client, auth):
    """Submit already-submitted deployment fails."""
    dep_id = await _create_deployment(client, auth)
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    assert r.status_code == 409


# Approve


@pytest.mark.anyio
async def test_approve_pending(client, auth):
    """Approve a pending deployment."""
    dep_id = await _create_deployment(client, auth)
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)
    assert r.status_code == 200
    assert r.json()["new_status"] == "approved"


@pytest.mark.anyio
async def test_approve_non_pending(client, auth):
    """Approve a draft deployment fails (must be pending)."""
    dep_id = await _create_deployment(client, auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)
    assert r.status_code == 409


# Reject


@pytest.mark.anyio
async def test_reject_pending(client, auth):
    """Reject a pending deployment."""
    dep_id = await _create_deployment(client, auth)
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    r = await client.post(
        f"/api/v1/deployments/{dep_id}/reject",
        json={"reason": "not ready"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["new_status"] == "cancelled"


# Execute


@pytest.mark.anyio
async def test_execute_approved(client, auth):
    """Execute an approved deployment (may fail without CI config)."""
    dep_id = await _create_deployment(client, auth)
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    # 200 = running, 503 = vault sealed
    assert r.status_code in (200, 503)


@pytest.mark.anyio
async def test_execute_non_approved(client, auth):
    """Execute a draft deployment fails."""
    dep_id = await _create_deployment(client, auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    assert r.status_code == 409


# Preflight — branch coverage for worker / repo / manager


@pytest.mark.anyio
async def test_preflight_worker_missing(client, auth):
    """worker_hostname set but no cicd_workers row → worker_exists false."""
    dep_id = await _create_deployment(
        client, auth, worker_hostname="ghost-worker"
    )
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "worker_exists" and c["ok"] is False for c in data["checks"]
    )


@pytest.mark.anyio
async def test_preflight_worker_offline(client, auth):
    """Seed a worker with status=offline → worker_online false."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO cicd_workers (external_id, ci_system, name, hostname, status)
            VALUES ('w1', 'woodpecker', 'w1', 'offworker', 'offline')
            """
        )
    finally:
        await conn.close()
    dep_id = await _create_deployment(client, auth, worker_hostname="offworker")
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "worker_online" and c["ok"] is False for c in data["checks"]
    )


@pytest.mark.anyio
async def test_preflight_worker_online(client, auth):
    """Seed a worker with status=online → worker_online true."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO cicd_workers (external_id, ci_system, name, hostname, status)
            VALUES ('w2', 'woodpecker', 'w2', 'upworker', 'idle')
            """
        )
    finally:
        await conn.close()
    dep_id = await _create_deployment(client, auth, worker_hostname="upworker")
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "worker_online" and c["ok"] is True for c in data["checks"]
    )


@pytest.mark.anyio
async def test_preflight_repo_missing(client, auth):
    """repo_name set but cicd_repositories row absent → repo_exists false."""
    dep_id = await _create_deployment(client, auth, repo_name="x/y-nope")
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "repo_exists" and c["ok"] is False for c in data["checks"]
    )


@pytest.mark.anyio
async def test_preflight_repo_without_ci(client, auth):
    """has_pipeline=false → repo_has_ci reports false."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO cicd_repositories
                (repo_name, forge, url, default_branch, has_pipeline)
            VALUES
                ('x/no-ci', 'gitea', 'https://gitea/x/no-ci', 'main', false)
            """
        )
    finally:
        await conn.close()
    dep_id = await _create_deployment(client, auth, repo_name="x/no-ci")
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "repo_has_ci" and c["ok"] is False for c in data["checks"]
    )


@pytest.mark.anyio
async def test_preflight_repo_with_ci(client, auth):
    """has_pipeline=true → repo_has_ci reports true."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO cicd_repositories
                (repo_name, forge, url, default_branch, has_pipeline)
            VALUES
                ('x/with-ci', 'gitea', 'https://gitea/x/with-ci', 'main', true)
            """
        )
    finally:
        await conn.close()
    dep_id = await _create_deployment(client, auth, repo_name="x/with-ci")
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "repo_has_ci" and c["ok"] is True for c in data["checks"]
    )


@pytest.mark.anyio
async def test_preflight_manager_connected(client, auth):
    """manager_id status=connected → manager_connected true."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        mgr_id = await conn.fetchval(
            """
            INSERT INTO container_managers
                (name, manager_type, url, token, status)
            VALUES
                ('preflight-mgr', 'portainer', 'https://p.example',
                 'tok', 'connected')
            RETURNING id
            """
        )
    finally:
        await conn.close()
    dep_id = await _create_deployment(client, auth, manager_id=str(mgr_id))
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "manager_connected" and c["ok"] is True
        for c in data["checks"]
    )


@pytest.mark.anyio
async def test_preflight_manager_disconnected(client, auth):
    """manager status=error → manager_connected false."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        mgr_id = await conn.fetchval(
            """
            INSERT INTO container_managers
                (name, manager_type, url, token, status)
            VALUES
                ('preflight-err-mgr', 'portainer', 'https://p.example',
                 'tok', 'error')
            RETURNING id
            """
        )
    finally:
        await conn.close()
    dep_id = await _create_deployment(client, auth, manager_id=str(mgr_id))
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    data = r.json()
    assert any(
        c["check"] == "manager_connected" and c["ok"] is False
        for c in data["checks"]
    )


# Patch coverage — worker_hostname, manager_id, config branches


@pytest.mark.anyio
async def test_patch_deployment_fields(client, auth):
    """PATCH worker_hostname / manager_id / config exercises the remaining
    branches of the set_clauses builder."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        mgr_id = await conn.fetchval(
            """
            INSERT INTO container_managers
                (name, manager_type, url, token, status)
            VALUES
                ('patch-mgr', 'portainer', 'https://p.example',
                 'tok', 'connected')
            RETURNING id
            """
        )
    finally:
        await conn.close()

    dep_id = await _create_deployment(client, auth)
    r = await client.put(
        f"/api/v1/deployments/{dep_id}",
        json={
            "worker_hostname": "w1",
            "manager_id": str(mgr_id),
            "config": {"foo": "bar"},
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["changed"] is True


@pytest.mark.anyio
async def test_patch_deployment_no_changes(client, auth):
    """PATCH with only unknown/empty fields → changed=false."""
    dep_id = await _create_deployment(client, auth)
    r = await client.put(
        f"/api/v1/deployments/{dep_id}", json={}, headers=auth
    )
    assert r.status_code == 200
    assert r.json()["changed"] is False
