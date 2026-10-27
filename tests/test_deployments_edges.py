"""deployments.py — preflight vault/woodpecker branches, manager not-found,
_transition 404, submit-eval error, execute vault/404, Woodpecker trigger path."""

import uuid

import pytest


async def _create(client, auth, **over):
    data = {"title": f"dep-{uuid.uuid4().hex[:8]}", "deploy_type": "image_pull"}
    data.update(over)
    r = await client.post("/api/v1/deployments", json=data, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()["id"]


@pytest.mark.anyio
async def test_preflight_woodpecker_check(client, auth):
    """container_build/ansible_playbook deploy → woodpecker_available check
    (lines 341-344)."""
    dep_id = await _create(client, auth, deploy_type="container_build")
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    assert r.status_code == 200
    checks = r.json()["checks"]
    assert any(c["check"] == "woodpecker_available" for c in checks)


@pytest.mark.anyio
async def test_preflight_vault_configured(client, auth, monkeypatch):
    """vault_configured() true → vault_unsealed check added (lines 360-361)."""
    import api.app.connectors.vault as vault_mod

    monkeypatch.setattr(vault_mod, "vault_configured", lambda: True)

    async def _unsealed():
        return True

    monkeypatch.setattr(vault_mod, "vault_is_unsealed", _unsealed)

    dep_id = await _create(client, auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/preflight", headers=auth)
    assert r.status_code == 200
    checks = r.json()["checks"]
    assert any(c["check"] == "vault_unsealed" for c in checks)


@pytest.mark.anyio
async def test_submit_automation_eval_error_swallowed(client, auth, monkeypatch):
    """run_evaluation raising during /submit → logged, does not break submit
    (lines 473-474)."""
    import api.app.routes.deployments as dep_mod

    async def _boom(*a, **kw):
        raise RuntimeError("eval boom")

    monkeypatch.setattr(dep_mod, "run_evaluation", _boom)

    dep_id = await _create(client, auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    assert r.status_code == 200
    assert r.json()["new_status"] == "pending"


@pytest.mark.anyio
async def test_execute_vault_sealed_returns_503(client, auth, monkeypatch):
    """require_vault_unsealed raising → 503 (lines 522-523)."""
    import api.app.routes.deployments as dep_mod

    async def _boom():
        raise dep_mod.VaultSealedError("sealed")

    monkeypatch.setattr(dep_mod, "require_vault_unsealed", _boom)

    dep_id = await _create(client, auth)
    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    assert r.status_code == 503


@pytest.mark.anyio
async def test_execute_deployment_not_found(client, auth):
    """execute on missing deployment → 404 (line 532)."""
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.post(f"/api/v1/deployments/{fake}/execute", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_execute_container_build_triggers_woodpecker(client, auth, monkeypatch):
    """approved container_build deploy → Woodpecker trigger path (551-566)."""
    import api.app.routes.deployments as dep_mod
    from api.app.config import settings as app_settings

    # Force Woodpecker to appear configured
    monkeypatch.setattr(app_settings, "woodpecker_url", "http://wp.test", raising=False)
    monkeypatch.setattr(app_settings, "woodpecker_token", "tkn", raising=False)

    class _CI:
        async def list_repos(self):
            return [
                {"id": 1, "full_name": "shdw/repo-x"},
            ]

        async def trigger_pipeline(self, repo_id, branch, variables):
            return {"number": 42, "link": "http://wp.test/p/42"}

    monkeypatch.setattr(dep_mod, "get_ci", lambda *a, **kw: _CI())

    dep_id = await _create(
        client,
        auth,
        deploy_type="container_build",
        repo_name="shdw/repo-x",
        branch="main",
    )
    # Walk through submit → approve
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)

    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["new_status"] == "running"
    assert data["pipeline_number"] == 42


async def _deployment_status(dep_id: str) -> str:
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        return await conn.fetchval(
            "SELECT status FROM deployments WHERE id = CAST($1 AS uuid)", dep_id
        )
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_execute_container_build_woodpecker_failure_fails_deploy(
    client, auth, monkeypatch
):
    """A required Woodpecker trigger that errors must FAIL the deployment (502),
    not leave it stuck in 'running' with no pipeline behind it (it would never
    report back)."""
    import api.app.routes.deployments as dep_mod
    from api.app.config import settings as app_settings

    monkeypatch.setattr(app_settings, "woodpecker_url", "http://wp.test", raising=False)
    monkeypatch.setattr(app_settings, "woodpecker_token", "tkn", raising=False)

    def _boom(*a, **kw):
        raise RuntimeError("wp offline")

    monkeypatch.setattr(dep_mod, "get_ci", _boom)

    dep_id = await _create(
        client,
        auth,
        deploy_type="container_build",
        repo_name="shdw/repo-x",
        branch="main",
    )
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)

    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    assert r.status_code == 502
    assert await _deployment_status(dep_id) == "failure"


@pytest.mark.anyio
async def test_execute_container_build_repo_not_found_fails_deploy(
    client, auth, monkeypatch
):
    """Repo absent from Woodpecker → no pipeline starts → deployment fails (502),
    not a perpetual 'running'."""
    import api.app.routes.deployments as dep_mod
    from api.app.config import settings as app_settings

    monkeypatch.setattr(app_settings, "woodpecker_url", "http://wp.test", raising=False)
    monkeypatch.setattr(app_settings, "woodpecker_token", "tkn", raising=False)

    class _CI:
        async def list_repos(self):
            return [{"id": 9, "full_name": "shdw/other-repo"}]

    monkeypatch.setattr(dep_mod, "get_ci", lambda *a, **kw: _CI())

    dep_id = await _create(
        client,
        auth,
        deploy_type="container_build",
        repo_name="shdw/repo-x",
        branch="main",
    )
    await client.post(f"/api/v1/deployments/{dep_id}/submit", headers=auth)
    await client.post(f"/api/v1/deployments/{dep_id}/approve", headers=auth)

    r = await client.post(f"/api/v1/deployments/{dep_id}/execute", headers=auth)
    assert r.status_code == 502
    assert await _deployment_status(dep_id) == "failure"
