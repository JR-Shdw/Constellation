"""cicd/pipelines.py — duration computation, failure eval swallowed,
   trigger get_ci/list_repos/trigger errors."""

import pytest


@pytest.mark.anyio
async def test_pipeline_failure_automation_eval_error_swallowed(
    client, collect_auth, monkeypatch
):
    """run_evaluation raises on failure ingestion → logged, ingestion continues
    (lines 96-97)."""
    import api.app.routes.cicd.pipelines as pmod

    async def _boom(*a, **kw):
        raise RuntimeError("eval boom")

    monkeypatch.setattr(pmod, "run_evaluation", _boom)

    r = await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": "edge/ci-fail",
                "number": 93,
                "status": "failure",
            }
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


@pytest.mark.anyio
async def test_trigger_pipeline_get_ci_valueerror(
    client, auth, monkeypatch
):
    """get_ci raising ValueError (unknown ci_system) → 400 (lines 181-182)."""
    import api.app.routes.cicd.pipelines as pmod
    from api.app.config import settings as app_settings

    monkeypatch.setattr(
        app_settings, "woodpecker_url", "http://wp", raising=False
    )
    monkeypatch.setattr(
        app_settings, "woodpecker_token", "x", raising=False
    )

    def _raise(*a, **kw):
        raise ValueError("unknown ci")

    monkeypatch.setattr(pmod, "get_ci", _raise)

    r = await client.post(
        "/api/v1/cicd/pipelines/trigger",
        json={
            "ci_system": "woodpecker",
            "repo_name": "edge/trig",
            "branch": "main",
        },
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_trigger_pipeline_list_repos_error_502(
    client, auth, monkeypatch
):
    """list_repos raising → 502 (lines 187-188)."""
    import api.app.routes.cicd.pipelines as pmod
    from api.app.config import settings as app_settings

    monkeypatch.setattr(
        app_settings, "woodpecker_url", "http://wp", raising=False
    )
    monkeypatch.setattr(
        app_settings, "woodpecker_token", "x", raising=False
    )

    class _CI:
        async def list_repos(self):
            raise RuntimeError("wp down")

    monkeypatch.setattr(pmod, "get_ci", lambda *a, **kw: _CI())

    r = await client.post(
        "/api/v1/cicd/pipelines/trigger",
        json={
            "ci_system": "woodpecker",
            "repo_name": "edge/trig",
            "branch": "main",
        },
        headers=auth,
    )
    assert r.status_code == 502


@pytest.mark.anyio
async def test_trigger_pipeline_trigger_error_502(
    client, auth, monkeypatch
):
    """trigger_pipeline raising → 502 (lines 198-199). Uses gitlab path so
    it skips the Woodpecker list_repos lookup."""
    import api.app.routes.cicd.pipelines as pmod
    from api.app.config import settings as app_settings

    monkeypatch.setattr(
        app_settings, "gitlab_url", "http://gl", raising=False
    )
    monkeypatch.setattr(
        app_settings, "gitlab_token", "x", raising=False
    )

    class _CI:
        async def trigger_pipeline(self, repo_id, branch, variables):
            raise RuntimeError("trigger exploded")

    monkeypatch.setattr(pmod, "get_ci", lambda *a, **kw: _CI())

    r = await client.post(
        "/api/v1/cicd/pipelines/trigger",
        json={
            "ci_system": "gitlab",
            "repo_name": "grp/proj",
            "branch": "main",
        },
        headers=auth,
    )
    assert r.status_code == 502
