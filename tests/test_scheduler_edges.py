"""scheduler.py — 404 branches, enabled filter, update/config/cron recalc,
trigger_job overlap + vault-sealed paths, runs filters, stats next_job."""

import uuid
from datetime import timezone

import pytest

# compute_next_run — the job timezone must actually drive scheduling


def test_compute_next_run_utc_default():
    from api.app.scheduler import compute_next_run

    r = compute_next_run("0 9 * * *", None)
    assert r.utcoffset().total_seconds() == 0
    assert r.hour == 9  # 09:00 UTC


def test_compute_next_run_honors_timezone():
    """A daily '0 9 * * *' in Europe/Paris fires at 09:00 Paris, not UTC."""
    from api.app.scheduler import compute_next_run

    paris = compute_next_run("0 9 * * *", "Europe/Paris")
    # Paris is UTC+1 (CET) or UTC+2 (CEST) — proves tzdata resolved the zone
    # (a UTC fallback would give offset 0 and fail here).
    assert paris.utcoffset().total_seconds() in (3600, 7200)
    assert paris.hour == 9  # 09:00 local wall-clock
    assert paris.astimezone(timezone.utc).hour in (7, 8)  # earlier UTC instant


def test_compute_next_run_unknown_tz_falls_back_to_utc():
    from api.app.scheduler import compute_next_run

    r = compute_next_run("0 9 * * *", "Not/ARealZone")
    assert r.utcoffset().total_seconds() == 0


async def _make_job(client, auth, **over):
    """Helper: create a disabled job and return its id."""
    base = {
        "name": f"edge-{uuid.uuid4().hex[:8]}",
        "job_type": "http_request",
        "cron_expr": "0 */6 * * *",
        "config": {"method": "GET", "url": "/api/v1/health"},
        "enabled": False,
    }
    base.update(over)
    r = await client.post("/api/v1/scheduler/jobs", json=base, headers=auth)
    assert r.status_code == 200
    return r.json()["id"]


@pytest.mark.anyio
async def test_list_jobs_enabled_filter(client, auth):
    """list_jobs?enabled=false exercises the `enabled is not None` branch."""
    await _make_job(client, auth)
    r = await client.get("/api/v1/scheduler/jobs?enabled=false", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["enabled"] is False for i in items)


@pytest.mark.anyio
async def test_get_job_not_found(client, auth):
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.get(f"/api/v1/scheduler/jobs/{fake}", headers=auth)
    assert r.status_code == 200
    assert r.json() == {"error": "not found"}


@pytest.mark.anyio
async def test_update_job_empty_body(client, auth):
    jid = await _make_job(client, auth)
    r = await client.put(f"/api/v1/scheduler/jobs/{jid}", json={}, headers=auth)
    assert r.status_code == 200
    assert r.json() == {"error": "nothing to update"}


@pytest.mark.anyio
async def test_update_job_invalid_cron(client, auth):
    jid = await _make_job(client, auth)
    r = await client.put(
        f"/api/v1/scheduler/jobs/{jid}",
        json={"cron_expr": "not a cron"},
        headers=auth,
    )
    assert r.status_code == 200
    assert "Invalid cron" in r.json()["error"]


@pytest.mark.anyio
async def test_update_job_config_and_cron_recalc(client, auth):
    """Updating `config` hits the JSONB cast; updating `cron_expr` hits recalc."""
    jid = await _make_job(client, auth)
    r = await client.put(
        f"/api/v1/scheduler/jobs/{jid}",
        json={
            "config": {"method": "POST", "url": "/api/v1/health"},
            "cron_expr": "*/15 * * * *",
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_toggle_job_not_found(client, auth):
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.post(f"/api/v1/scheduler/jobs/{fake}/toggle", headers=auth)
    assert r.status_code == 200
    assert r.json() == {"error": "not found"}


@pytest.mark.anyio
async def test_trigger_job_not_found(client, auth):
    fake = "00000000-0000-0000-0000-000000000000"
    r = await client.post(f"/api/v1/scheduler/jobs/{fake}/trigger", headers=auth)
    assert r.status_code == 200
    assert r.json() == {"error": "not found"}


@pytest.mark.anyio
async def test_trigger_job_success(client, auth, monkeypatch):
    """Full trigger path with execute_job mocked + background task fires."""
    import api.app.scheduler as sched_mod

    called = {"n": 0}

    async def _fake_exec(job):
        called["n"] += 1

    monkeypatch.setattr(sched_mod, "execute_job", _fake_exec)

    jid = await _make_job(client, auth, allow_overlap=True)
    r = await client.post(f"/api/v1/scheduler/jobs/{jid}/trigger", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    # Background task is fire-and-forget — don't assert called["n"]


@pytest.mark.anyio
async def test_trigger_job_overlap_blocked(client, auth):
    """Insert a running run to force the overlap-check branch."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    jid = await _make_job(client, auth, allow_overlap=False)
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO scheduler_runs (job_id, job_name, status, started_at)
            VALUES (CAST($1 AS uuid), 'edge', 'running', NOW())
            """,
            jid,
        )
    finally:
        await conn.close()

    r = await client.post(f"/api/v1/scheduler/jobs/{jid}/trigger", headers=auth)
    assert r.status_code == 200
    assert "already running" in r.json().get("error", "")


@pytest.mark.anyio
async def test_trigger_job_vault_sealed_503(client, auth, monkeypatch):
    """Vault sealed → 503 via require_vault_unsealed raising VaultSealedError."""
    import api.app.routes.scheduler as sched_mod

    async def _boom():
        raise sched_mod.VaultSealedError("sealed")

    monkeypatch.setattr(sched_mod, "require_vault_unsealed", _boom)
    jid = await _make_job(client, auth)
    r = await client.post(f"/api/v1/scheduler/jobs/{jid}/trigger", headers=auth)
    assert r.status_code == 503


@pytest.mark.anyio
async def test_list_runs_filters(client, auth):
    """list_runs with both job_id + status filters (lines 346-350)."""
    jid = await _make_job(client, auth)
    r = await client.get(
        f"/api/v1/scheduler/runs?job_id={jid}&status=success",
        headers=auth,
    )
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_get_run_found_and_404(client, auth):
    """GET /runs/{id} — insert one then fetch + 404 branch (lines 380-388)."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    jid = await _make_job(client, auth)
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        run_id = await conn.fetchval(
            """
            INSERT INTO scheduler_runs (job_id, job_name, status, started_at)
            VALUES (CAST($1 AS uuid), 'edge', 'success', NOW())
            RETURNING id
            """,
            jid,
        )
    finally:
        await conn.close()

    r = await client.get(f"/api/v1/scheduler/runs/{run_id}", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "success"

    fake = "00000000-0000-0000-0000-000000000000"
    r2 = await client.get(f"/api/v1/scheduler/runs/{fake}", headers=auth)
    assert r2.status_code == 200
    assert r2.json() == {"error": "not found"}


@pytest.mark.anyio
async def test_tick_single_commit_for_multiple_due_jobs(client, auth, monkeypatch):
    """Regression guard for the double-execution race: _tick must advance ALL
    due jobs under ONE commit. The buggy version committed per-job inside the
    loop, releasing the FOR UPDATE locks on still-due rows mid-iteration. So a
    tick with N due jobs must produce exactly 1 commit, not N.
    """
    import asyncio

    import asyncpg
    from sqlalchemy.ext.asyncio import AsyncSession

    import api.app.scheduler as sched_mod

    from .conftest import ASYNCPG_DSN

    tag = uuid.uuid4().hex[:8]
    jid1 = await _make_job(client, auth, name=f"tick-{tag}-a", enabled=True)
    jid2 = await _make_job(client, auth, name=f"tick-{tag}-b", enabled=True)

    # Force both due (next_run_at in the past).
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        for jid in (jid1, jid2):
            await conn.execute(
                "UPDATE scheduler_jobs SET next_run_at = NOW() - INTERVAL '1 hour' "
                "WHERE id = CAST($1 AS uuid)",
                jid,
            )
    finally:
        await conn.close()

    # Don't actually run jobs — record dispatches instead.
    dispatched: list[str] = []

    async def _record(job):
        dispatched.append(job["name"])

    monkeypatch.setattr(sched_mod, "_execute_job_safe", _record)

    # Count commits during the tick. (The recorder above commits nothing, and a
    # test event loop runs only what we await, so every commit here is _tick's.)
    orig_commit = AsyncSession.commit
    commits = {"n": 0}

    async def _counting_commit(self):
        commits["n"] += 1
        return await orig_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", _counting_commit)

    await sched_mod._tick()
    await asyncio.sleep(0.05)  # let the create_task'd dispatches run

    # Exactly one commit regardless of how many due jobs were advanced.
    assert commits["n"] == 1, f"expected 1 commit, got {commits['n']}"
    # Both our jobs were advanced + dispatched in that single tick.
    assert f"tick-{tag}-a" in dispatched
    assert f"tick-{tag}-b" in dispatched


@pytest.mark.anyio
async def test_stats_next_job_branch(client, auth):
    """Create an enabled job → stats exposes next_job_name (lines 428-429)."""
    # Enabled so it has next_run_at
    await _make_job(client, auth, enabled=True)
    r = await client.get("/api/v1/scheduler/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total_jobs" in data
    # next_job_name present because at least one enabled job with next_run_at
    assert "next_job_name" in data
