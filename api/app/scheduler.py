# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Built-in job scheduler — asyncio background loop.

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
AI training: not authorized. TDM reservation per EU DSM directive (art. 4).
See: NOTICE, LICENSE-AI.md, /.well-known/tdmrep.json

Runs every TICK_INTERVAL seconds in the API process.
Multi-worker safe via FOR UPDATE SKIP LOCKED.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from croniter import croniter
from sqlalchemy import text

from .config import settings
from .connectors import get_ci
from .connectors.vault import VaultSealedError, require_vault_unsealed
from .database import async_session
from .notify import send_automation_notification

logger = logging.getLogger(__name__)

TICK_INTERVAL = 30  # seconds between checks


def compute_next_run(cron_expr: str, tz_name: str | None = None) -> datetime:
    """Next fire time for a cron, evaluated in the job's timezone (DST-aware).

    The cron is interpreted as local wall-clock time in tz_name (e.g.
    '0 9 * * *' in 'Europe/Paris' fires at 09:00 Paris, not 09:00 UTC). The
    returned datetime is tz-aware, so it stores into TIMESTAMPTZ as the right
    UTC instant. Falls back to UTC for an empty/unknown zone (and on a runtime
    with no tz database) rather than raising.
    """
    try:
        tz = ZoneInfo(tz_name) if tz_name else timezone.utc
    except (ZoneInfoNotFoundError, ValueError):
        tz = timezone.utc
    return croniter(cron_expr, datetime.now(tz)).get_next(datetime)


# Startup helpers


async def cleanup_stale_runs():
    """Mark runs stuck in 'running' for >2h as failed (crash recovery)."""
    async with async_session() as db:
        r = await db.execute(
            text("""
            UPDATE scheduler_runs SET
                status = 'failure',
                finished_at = NOW(),
                error_msg = 'Stale run cleaned up at startup'
            WHERE status = 'running'
              AND started_at < NOW() - INTERVAL '2 hours'
            """)
        )
        if r.rowcount:
            logger.info("[scheduler] Cleaned up %d stale runs", r.rowcount)
        await db.commit()


async def initialize_next_runs():
    """Compute next_run_at for jobs that don't have one yet."""
    async with async_session() as db:
        rows = await db.execute(
            text("""
            SELECT id, cron_expr, timezone FROM scheduler_jobs
            WHERE enabled = true AND next_run_at IS NULL
            """)
        )
        count = 0
        for row in rows.mappings():
            next_dt = compute_next_run(row["cron_expr"], row["timezone"])
            await db.execute(
                text("""
                UPDATE scheduler_jobs SET next_run_at = :next_at
                WHERE id = CAST(:jid AS uuid)
                """),
                {"next_at": next_dt, "jid": str(row["id"])},
            )
            count += 1
        if count:
            logger.info("[scheduler] Initialized next_run_at for %d jobs", count)
        await db.commit()


# Main loop


async def scheduler_loop():
    """Background loop — runs every TICK_INTERVAL seconds."""
    logger.info("[scheduler] Started (tick=%ds)", TICK_INTERVAL)
    while True:
        try:
            await _tick()
        except Exception:
            logger.exception("[scheduler] Tick failed")
        await asyncio.sleep(TICK_INTERVAL)


async def _tick():
    """Single tick — find due jobs and execute them.

    Every due job's next_run_at is advanced inside the single transaction that
    holds the FOR UPDATE locks, then committed once. Committing per-job would
    end the transaction and release the locks on the still-unprocessed (and
    still-due) rows mid-loop, letting a concurrent worker's tick re-select and
    re-dispatch them — a double-execution race. Holding the locks until every
    next_run_at is in the future closes that window.
    """
    async with async_session() as db:
        result = await db.execute(
            text("""
            SELECT id, name, job_type, cron_expr, timezone, config,
                   timeout_secs, max_retries, retry_delay_secs, allow_overlap
            FROM scheduler_jobs
            WHERE enabled = true AND next_run_at <= NOW()
            FOR UPDATE SKIP LOCKED
            """)
        )
        due_jobs = result.mappings().all()

        to_dispatch = []
        for job in due_jobs:
            # Overlap protection — skip execution (but still reschedule) when a
            # prior run of this job is still going.
            if not job["allow_overlap"]:
                running = await db.execute(
                    text("""
                    SELECT 1 FROM scheduler_runs
                    WHERE job_id = CAST(:jid AS uuid) AND status = 'running'
                    LIMIT 1
                    """),
                    {"jid": str(job["id"])},
                )
                if running.scalar_one_or_none():
                    logger.info("[scheduler] Skipping %s — still running", job["name"])
                    await _advance_next_run(db, job)
                    continue

            await _advance_next_run(db, job)
            to_dispatch.append(dict(job))

        # Single commit: the FOR UPDATE locks are held until every due row's
        # next_run_at is in the future, so no concurrent tick can re-select them.
        await db.commit()

        # Dispatch only after the schedule is durably advanced.
        for job in to_dispatch:
            asyncio.create_task(_execute_job_safe(job))


async def _advance_next_run(db, job):
    """Compute and set the next run time from cron expression."""
    next_dt = compute_next_run(job["cron_expr"], job.get("timezone"))
    await db.execute(
        text("""
        UPDATE scheduler_jobs
        SET next_run_at = :next_at, updated_at = NOW()
        WHERE id = CAST(:jid AS uuid)
        """),
        {"next_at": next_dt, "jid": str(job["id"])},
    )


# Job execution


async def _execute_job_safe(job: dict):
    """Wrapper — never crashes the event loop."""
    try:
        await execute_job(job)
    except Exception:
        logger.exception("[scheduler] Job %s crashed", job["name"])


async def execute_job(job: dict, attempt: int = 1):
    """Execute a single job. Called by tick or manual trigger."""
    job_id = str(job["id"])
    job_name = job["name"]

    # Vault gate — only for jobs that need external secrets (CI pipelines)
    job_type = job.get("job_type", "")
    if job_type in ("woodpecker_pipeline", "gitlab_pipeline"):
        try:
            await require_vault_unsealed()
        except VaultSealedError:
            logger.warning("[scheduler] %s skipped — vault sealed", job_name)
            async with async_session() as db:
                await db.execute(
                    text("""
                    INSERT INTO scheduler_runs
                        (job_id, job_name, status, attempt, error_msg, finished_at)
                    VALUES
                        (CAST(:jid AS uuid), :name, 'failure', :attempt,
                         'Vault sealed — execution blocked', NOW())
                    """),
                    {"jid": job_id, "name": job_name, "attempt": attempt},
                )
                await db.commit()
            return

    # Create run record
    async with async_session() as db:
        run_result = await db.execute(
            text("""
            INSERT INTO scheduler_runs (job_id, job_name, status, attempt)
            VALUES (CAST(:jid AS uuid), :name, 'running', :attempt)
            RETURNING id
            """),
            {"jid": job_id, "name": job_name, "attempt": attempt},
        )
        run_id = str(run_result.scalar_one())
        await db.commit()

    # Execute with timeout
    status = "success"
    error_msg = None
    result_data = {}
    timeout = job.get("timeout_secs", 300)

    try:
        result_data = await asyncio.wait_for(
            _run_job(job),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        status = "timeout"
        error_msg = f"Job timed out after {timeout}s"
        logger.warning("[scheduler] %s timed out after %ds", job_name, timeout)
    except Exception as e:
        status = "failure"
        error_msg = str(e)[:500]
        logger.error("[scheduler] %s failed: %s", job_name, e)

    # Update run + job
    async with async_session() as db:
        await db.execute(
            text("""
            UPDATE scheduler_runs SET
                status = :status,
                finished_at = NOW(),
                duration_secs = EXTRACT(EPOCH FROM (NOW() - started_at))::integer,
                result = CAST(:result AS jsonb),
                error_msg = :error,
                pipeline_number = :pnum,
                pipeline_link = :plink
            WHERE id = CAST(:rid AS uuid)
            """),
            {
                "status": status,
                "result": json.dumps(result_data or {}),
                "error": error_msg,
                "pnum": (result_data or {}).get("pipeline_number"),
                "plink": (result_data or {}).get("pipeline_link"),
                "rid": run_id,
            },
        )
        await db.execute(
            text("""
            UPDATE scheduler_jobs SET
                last_run_at = NOW(), last_status = :status, updated_at = NOW()
            WHERE id = CAST(:jid AS uuid)
            """),
            {"status": status, "jid": job_id},
        )
        await db.commit()

    # Retry on failure
    max_retries = job.get("max_retries", 0)
    if status == "failure" and attempt <= max_retries:
        delay = job.get("retry_delay_secs", 60)
        logger.info(
            "[scheduler] %s retry %d/%d in %ds",
            job_name,
            attempt,
            max_retries,
            delay,
        )
        await asyncio.sleep(delay)
        await execute_job(job, attempt + 1)
        return

    # Notify on final failure
    if status in ("failure", "timeout"):
        try:
            async with async_session() as db:
                await send_automation_notification(
                    "pipeline_failure",
                    f"[CMDB Scheduler] Job '{job_name}' {status}: "
                    f"{error_msg or 'unknown'}",
                    db,
                )
                await db.commit()
        except Exception:
            logger.warning("[scheduler] Failed to notify for %s", job_name)


# Type executors


async def _run_job(job: dict) -> dict:
    """Dispatch to the appropriate executor."""
    job_type = job["job_type"]
    config = job["config"]
    if isinstance(config, str):
        config = json.loads(config)

    timeout = job.get("timeout_secs", 300)

    if job_type == "woodpecker_pipeline":
        return await _run_woodpecker(config, job["name"])
    elif job_type == "gitlab_pipeline":
        return await _run_gitlab(config, job["name"])
    elif job_type == "http_request":
        return await _run_http(config, job["name"], timeout=timeout)
    elif job_type == "cve_feeds_fetch":
        return await _run_cve_feeds_fetch()
    else:
        raise ValueError(f"Unknown job type: {job_type}")


async def _run_cve_feeds_fetch() -> dict:
    """Iterate every enabled CVE feed and ingest fresh advisories.

    Raises RuntimeError when every feed errored — _fetch_all_feeds_internal
    swallows per-feed exceptions and returns counters, but execute_job needs
    a raise to mark the run as failure and trigger the failure notification.
    Mirrors the _run_woodpecker / _run_gitlab pattern of surfacing total
    failures as exceptions.
    """
    # Late imports : avoid a circular dep (routes import from app, scheduler
    # is imported from app/main).
    from .routes.cve_feeds import _fetch_all_feeds_internal
    from .routes.settings import feature_enabled

    async with async_session() as db:
        if not await feature_enabled("cve", db):
            # Feature was disabled — skip this tick rather than re-ingesting
            # advisories into freshly-truncated tables.
            return {"feeds": 0, "skipped": True, "reason": "cve module disabled"}
        summary = await _fetch_all_feeds_internal(db)

    # Total failure (DNS down, all sources 5xx, ...) must surface as a job
    # failure so the failure-only Matrix notification fires. Partial failures
    # (some feeds ok, some errored) stay 'success' — the individual feed rows
    # carry last_status='error' for follow-up.
    if summary.get("errors", 0) > 0 and summary.get("feeds", 0) == 0:
        raise RuntimeError(
            f"All CVE feeds failed ({summary['errors']} errors, 0 successes)"
        )
    return summary


async def _run_woodpecker(config: dict, job_name: str) -> dict:
    """Trigger a Woodpecker pipeline."""
    wp_url = settings.woodpecker_url
    wp_token = settings.woodpecker_token
    if not wp_url or not wp_token:
        raise RuntimeError(
            "Constellation/Apache-2.0 (author: shdw <contact@resurgamus.com>): "
            "Woodpecker not configured"
        )

    ci = get_ci("woodpecker", wp_url, wp_token)

    repo_name = config.get("repo_name", "")
    branch = config.get("branch", "main")
    variables = config.get("variables", {})

    if not repo_name:
        raise ValueError("config.repo_name required")

    # Find repo in Woodpecker
    wp_repos = await ci.list_repos()
    wp_repo = next(
        (r for r in wp_repos if r.get("full_name") == repo_name),
        None,
    )
    if not wp_repo:
        raise RuntimeError(f"Repo '{repo_name}' not found in Woodpecker")

    result = await ci.trigger_pipeline(wp_repo["id"], branch, variables)
    pnum = result.get("number")
    plink = result.get("link", "")

    logger.info("[scheduler] %s: triggered pipeline #%s", job_name, pnum)
    return {"pipeline_number": pnum, "pipeline_link": plink}


async def _run_gitlab(config: dict, job_name: str) -> dict:
    """Trigger a GitLab CI pipeline."""
    gl_url = settings.gitlab_url
    gl_token = settings.gitlab_token
    if not gl_url or not gl_token:
        raise RuntimeError("Constellation/Apache-2.0: GitLab not configured")

    ci = get_ci("gitlab", gl_url, gl_token)

    repo_name = config.get("repo_name", "")
    branch = config.get("branch", "main")
    variables = config.get("variables", {})

    if not repo_name:
        raise ValueError("config.repo_name required")

    result = await ci.trigger_pipeline(repo_name, branch, variables)
    pnum = result.get("number")
    plink = result.get("link", "")

    logger.info("[scheduler] %s: triggered GitLab pipeline #%s", job_name, pnum)
    return {"pipeline_number": pnum, "pipeline_link": plink}


async def _run_http(config: dict, job_name: str, timeout: int = 300) -> dict:
    """Execute an HTTP request."""
    method = config.get("method", "GET").upper()
    url = config.get("url", "")
    headers = dict(config.get("headers", {}))
    body = config.get("body")
    expected = config.get("expected_status", [200])

    if not url:
        raise ValueError("config.url required")

    # Relative URL → local API with auto-auth
    if url.startswith("/"):
        url = f"http://localhost:8000{url}"
        headers.setdefault("Authorization", f"Bearer {settings.secret_key}")

    async with httpx.AsyncClient(timeout=float(timeout)) as client:
        kwargs: dict = {"headers": headers}
        if body and method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = body

        r = await client.request(method, url, **kwargs)

        if r.status_code not in expected:
            raise RuntimeError(
                f"HTTP {r.status_code} (expected {expected}): {r.text[:300]}"
            )

        logger.info("[scheduler] %s: %s %s -> %d", job_name, method, url, r.status_code)

        try:
            return {"status_code": r.status_code, "body": r.json()}
        except Exception:
            return {"status_code": r.status_code, "body": r.text[:500]}
