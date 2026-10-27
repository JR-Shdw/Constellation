# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Scheduler — CRUD jobs, manual trigger, run history, stats."""

import asyncio
import json

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..connectors.vault import VaultSealedError, require_vault_unsealed
from ..database import get_db
from ..models.schemas import SchedulerJobCreate, SchedulerJobPatch
from ..scheduler import compute_next_run
from ..utils.sql import where_clause

router = APIRouter(prefix="/api/v1/scheduler", tags=["scheduler"])


# Jobs CRUD


@router.get("/jobs")
async def list_jobs(
    job_type: str | None = Query(None),
    enabled: bool | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("scheduler", "r")),
):
    clauses = []
    params: dict = {}
    if job_type:
        clauses.append("job_type = :jt")
        params["jt"] = job_type
    if enabled is not None:
        clauses.append("enabled = :en")
        params["en"] = enabled
    where = where_clause(clauses)

    rows = await db.execute(
        text(f"""
        SELECT * FROM v_scheduler_summary {where}
        ORDER BY enabled DESC, name
        """),
        params,
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.post("/jobs")
async def create_job(
    payload: SchedulerJobCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("scheduler", "w")),
):
    if not croniter.is_valid(payload.cron_expr):
        return {"error": f"Invalid cron expression: {payload.cron_expr}"}

    # Compute first next_run_at in the job's timezone
    next_at = compute_next_run(payload.cron_expr, payload.timezone)

    result = await db.execute(
        text("""
        INSERT INTO scheduler_jobs
            (name, description, job_type, cron_expr, timezone, config,
             timeout_secs, max_retries, retry_delay_secs, allow_overlap,
             enabled, next_run_at, created_by)
        VALUES
            (:name, :desc, :jt, :cron, :tz, CAST(:config AS jsonb),
             :timeout, :retries, :retry_delay, :overlap,
             :enabled, :next_at, :actor)
        RETURNING id
        """),
        {
            "name": payload.name,
            "desc": payload.description,
            "jt": payload.job_type,
            "cron": payload.cron_expr,
            "tz": payload.timezone,
            "config": json.dumps(payload.config),
            "timeout": payload.timeout_secs,
            "retries": payload.max_retries,
            "retry_delay": payload.retry_delay_secs,
            "overlap": payload.allow_overlap,
            "enabled": payload.enabled,
            "next_at": next_at,
            "actor": actor,
        },
    )
    job_id = str(result.scalar_one())
    await log_action(
        db,
        actor=actor,
        action="create_job",
        target_type="scheduler_job",
        target_id=job_id,
        detail={"name": payload.name, "job_type": payload.job_type},
    )
    await db.commit()
    return {"status": "ok", "id": job_id}


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("scheduler", "r")),
):
    validate_uuid(job_id, "job_id")
    row = await db.execute(
        text("SELECT * FROM v_scheduler_summary WHERE id = CAST(:jid AS uuid)"),
        {"jid": job_id},
    )
    job = row.mappings().first()
    if not job:
        return {"error": "not found"}

    runs = await db.execute(
        text("""
        SELECT * FROM scheduler_runs
        WHERE job_id = CAST(:jid AS uuid)
        ORDER BY started_at DESC LIMIT 10
        """),
        {"jid": job_id},
    )
    return {
        "job": dict(job),
        "recent_runs": [dict(r._mapping) for r in runs],
    }


@router.put("/jobs/{job_id}")
async def update_job(
    job_id: str,
    payload: SchedulerJobPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("scheduler", "w")),
):
    validate_uuid(job_id, "job_id")
    data = payload.model_dump(exclude_unset=True)
    if not data:
        return {"error": "nothing to update"}

    # Validate cron if changed
    if "cron_expr" in data and not croniter.is_valid(data["cron_expr"]):
        return {"error": f"Invalid cron expression: {data['cron_expr']}"}

    field_map = {
        "name": "name",
        "description": "description",
        "job_type": "job_type",
        "cron_expr": "cron_expr",
        "timezone": "timezone",
        "config": "config",
        "timeout_secs": "timeout_secs",
        "max_retries": "max_retries",
        "retry_delay_secs": "retry_delay_secs",
        "allow_overlap": "allow_overlap",
        "enabled": "enabled",
    }

    sets = ["updated_at = NOW()"]
    params: dict = {"jid": job_id}
    for key, col in field_map.items():
        if key in data:
            val = data[key]
            if key == "config":
                sets.append(f"{col} = CAST(:{key} AS jsonb)")
                params[key] = json.dumps(val)
            else:
                sets.append(f"{col} = :{key}")
                params[key] = val

    # Recalculate next_run_at when the cron OR the timezone changes — both
    # affect the next fire time. Use the new values, falling back to the
    # stored ones for whichever field the patch didn't touch.
    if "cron_expr" in data or "timezone" in data:
        cur = (
            (
                await db.execute(
                    text(
                        "SELECT cron_expr, timezone FROM scheduler_jobs "
                        "WHERE id = CAST(:jid AS uuid)"
                    ),
                    {"jid": job_id},
                )
            )
            .mappings()
            .first()
        )
        cron_expr = data.get("cron_expr") or (cur["cron_expr"] if cur else None)
        tz_name = (
            data.get("timezone")
            if "timezone" in data
            else (cur["timezone"] if cur else None)
        )
        if cron_expr:
            sets.append("next_run_at = :next_at")
            params["next_at"] = compute_next_run(cron_expr, tz_name)

    await db.execute(
        text(
            f"UPDATE scheduler_jobs SET {', '.join(sets)} WHERE id = CAST(:jid AS uuid)"
        ),
        params,
    )
    await log_action(
        db,
        actor=actor,
        action="update_job",
        target_type="scheduler_job",
        target_id=job_id,
        detail=data,
    )
    await db.commit()
    return {"status": "ok"}


@router.delete("/jobs/{job_id}")
async def delete_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("scheduler", "w")),
):
    validate_uuid(job_id, "job_id")
    await db.execute(
        text("DELETE FROM scheduler_jobs WHERE id = CAST(:jid AS uuid)"),
        {"jid": job_id},
    )
    await log_action(
        db,
        actor=actor,
        action="delete_job",
        target_type="scheduler_job",
        target_id=job_id,
    )
    await db.commit()
    return {"status": "ok"}


# Toggle + Trigger


@router.post("/jobs/{job_id}/toggle")
async def toggle_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("scheduler", "w")),
):
    validate_uuid(job_id, "job_id")
    row = await db.execute(
        text(
            "SELECT enabled, cron_expr, timezone FROM scheduler_jobs "
            "WHERE id = CAST(:jid AS uuid)"
        ),
        {"jid": job_id},
    )
    job = row.mappings().first()
    if not job:
        return {"error": "not found"}

    new_enabled = not job["enabled"]
    params: dict = {"jid": job_id, "en": new_enabled}
    extra = ""

    # Recalculate next_run_at when re-enabling (honor the job's timezone)
    if new_enabled:
        params["next_at"] = compute_next_run(job["cron_expr"], job["timezone"])
        extra = ", next_run_at = :next_at"

    await db.execute(
        text(
            f"UPDATE scheduler_jobs SET enabled = :en, updated_at = NOW(){extra} "
            f"WHERE id = CAST(:jid AS uuid)"
        ),
        params,
    )
    await log_action(
        db,
        actor=actor,
        action="toggle_job",
        target_type="scheduler_job",
        target_id=job_id,
        detail={"enabled": new_enabled},
    )
    await db.commit()
    return {"status": "ok", "enabled": new_enabled}


@router.post("/jobs/{job_id}/trigger")
async def trigger_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("scheduler", "w")),
):
    validate_uuid(job_id, "job_id")

    try:
        await require_vault_unsealed()
    except VaultSealedError as e:
        raise HTTPException(503, str(e)) from e

    row = await db.execute(
        text("""
        SELECT id, name, job_type, cron_expr, timezone, config,
               timeout_secs, max_retries, retry_delay_secs, allow_overlap
        FROM scheduler_jobs WHERE id = CAST(:jid AS uuid)
        """),
        {"jid": job_id},
    )
    job = row.mappings().first()
    if not job:
        return {"error": "not found"}

    # Check overlap
    if not job["allow_overlap"]:
        running = await db.execute(
            text("""
            SELECT 1 FROM scheduler_runs
            WHERE job_id = CAST(:jid AS uuid) AND status = 'running'
            LIMIT 1
            """),
            {"jid": job_id},
        )
        if running.scalar_one_or_none():
            return {"error": "Job is already running"}

    await log_action(
        db,
        actor=actor,
        action="trigger_job",
        target_type="scheduler_job",
        target_id=job_id,
        detail={"name": job["name"]},
    )
    await db.commit()

    # Fire in background
    from ..scheduler import execute_job

    asyncio.create_task(execute_job(dict(job)))
    return {"status": "ok", "message": f"Job '{job['name']}' triggered"}


# Runs (history)


@router.get("/runs")
async def list_runs(
    job_id: str | None = Query(None),
    status: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("scheduler", "r")),
):
    offset = (page - 1) * per_page
    clauses = []
    params: dict = {"limit": per_page, "offset": offset}

    if job_id:
        clauses.append("job_id = CAST(:jid AS uuid)")
        params["jid"] = job_id
    if status:
        clauses.append("status = :status")
        params["status"] = status

    where = where_clause(clauses)

    total = (
        await db.execute(text(f"SELECT COUNT(*) FROM scheduler_runs {where}"), params)
    ).scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT * FROM scheduler_runs {where}
        ORDER BY started_at DESC
        LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("scheduler", "r")),
):
    validate_uuid(run_id, "run_id")
    row = await db.execute(
        text("SELECT * FROM scheduler_runs WHERE id = CAST(:rid AS uuid)"),
        {"rid": run_id},
    )
    run = row.mappings().first()
    if not run:
        return {"error": "not found"}
    return dict(run)


# Stats


@router.get("/stats")
async def scheduler_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("scheduler", "r")),
):
    row = await db.execute(
        text("""
        SELECT
            (SELECT COUNT(*) FROM scheduler_jobs) AS total_jobs,
            (SELECT COUNT(*) FROM scheduler_jobs WHERE enabled) AS enabled_jobs,
            (SELECT COUNT(*) FROM scheduler_runs
             WHERE status = 'running') AS running_jobs,
            (SELECT COUNT(*) FROM scheduler_runs
             WHERE started_at > NOW() - INTERVAL '24 hours') AS runs_24h,
            (SELECT COUNT(*) FROM scheduler_runs
             WHERE started_at > NOW() - INTERVAL '24 hours'
               AND status = 'success') AS success_24h,
            (SELECT COUNT(*) FROM scheduler_runs
             WHERE started_at > NOW() - INTERVAL '24 hours'
               AND status IN ('failure', 'timeout')) AS failure_24h
        """)
    )
    result = dict(row.mappings().first())

    # Next scheduled job
    nxt = await db.execute(
        text("""
        SELECT name, next_run_at FROM scheduler_jobs
        WHERE enabled = true AND next_run_at IS NOT NULL
        ORDER BY next_run_at LIMIT 1
        """)
    )
    nxt_row = nxt.mappings().first()
    if nxt_row:
        result["next_job_name"] = nxt_row["name"]
        result["next_job_at"] = nxt_row["next_run_at"]

    return result
