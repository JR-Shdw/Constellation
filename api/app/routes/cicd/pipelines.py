# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Pipelines — ingestion, listing, trigger."""

import json
from datetime import datetime

from fastapi import Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_collect_token, require_permission
from ...connectors import get_ci
from ...connectors.vault import VaultSealedError, require_vault_unsealed
from ...database import get_db
from ...utils.sql import set_statement_timeout
from ..automation import run_evaluation
from . import _resolve_ci_credentials, logger, router


def _parse_ts(val):
    """Parse ISO string to datetime; passthrough if already datetime."""
    if val is None or isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


@router.post("/pipelines/report")
async def pipelines_report(
    payload: list[dict],
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Upsert CI/CD pipeline runs from sync scripts."""
    await set_statement_timeout(db, "batch")
    upserted = 0
    for run in payload:
        repo_name = run.get("repo_name", "")
        number = run.get("number") or run.get("pipeline_number")
        ci_sys = run.get("ci_system", "woodpecker")
        if not repo_name or not number:
            continue

        started = _parse_ts(run.get("started_at") or run.get("created_at"))
        finished = _parse_ts(run.get("finished_at"))
        duration = run.get("duration_secs")
        if not duration and started and finished:
            duration = max(0, int((finished - started).total_seconds()))

        message = run.get("commit_message") or run.get("message", "")
        if len(message) > 500:
            message = message[:500]

        result = await db.execute(
            text("""
            WITH prev AS (
                SELECT status AS old_status FROM cicd_pipelines
                WHERE ci_system = :ci_sys AND repo_name = :repo_name
                  AND pipeline_number = :number
            )
            INSERT INTO cicd_pipelines
                (ci_system, repo_name, pipeline_number, status, event,
                 branch, commit_sha, commit_message, author,
                 duration_secs, started_at, finished_at, link, raw)
            VALUES
                (:ci_sys, :repo_name, :number, :status, :event,
                 :branch, :sha, :message, :author,
                 :duration, :started_at, :finished_at, :link,
                 CAST(:raw AS jsonb))
            ON CONFLICT (ci_system, repo_name, pipeline_number)
            DO UPDATE SET
                status         = EXCLUDED.status,
                duration_secs  = EXCLUDED.duration_secs,
                finished_at    = EXCLUDED.finished_at,
                raw            = EXCLUDED.raw
            RETURNING (SELECT old_status FROM prev) AS old_status
            """),
            {
                "ci_sys": ci_sys,
                "repo_name": repo_name,
                "number": number,
                "status": run.get("status", "pending"),
                "event": run.get("event"),
                "branch": run.get("branch"),
                "sha": run.get("commit") or run.get("commit_sha", ""),
                "message": message,
                "author": run.get("author") or run.get("author_login", ""),
                "duration": duration,
                "started_at": started,
                "finished_at": finished,
                "link": run.get("link", ""),
                "raw": json.dumps(run.get("raw", {})),
            },
        )
        prev_status = result.scalar()
        upserted += 1

        # Fire pipeline_failure only on the transition into failure, not on
        # every re-ingestion of an already-known failure. The sync re-sends the
        # last N pipelines each cycle; without this guard a single failed run
        # re-fires the automation (and its notification, which has no dedup
        # ledger) every sync until it scrolls out of the window.
        if run.get("status") == "failure" and prev_status != "failure":
            try:
                await run_evaluation(
                    {
                        "trigger_type": "pipeline_failure",
                        "hostname": run.get("author", ""),
                        "container": repo_name,
                    },
                    db,
                )
            except Exception as e:
                logger.warning(
                    "[cicd] automation eval failed for pipeline %s#%s: %s",
                    repo_name,
                    number,
                    e,
                )

    await db.commit()
    logger.info("[cicd] pipelines upserted: %d", upserted)
    return {"status": "ok", "upserted": upserted}


@router.get("/pipelines")
async def list_pipelines(
    repo: str | None = Query(None),
    status: str | None = Query(None),
    event: str | None = Query(None),
    size: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "r")),
):
    """List pipeline runs with optional filters."""
    conditions = []
    params: dict = {"limit": size, "offset": offset}

    if repo:
        conditions.append("p.repo_name = :repo")
        params["repo"] = repo
    if status:
        conditions.append("p.status = :status")
        params["status"] = status
    if event:
        conditions.append("p.event = :event")
        params["event"] = event

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    count_row = await db.execute(
        text(f"SELECT COUNT(*) FROM cicd_pipelines p {where}"), params
    )
    total = count_row.scalar() or 0

    rows = await db.execute(
        text(f"""
        SELECT p.* FROM cicd_pipelines p
        {where}
        ORDER BY p.started_at DESC NULLS LAST
        LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
    }


@router.post("/pipelines/trigger")
async def trigger_pipeline(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "w")),
):
    """Trigger a pipeline on a CI system (Woodpecker, GitLab…)."""
    try:
        await require_vault_unsealed()
    except VaultSealedError as e:
        raise HTTPException(503, str(e)) from e

    ci_system = payload.get("ci_system", "woodpecker")
    repo_name = payload.get("repo_name", "")
    branch = payload.get("branch", "main")
    variables = payload.get("variables", {})

    if not repo_name:
        raise HTTPException(400, "repo_name required")

    url, token = await _resolve_ci_credentials(ci_system, db)
    if not url or not token:
        raise HTTPException(503, f"{ci_system} not configured")

    try:
        ci = get_ci(ci_system, url, token)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    if ci_system == "woodpecker":
        try:
            wp_repos = await ci.list_repos()
        except Exception as e:
            raise HTTPException(502, f"Woodpecker API error: {e}") from e
        wp_repo = next((r for r in wp_repos if r.get("full_name") == repo_name), None)
        if not wp_repo:
            raise HTTPException(404, f"Repo '{repo_name}' not found")
        repo_id = wp_repo["id"]
    else:
        repo_id = repo_name

    try:
        result = await ci.trigger_pipeline(repo_id, branch, variables)
    except Exception as e:
        raise HTTPException(502, f"Pipeline trigger failed: {e}") from e

    return {
        "status": "ok",
        "pipeline_number": result.get("number"),
        "repo_name": repo_name,
        "branch": branch,
    }
