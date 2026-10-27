# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Repositories — ingestion, listing, detail."""

from fastapi import Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_collect_token, require_permission
from ...database import get_db
from ...utils.sql import set_statement_timeout
from . import logger, router


@router.post("/repos/report")
async def repos_report(
    payload: list[dict],
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Upsert Gitea repositories from sync script."""
    await set_statement_timeout(db, "batch")
    upserted = 0
    for repo in payload:
        repo_name = repo.get("full_name") or repo.get("repo_name", "")
        if not repo_name:
            continue
        await db.execute(
            text("""
            INSERT INTO cicd_repositories
                (forge, repo_name, owner, description,
                 default_branch, url, private, language,
                 topics, stars, has_pipeline, branches,
                 last_commit_at, last_sync_at, updated_at)
            VALUES
                (:forge, :repo_name, :owner, :description,
                 :default_branch, :url, :private, :language,
                 :topics, :stars, :has_pipeline, :branches,
                 :last_commit_at, NOW(), NOW())
            ON CONFLICT (forge, repo_name) DO UPDATE SET
                description    = EXCLUDED.description,
                default_branch = EXCLUDED.default_branch,
                url            = EXCLUDED.url,
                private        = EXCLUDED.private,
                language       = EXCLUDED.language,
                topics         = EXCLUDED.topics,
                stars          = EXCLUDED.stars,
                has_pipeline   = EXCLUDED.has_pipeline,
                branches       = EXCLUDED.branches,
                last_commit_at = EXCLUDED.last_commit_at,
                last_sync_at   = NOW(),
                updated_at     = NOW()
            """),
            {
                "forge": repo.get("forge", "gitea"),
                "repo_name": repo_name,
                "owner": repo.get(
                    "owner",
                    repo_name.split("/")[0] if "/" in repo_name else "",
                ),
                "description": repo.get("description", ""),
                "default_branch": repo.get("default_branch", "main"),
                "url": (repo.get("html_url") or repo.get("url", "")),
                "private": repo.get("private", False),
                "language": repo.get("language", ""),
                "topics": repo.get("topics") or [],
                "stars": (repo.get("stars_count") or repo.get("stars", 0)),
                "has_pipeline": repo.get("has_pipeline", False),
                "branches": repo.get("branches") or [],
                "last_commit_at": (
                    repo.get("updated_at") or repo.get("last_commit_at")
                ),
            },
        )
        upserted += 1
    await db.commit()
    logger.info("[cicd] repos upserted: %d", upserted)
    return {"status": "ok", "upserted": upserted}


@router.get("/repos")
async def list_repos(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "r")),
):
    """List repositories with latest pipeline status."""
    rows = await db.execute(
        text("""
        SELECT
            r.*,
            l.pipeline_number AS last_pipeline_number,
            l.status          AS last_pipeline_status,
            l.event           AS last_pipeline_event,
            l.branch          AS last_pipeline_branch,
            l.started_at      AS last_pipeline_at,
            l.duration_secs   AS last_pipeline_duration,
            l.link            AS last_pipeline_link,
            s.total_runs,
            s.success_count,
            s.failure_count,
            s.success_rate,
            s.avg_duration_secs
        FROM cicd_repositories r
        LEFT JOIN v_cicd_latest l ON l.repo_name = r.repo_name
        LEFT JOIN v_cicd_stats_30d s ON s.repo_name = r.repo_name
        ORDER BY l.started_at DESC NULLS LAST, r.repo_name
    """)
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.get("/repos/{repo_id}")
async def get_repo(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "r")),
):
    """Single repo detail with recent pipelines."""
    row = await db.execute(
        text("""
        SELECT * FROM cicd_repositories
        WHERE id = CAST(:rid AS uuid)
        """),
        {"rid": repo_id},
    )
    repo = row.mappings().first()
    if not repo:
        raise HTTPException(404, "Repo not found")

    pipes = await db.execute(
        text("""
        SELECT * FROM cicd_pipelines
        WHERE repo_name = :name
        ORDER BY started_at DESC NULLS LAST
        LIMIT 20
        """),
        {"name": repo["repo_name"]},
    )
    return {
        "repo": dict(repo),
        "pipelines": [dict(r._mapping) for r in pipes],
    }
