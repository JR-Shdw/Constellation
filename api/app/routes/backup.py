# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_collect_token, require_permission
from ..database import get_db
from ..models.schemas import BackupReport
from ..utils.hostname import resolve_node_id
from ..utils.sql import set_statement_timeout, where_clause
from .automation import run_evaluation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/backup", tags=["backup"])


def _parse_ts(val: str | None) -> datetime | None:
    """Parse ISO timestamp string to datetime, or None."""
    if not val:
        return None
    try:
        s = val.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


@router.post("/report")
async def backup_report(
    payload: BackupReport,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Endpoint pour le wrapper restic — upsert repo + insert run."""
    from .settings import feature_enabled

    await set_statement_timeout(db, "batch")
    if not await feature_enabled("backup", db):
        return {"status": "skipped", "detail": "Backup module disabled"}

    logger.info(
        "[backup] received: host=%s repo=%s status=%s "
        "files_new=%d size_added=%d duration=%ds",
        payload.hostname,
        payload.repo_name,
        payload.status,
        payload.files_new,
        payload.size_added,
        payload.duration_secs,
    )

    # Resolve node_id — utils.hostname.resolve_node_id handles
    # FQDN ↔ short ↔ case-insensitive lookups so a backup arriving
    # as `sirius.example.com` rattaches to a nodes row keyed by `sirius`,
    # and vice versa.
    lookup_name = payload.node_hostname or payload.hostname
    node_id = await resolve_node_id(db, lookup_name)
    if node_id is None:
        logger.warning(
            "[backup] hostname '%s' not found in nodes table — "
            "repo will be stored without node_id link. "
            "Run Ansible collect on this host to link it.",
            payload.hostname,
        )

    # Upsert repo — merge orphan repos (node_id NULL) when node is resolved
    try:
        repo_id = None

        if node_id:
            # Check if a linked repo already exists for this node + name
            linked = await db.execute(
                text("""
                SELECT id FROM backup_repositories
                WHERE node_id = CAST(:nid AS uuid) AND name = :name
                LIMIT 1
                """),
                {"nid": str(node_id), "name": payload.repo_name},
            )
            linked_id = linked.scalar_one_or_none()

            # Check for orphan repo (same name, no node)
            orphan = await db.execute(
                text("""
                SELECT id FROM backup_repositories
                WHERE node_id IS NULL AND name = :name
                LIMIT 1
                """),
                {"name": payload.repo_name},
            )
            orphan_id = orphan.scalar_one_or_none()

            if orphan_id and linked_id:
                # Both exist: merge orphan runs into linked, delete orphan
                await db.execute(
                    text("""
                    UPDATE backup_runs
                    SET repo_id = CAST(:target AS uuid),
                        node_id = CAST(:nid AS uuid)
                    WHERE repo_id = CAST(:src AS uuid)
                    """),
                    {
                        "target": str(linked_id),
                        "nid": str(node_id),
                        "src": str(orphan_id),
                    },
                )
                await db.execute(
                    text(
                        "DELETE FROM backup_repositories WHERE id = CAST(:id AS uuid)"
                    ),
                    {"id": str(orphan_id)},
                )
                repo_id = str(linked_id)
                logger.info(
                    "[backup] merged orphan %s into %s",
                    orphan_id,
                    repo_id,
                )
            elif orphan_id:
                # Only orphan: adopt it (set node_id)
                await db.execute(
                    text("""
                    UPDATE backup_repositories
                    SET node_id = CAST(:node_id AS uuid),
                        repo_path = :path,
                        sftp_host = :sftp_host,
                        sftp_user = :sftp_user
                    WHERE id = CAST(:id AS uuid)
                    """),
                    {
                        "node_id": str(node_id),
                        "path": payload.repo_path,
                        "sftp_host": payload.sftp_host,
                        "sftp_user": payload.sftp_user,
                        "id": str(orphan_id),
                    },
                )
                repo_id = str(orphan_id)
                logger.info(
                    "[backup] adopted orphan repo %s → node %s",
                    repo_id,
                    node_id,
                )

        # Normal upsert if no orphan was handled
        if not repo_id:
            repo = await db.execute(
                text("""
                INSERT INTO backup_repositories
                    (node_id, name, repo_path, sftp_host, sftp_user)
                VALUES (:node_id, :name, :path, :sftp_host, :sftp_user)
                ON CONFLICT (node_id, name) DO UPDATE SET
                    repo_path = EXCLUDED.repo_path,
                    sftp_host = EXCLUDED.sftp_host
                RETURNING id
                """),
                {
                    "node_id": str(node_id) if node_id else None,
                    "name": payload.repo_name,
                    "path": payload.repo_path,
                    "sftp_host": payload.sftp_host,
                    "sftp_user": payload.sftp_user,
                },
            )
            repo_id = str(repo.scalar_one())

        logger.info("[backup] repo upserted: id=%s", repo_id)
    except Exception as e:
        await db.rollback()
        logger.error(
            "[backup] failed to upsert repo for %s/%s: %s",
            payload.hostname,
            payload.repo_name,
            e,
        )
        return {"status": "error", "detail": f"repo upsert failed: {e}"}

    # Insert run
    try:
        raw_json = json.dumps(payload.raw) if payload.raw else "{}"
        files_total = (
            payload.files_new + payload.files_changed + payload.files_unmodified
        )
        await db.execute(
            text("""
            INSERT INTO backup_runs (
                repo_id, node_id, hostname, status,
                files_new, files_changed, files_unmodified, files_total,
                size_added, size_total, snapshots_total, duration_secs,
                source, error_msg, raw, started_at, finished_at
            ) VALUES (
                :repo_id, :node_id, :hostname, :status,
                :files_new, :files_changed, :files_unmodified, :files_total,
                :size_added, :size_total, :snapshots_total, :duration_secs,
                :source, :error_msg, CAST(:raw AS jsonb),
                :started_at, NOW()
            )
            ON CONFLICT (repo_id, (utc_date(started_at)))
            WHERE started_at IS NOT NULL
            DO UPDATE SET
                status = EXCLUDED.status,
                files_new = EXCLUDED.files_new,
                files_changed = EXCLUDED.files_changed,
                files_total = EXCLUDED.files_total,
                size_added = EXCLUDED.size_added,
                size_total = EXCLUDED.size_total,
                duration_secs = EXCLUDED.duration_secs,
                error_msg = EXCLUDED.error_msg,
                raw = EXCLUDED.raw,
                finished_at = NOW()
            """),
            {
                "repo_id": repo_id,
                "node_id": str(node_id) if node_id else None,
                "hostname": payload.hostname,
                "status": payload.status,
                "files_new": payload.files_new,
                "files_changed": payload.files_changed,
                "files_unmodified": payload.files_unmodified,
                "files_total": files_total,
                "size_added": payload.size_added,
                "size_total": payload.size_total,
                "snapshots_total": payload.snapshots_total,
                "duration_secs": payload.duration_secs,
                "source": payload.source,
                "error_msg": payload.error_msg,
                "raw": raw_json,
                "started_at": _parse_ts(payload.started_at),
            },
        )
        await db.commit()
        logger.info(
            "[backup] run inserted for %s/%s status=%s",
            payload.hostname,
            payload.repo_name,
            payload.status,
        )
    except Exception as e:
        await db.rollback()
        logger.error(
            "[backup] failed to insert run for %s/%s: %s",
            payload.hostname,
            payload.repo_name,
            e,
        )
        return {"status": "error", "detail": f"run insert failed: {e}"}

    # Fire automation event on backup failure. The canonical failure status is
    # "failure" (what restic-backup.sh and mail_backup_parser.py emit, and the
    # only failure value the backup_runs CHECK accepts) — the old "failed" was
    # never produced, so genuine failures silently never fired backup_overdue.
    if payload.status in ("error", "warning", "failure"):
        try:
            await run_evaluation(
                {
                    "trigger_type": "backup_overdue",
                    "hostname": payload.hostname,
                },
                db,
            )
            # run_evaluation writes the automation_log row (and any
            # create_deployment) on this session but does NOT commit — that's
            # the caller's job. Without this commit the automation effects are
            # rolled back at request teardown (same bug fixed in heartbeat
            # 55730c3 / repositories / misconf).
            await db.commit()
        except Exception as e:
            logger.warning(
                "[backup] automation eval failed for %s: %s",
                payload.hostname,
                e,
            )
            await db.rollback()

    return {"status": "ok", "repo_id": repo_id, "node_linked": node_id is not None}


@router.get("/summary")
async def backup_summary(
    node_id: str | None = None,
    hostname: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("backup", "r")),
):
    clauses = []
    params: dict = {}
    if node_id:
        clauses.append("l.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if hostname:
        clauses.append("l.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    where = where_clause(clauses)
    rows = await db.execute(
        text(f"""
        SELECT l.*, s.total_runs, s.success_count, s.failure_count,
               s.avg_duration_secs, s.success_rate, s.total_added_30d
        FROM v_backup_latest l
        LEFT JOIN v_backup_stats_30d s ON s.repo_id = l.repo_id
        {where}
        ORDER BY l.overdue DESC, l.hostname, l.repo_name
    """),
        params,
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.get("/history/{repo_id}")
async def backup_history(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("backup", "r")),
):
    rows = await db.execute(
        text("""
        SELECT * FROM backup_runs
        WHERE repo_id = :rid
        ORDER BY finished_at DESC
        LIMIT 90
    """),
        {"rid": repo_id},
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.get("/alerts")
async def backup_alerts(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("backup", "r")),
):
    """Alertes backup : failed, overdue, nodes sans backup."""
    rows = await db.execute(
        text("SELECT * FROM v_backup_alerts ORDER BY alert_type, hostname")
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.patch("/repos/{repo_id}")
async def patch_backup_repo(
    repo_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("backup", "w")),
):
    """Assign/change node_id on a backup repo.

    If assigning would create a duplicate (same node_id + name),
    merge: move runs from this repo to the existing one, then delete this repo.
    """
    from ..audit import log_action, validate_uuid

    validate_uuid(repo_id)
    node_id = body.get("node_id")
    if node_id:
        validate_uuid(node_id)

    # Check for duplicate: does a repo with same (node_id, name) already exist?
    if node_id:
        repo_row = await db.execute(
            text("SELECT name FROM backup_repositories WHERE id = CAST(:id AS uuid)"),
            {"id": repo_id},
        )
        repo_name = repo_row.scalar_one_or_none()

        if repo_name:
            dup_row = await db.execute(
                text("""
                SELECT id FROM backup_repositories
                WHERE node_id = CAST(:nid AS uuid)
                  AND name = :name
                  AND id != CAST(:id AS uuid)
                LIMIT 1
                """),
                {"nid": node_id, "name": repo_name, "id": repo_id},
            )
            target_id = dup_row.scalar_one_or_none()

            if target_id:
                # Merge: move runs to existing repo, delete orphan
                await db.execute(
                    text("""
                    UPDATE backup_runs
                    SET repo_id = CAST(:target AS uuid),
                        node_id = CAST(:nid AS uuid)
                    WHERE repo_id = CAST(:src AS uuid)
                    """),
                    {
                        "target": str(target_id),
                        "nid": node_id,
                        "src": repo_id,
                    },
                )
                await db.execute(
                    text(
                        "DELETE FROM backup_repositories WHERE id = CAST(:id AS uuid)"
                    ),
                    {"id": repo_id},
                )
                await log_action(
                    db,
                    actor=actor,
                    action="backup_repo_merge",
                    target_type="backup_repository",
                    target_id=str(target_id),
                    detail={
                        "merged_from": repo_id,
                        "node_id": node_id,
                    },
                )
                await db.commit()
                return {
                    "status": "ok",
                    "merged_into": str(target_id),
                }

    # Normal update (no duplicate)
    await db.execute(
        text("""
        UPDATE backup_repositories
        SET node_id = CAST(:node_id AS uuid)
        WHERE id = CAST(:id AS uuid)
        """),
        {"id": repo_id, "node_id": node_id},
    )
    await db.execute(
        text("""
        UPDATE backup_runs SET node_id = CAST(:node_id AS uuid)
        WHERE repo_id = CAST(:id AS uuid)
        """),
        {"id": repo_id, "node_id": node_id},
    )
    await log_action(
        db,
        actor=actor,
        action="backup_repo_update",
        target_type="backup_repository",
        target_id=repo_id,
        detail={"node_id": node_id},
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/repos/delete")
async def delete_backup_repos(
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("backup", "w")),
):
    """Delete backup repos by IDs (cascades to runs)."""
    from ..audit import log_action, validate_uuid

    ids = body.get("ids", [])
    if not ids:
        return {"status": "ok", "deleted": 0}
    for rid in ids:
        validate_uuid(rid)

    placeholders = ", ".join(f":id_{i}" for i in range(len(ids)))
    params = {f"id_{i}": ids[i] for i in range(len(ids))}
    result = await db.execute(
        text(f"""
        DELETE FROM backup_repositories
        WHERE id IN ({placeholders})
        """),
        params,
    )
    await log_action(
        db,
        actor=actor,
        action="backup_repo_delete",
        target_type="backup_repository",
        target_id=",".join(ids),
        detail={"deleted_count": result.rowcount},
    )
    await db.commit()
    return {"status": "ok", "deleted": result.rowcount}
