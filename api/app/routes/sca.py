# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_collect_token, require_permission
from ..database import get_db
from ..utils.hostname import resolve_node_id
from ..utils.sql import set_statement_timeout, where_clause

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sca", tags=["sca"])


def _parse_ts(val) -> datetime | None:
    """Parse the Wazuh `end_scan` field into a tz-aware datetime.

    Wazuh returns ISO strings like '2024-12-15T10:34:56.123Z' or
    '2024-12-15 10:34:56' depending on version. asyncpg refuses to
    bind a string against a TIMESTAMPTZ column — every SCA push was
    failing with a 500 because of this. Returns None on any parsing
    error so the row still gets inserted (end_scan can be NULL).
    """
    if val is None or val == "":
        return None
    if isinstance(val, datetime):
        return val
    if not isinstance(val, str):
        return None
    s = val.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@router.post("/report")
async def sca_report(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Endpoint collecte Wazuh SCA — upsert résultats par policy."""

    await set_statement_timeout(db, "batch")
    hostname = payload.get("hostname", "")
    source = payload.get("source", "wazuh")
    policies = payload.get("policies", [])

    if not hostname:
        return {"status": "error", "detail": "hostname required"}

    node_id = await resolve_node_id(db, hostname)
    if not node_id:
        return {"status": "error", "detail": f"Node {hostname} not found"}

    ingested = 0
    skipped = 0
    for policy in policies:
        policy_id = (policy.get("policy_id") or "").strip()
        if not policy_id:
            # policy_id is NOT NULL in schema — skip rather than 500
            skipped += 1
            continue
        try:
            # Savepoint per policy: a single bad row (e.g. malformed
            # end_scan) is rolled back without losing the rows already
            # inserted in this push. The previous implementation 500'd
            # the whole batch on a TIMESTAMPTZ binding error.
            async with db.begin_nested():
                await db.execute(
                    text("""
                    INSERT INTO sca_results
                        (node_id, source, policy_id, policy_name,
                         score, total_checks, passed, failed, end_scan)
                    VALUES
                        (CAST(:nid AS uuid), :source, :policy_id, :policy_name,
                         :score, :total_checks, :passed, :failed, :end_scan)
                    ON CONFLICT (node_id, policy_id) DO UPDATE SET
                        policy_name  = EXCLUDED.policy_name,
                        score        = EXCLUDED.score,
                        total_checks = EXCLUDED.total_checks,
                        passed       = EXCLUDED.passed,
                        failed       = EXCLUDED.failed,
                        end_scan     = EXCLUDED.end_scan,
                        updated_at   = NOW()
                """),
                    {
                        "nid": node_id,
                        "source": source,
                        "policy_id": policy_id,
                        "policy_name": policy.get("policy_name", ""),
                        "score": policy.get("score"),
                        "total_checks": policy.get("total_checks"),
                        "passed": policy.get("passed"),
                        "failed": policy.get("failed"),
                        "end_scan": _parse_ts(policy.get("end_scan")),
                    },
                )
            ingested += 1
        except Exception as e:
            logger.warning(
                "[sca] insert failed for %s policy=%s: %s — skipping",
                hostname,
                policy_id,
                str(e)[:200],
            )
            skipped += 1

    await db.commit()
    return {
        "status": "ok",
        "node_id": node_id,
        "policies_ingested": ingested,
        "policies_skipped": skipped,
    }


@router.get("/")
async def list_sca(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    hostname: str | None = None,
    policy_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Liste tous les résultats SCA avec filtres optionnels."""
    offset = (page - 1) * per_page
    where_clauses = []
    params: dict = {"limit": per_page, "offset": offset}

    if hostname:
        where_clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    if policy_id:
        where_clauses.append("s.policy_id = :policy_id")
        params["policy_id"] = policy_id

    where = where_clause(where_clauses)

    count_result = await db.execute(
        text(f"""
        SELECT COUNT(*) FROM sca_results s
        JOIN nodes n ON n.id = s.node_id
        {where}
    """),
        params,
    )
    total = count_result.scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT
            s.id, s.policy_id, s.policy_name, s.source,
            s.score, s.total_checks, s.passed, s.failed,
            s.end_scan, s.updated_at,
            n.hostname, n.id AS node_id
        FROM sca_results s
        JOIN nodes n ON n.id = s.node_id
        {where}
        ORDER BY s.score ASC, n.hostname
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


@router.get("/summary")
async def sca_summary(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Score SCA moyen par node + nodes les moins conformes."""
    rows = await db.execute(
        text("""
        SELECT
            n.hostname,
            n.id AS node_id,
            ROUND(AVG(s.score), 1) AS avg_score,
            SUM(s.passed)          AS total_passed,
            SUM(s.failed)          AS total_failed,
            COUNT(s.policy_id)     AS policy_count,
            MAX(s.updated_at)      AS last_scan
        FROM sca_results s
        JOIN nodes n ON n.id = s.node_id
        GROUP BY n.id, n.hostname
        ORDER BY avg_score ASC
    """)
    )
    items = [dict(r._mapping) for r in rows]

    # avg_score is NULL for a node whose policies all have NULL scores
    # (Wazuh can omit score). Excluding them avoids a float + None TypeError
    # that would 500 the whole endpoint because of one such node.
    scores = [i["avg_score"] for i in items if i["avg_score"] is not None]
    global_avg = round(sum(scores) / len(scores), 1) if scores else None

    return {
        "global_avg_score": global_avg,
        "nodes": items,
    }


@router.get("/{node_id}")
async def get_node_sca(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Détail SCA pour un node."""
    from ..audit import validate_uuid

    validate_uuid(node_id, "node_id")
    rows = await db.execute(
        text("""
        SELECT
            s.policy_id, s.policy_name, s.source,
            s.score, s.total_checks, s.passed, s.failed,
            s.end_scan, s.updated_at
        FROM sca_results s
        WHERE s.node_id = CAST(:nid AS uuid)
        ORDER BY s.score ASC
    """),
        {"nid": node_id},
    )
    return {"items": [dict(r._mapping) for r in rows]}
