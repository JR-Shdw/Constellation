# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Workers/runners — ingestion, listing, live sync."""

import json
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_collect_token, require_permission
from ...connectors import get_ci
from ...database import get_db
from ...utils.sql import set_statement_timeout
from ..automation import run_evaluation
from . import _resolve_ci_credentials, logger, router

# Woodpecker agents heartbeat to their server roughly every 30s. Treat an
# agent silent for longer than this as offline. Generous enough to absorb
# sync timing jitter without false positives.
_WORKER_OFFLINE_AFTER_SECS = 600


def _parse_ts(val):
    """Parse ISO string to datetime; passthrough if already datetime."""
    if val is None or isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


@router.post("/workers/report")
async def workers_report(
    payload: list[dict],
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Upsert CI/CD workers/runners from sync script or live sync."""
    await set_statement_timeout(db, "batch")
    upserted = 0
    for agent in payload:
        ci_sys = agent.get("ci_system", "woodpecker")
        ext_id = str(
            agent.get("external_id")
            or agent.get("id")
            or agent.get("woodpecker_id", "")
        )
        if not ext_id:
            continue
        hostname = agent.get("hostname", "")
        node_row = await db.execute(
            text("SELECT id FROM nodes WHERE hostname = :h"),
            {"h": hostname},
        )
        node_id = node_row.scalar_one_or_none()

        # Derive offline from heartbeat freshness. Neither the live-sync
        # connector nor the external sync script reports a real 'offline'
        # status — they only carry last_contact — so without this the status
        # was permanently 'connected' and worker_offline never fired. An
        # explicit 'offline' in the payload still wins.
        last_contact_dt = _parse_ts(agent.get("last_contact"))
        if last_contact_dt is not None and last_contact_dt.tzinfo is None:
            last_contact_dt = last_contact_dt.replace(tzinfo=timezone.utc)
        explicit_status = agent.get("status")
        if explicit_status == "offline":
            status = "offline"
        elif (
            last_contact_dt is not None
            and (datetime.now(timezone.utc) - last_contact_dt).total_seconds()
            > _WORKER_OFFLINE_AFTER_SECS
        ):
            status = "offline"
        else:
            status = explicit_status or "connected"

        result = await db.execute(
            text("""
            WITH prev AS (
                SELECT status AS old_status FROM cicd_workers
                WHERE ci_system = :ci_sys AND external_id = :ext_id
            )
            INSERT INTO cicd_workers
                (ci_system, external_id, name, hostname, platform,
                 labels, capacity, status, last_contact,
                 node_id, updated_at)
            VALUES
                (:ci_sys, :ext_id, :name, :hostname, :platform,
                 CAST(:labels AS jsonb), :capacity, :status,
                 :last_contact, :node_id, NOW())
            ON CONFLICT (ci_system, external_id) DO UPDATE SET
                name         = EXCLUDED.name,
                hostname     = EXCLUDED.hostname,
                platform     = EXCLUDED.platform,
                labels       = EXCLUDED.labels,
                capacity     = EXCLUDED.capacity,
                status       = EXCLUDED.status,
                last_contact = EXCLUDED.last_contact,
                node_id      = EXCLUDED.node_id,
                updated_at   = NOW()
            RETURNING (SELECT old_status FROM prev) AS old_status
            """),
            {
                "ci_sys": ci_sys,
                "ext_id": ext_id,
                "name": agent.get("name", f"agent-{ext_id}"),
                "hostname": hostname,
                "platform": agent.get("platform", ""),
                "labels": json.dumps(agent.get("labels") or {}),
                "capacity": agent.get(
                    "capacity",
                    agent.get("max_workflows", 1),
                ),
                "status": status,
                "last_contact": last_contact_dt,
                "node_id": str(node_id) if node_id else None,
            },
        )
        prev_status = result.scalar()
        upserted += 1

        # Fire worker_offline only on the transition into offline (status is
        # derived from last_contact freshness above). The sync re-reports every
        # agent each cycle, so without this guard an offline runner re-fires the
        # automation (and its dedup-less notification) every sync.
        if status == "offline" and prev_status != "offline":
            try:
                await run_evaluation(
                    {
                        "trigger_type": "worker_offline",
                        "hostname": hostname,
                    },
                    db,
                )
            except Exception as e:
                logger.warning(
                    "[cicd] automation eval failed for worker %s: %s",
                    hostname,
                    e,
                )

    await db.commit()
    logger.info("[cicd] workers upserted: %d", upserted)
    return {"status": "ok", "upserted": upserted}


@router.get("/workers")
async def list_workers(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "r")),
):
    """List all Woodpecker workers with status."""
    rows = await db.execute(
        text("""
        SELECT * FROM v_cicd_workers_status
        ORDER BY status, name
    """)
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.post("/workers/sync")
async def sync_workers(
    ci_system: str = Query("woodpecker"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("cicd", "w")),
):
    """Live sync workers/runners from a CI system."""
    await set_statement_timeout(db, "batch")
    url, token = await _resolve_ci_credentials(ci_system, db)
    if not url or not token:
        raise HTTPException(503, f"{ci_system} not configured")
    try:
        ci = get_ci(ci_system, url, token)
        runners = await ci.list_runners()
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(502, f"{ci_system} API error: {e}") from e

    payload = []
    for r in runners:
        labels = r.get("labels", {})
        hostname = labels.get("host", r.get("hostname") or r.get("name", ""))
        payload.append(
            {
                "ci_system": ci_system,
                "external_id": str(r.get("external_id", "")),
                "name": r.get("name", ""),
                "hostname": hostname,
                "platform": r.get("platform", ""),
                "labels": labels,
                "capacity": r.get("capacity", 1),
                "status": r.get("status", "connected"),
                "last_contact": r.get("last_contact"),
            }
        )
    result = await workers_report(payload, db, _)
    return result
