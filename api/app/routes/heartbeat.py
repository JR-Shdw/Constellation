# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Heartbeat — ping nodes and track uptime."""

import asyncio
import json
import logging
import time

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_permission
from ..database import async_session, get_db
from ..notify import send_automation_notification
from .automation import run_evaluation

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/heartbeat", tags=["heartbeat"])

# Ping pacing. gather() over every node would spawn one `ping` subprocess per
# node at once — fine for a handful, a fork-bomb / fd exhaustion (and a burst
# of ICMP that looks like a scan) at thousands (the design target). Cap how
# many run at once AND stagger the launches so the ICMP ramps out smoothly
# instead of as one synchronized wave. Up hosts return in <100ms; only down
# hosts pay the full timeout. Both are tunable for the fleet size.
_PING_CONCURRENCY = 64
_PING_SPACING_S = 0.005  # delay between launching each ping (~200/s ramp)


async def _ping(host: str, timeout: float = 3.0) -> tuple[bool, int | None]:
    """ICMP ping via subprocess. Returns (is_up, latency_ms)."""
    proc = None
    try:
        t0 = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            "ping",
            "-c",
            "1",
            "-W",
            str(int(timeout)),
            host,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
        latency = int((time.monotonic() - t0) * 1000)
        return proc.returncode == 0, latency if proc.returncode == 0 else None
    except (asyncio.TimeoutError, OSError):
        # On timeout the ping child is still running — kill and reap it so we
        # don't leak orphan processes across many check waves (a hung DNS
        # lookup or unreachable host is exactly when wait_for fires).
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        return False, None


@router.post("/check")
async def check_all(
    _: str = Depends(require_permission("read", "w")),
):
    """Ping all active nodes and record heartbeat results.

    The endpoint runs in 4 short DB phases instead of one long-held
    session, so a connection from the SQLAlchemy pool is only checked
    out for the actual SQL — the ping wave (slowest part) runs without
    holding any pool slot.

    Phase 1 — fetch the active nodes (with their previous heartbeat
    status so we don't need a per-node SELECT later).
    Phase 2 — ping every node concurrently (no DB).
    Phase 3 — bulk INSERT all heartbeat rows + bulk UPDATE node
    status in a single transaction.
    Phase 4 — purge stale rows.
    Phase 5 — notify + fire automation for nodes that just went down
    (each in its own session so a slow Matrix call can't pin a
    connection during the next phases).
    """
    # Phase 1 — fetch nodes + prev status
    async with async_session() as db:
        rows = await db.execute(
            text("""
            SELECT id, hostname, check_address, ip_address,
                   heartbeat_status AS prev_status
            FROM nodes WHERE is_active = true
            ORDER BY hostname
            """)
        )
        nodes = [dict(r._mapping) for r in rows]
    if not nodes:
        return {"status": "ok", "checked": 0}

    # Phase 2 — ping all nodes in parallel (no DB held), but bounded + paced:
    # at most _PING_CONCURRENCY in flight, and launches staggered by
    # _PING_SPACING_S so a large fleet ramps out smoothly instead of as one
    # ICMP burst.
    _sem = asyncio.Semaphore(_PING_CONCURRENCY)

    async def _ping_bounded(host: str) -> tuple[bool, int | None]:
        async with _sem:
            return await _ping(host)

    tasks = []
    for n in nodes:
        target = n["check_address"] or n["ip_address"] or n["hostname"]
        tasks.append(asyncio.create_task(_ping_bounded(target)))
        if _PING_SPACING_S:
            await asyncio.sleep(_PING_SPACING_S)
    results = await asyncio.gather(*tasks)

    up_count = 0
    down_count = 0
    newly_down: list[str] = []
    insert_rows: list[dict] = []
    update_rows: list[dict] = []

    for node, (is_up, latency) in zip(nodes, results):
        status = "up" if is_up else "down"
        node_id = str(node["id"])
        insert_rows.append({"nid": node_id, "st": status, "lat": latency})
        update_rows.append({"nid": node_id, "st": status})
        if is_up:
            up_count += 1
        else:
            down_count += 1
            if node["prev_status"] != "down":
                newly_down.append(node["hostname"])

    # Phase 3 — bulk INSERT + bulk UPDATE in a single short transaction.
    # SQLAlchemy's `executemany` (via passing a list of param dicts)
    # batches the INSERTs server-side; the UPDATE uses a VALUES-driven
    # join so the whole node table gets refreshed in one statement.
    async with async_session() as db:
        await db.execute(
            text("""
            INSERT INTO node_heartbeats (node_id, status, latency_ms)
            VALUES (CAST(:nid AS uuid), :st, :lat)
            """),
            insert_rows,
        )
        await db.execute(
            text("""
            UPDATE nodes
            SET heartbeat_status = v.st, last_heartbeat = NOW()
            FROM (
                SELECT (x->>'nid')::uuid AS nid, x->>'st' AS st
                FROM jsonb_array_elements(CAST(:rows AS jsonb)) x
            ) v
            WHERE nodes.id = v.nid
            """),
            {"rows": json.dumps(update_rows)},
        )
        await db.commit()

    # Phase 4 — purge old heartbeat records (keep 90 days)
    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM node_heartbeats "
                "WHERE checked_at < NOW() - INTERVAL '90 days'"
            )
        )
        await db.commit()

    # Phase 5 — notify + fire automation for newly offline nodes.
    # Done in a separate session so a slow Matrix/SMTP roundtrip
    # doesn't pin a pool connection during the heavy phases above.
    if newly_down:
        msg = f"[HEARTBEAT] {len(newly_down)} node(s) DOWN: " + ", ".join(newly_down)
        async with async_session() as db:
            try:
                # send_automation_notification ignores the passed db (it opens
                # its own sessions), so no commit is needed for the notify.
                await send_automation_notification("node_offline", msg, db)
            except Exception as e:
                logger.warning("[heartbeat] notification failed: %s", e)
            for hostname in newly_down:
                try:
                    await run_evaluation(
                        {"trigger_type": "node_offline", "hostname": hostname},
                        db,
                    )
                    # run_evaluation does not commit — the caller must. Without
                    # this the automation_log row (and any create_deployment
                    # side effect) is rolled back when the session closes, so
                    # node_offline automations ran with no audit trail.
                    await db.commit()
                except Exception as e:
                    await db.rollback()
                    logger.warning(
                        "[heartbeat] automation failed for %s: %s", hostname, e
                    )

    logger.info(
        "[heartbeat] checked %d nodes: %d up, %d down",
        len(nodes),
        up_count,
        down_count,
    )
    return {
        "status": "ok",
        "checked": len(nodes),
        "up": up_count,
        "down": down_count,
        "newly_down": newly_down,
    }


@router.get("/status")
async def heartbeat_status(
    sort_by: str | None = Query(None),
    sort_dir: str = Query("asc"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Current heartbeat status for all active nodes."""
    _SORT_MAP = {
        "status": "n.heartbeat_status",
        "hostname": "n.hostname",
        "last_heartbeat": "n.last_heartbeat",
        "last_down": "last_down_at",
    }
    direction = "DESC" if sort_dir == "desc" else "ASC"
    order = (
        f"{_SORT_MAP[sort_by]} {direction} NULLS LAST, n.hostname"
        if sort_by in _SORT_MAP
        else "n.heartbeat_status DESC, n.hostname"
    )
    rows = await db.execute(
        text(f"""
        SELECT n.id, n.hostname, n.heartbeat_status,
               n.last_heartbeat, n.check_address, n.ip_address,
               (SELECT MAX(h.checked_at) FROM node_heartbeats h
                WHERE h.node_id = n.id AND h.status = 'down'
               ) AS last_down_at
        FROM nodes n
        WHERE n.is_active = true
        ORDER BY {order}
        """)
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.get("/trends")
async def heartbeat_trends(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Hourly buckets for the last N hours — fed to Summary mini-cards.

    Returns one row per hour in the window with:
    - up / down counts (each ping recorded across all nodes)
    - avg_latency_ms (mean of latency_ms where status='up')
    - down_events    (transitions from up→down within the bucket)

    The hour column is filled even when there are no pings, so the
    sparklines align with the wall clock.
    """
    rows = await db.execute(
        text("""
        WITH hours AS (
            SELECT generate_series(
                date_trunc('hour', NOW() - make_interval(hours => :hours)),
                date_trunc('hour', NOW()),
                INTERVAL '1 hour'
            ) AS hour
        ),
        buckets AS (
            SELECT date_trunc('hour', checked_at) AS hour,
                   COUNT(*) FILTER (WHERE status = 'up') AS up,
                   COUNT(*) FILTER (WHERE status = 'down') AS down,
                   AVG(latency_ms) FILTER (
                       WHERE status = 'up' AND latency_ms IS NOT NULL
                   ) AS avg_latency_ms
            FROM node_heartbeats
            WHERE checked_at > NOW() - make_interval(hours => :hours)
            GROUP BY 1
        ),
        -- A "down event" = a 'down' row whose immediate predecessor for the
        -- same node was 'up' (or the very first ping). Counted per bucket.
        events AS (
            SELECT date_trunc('hour', checked_at) AS hour,
                   COUNT(*) AS down_events
            FROM (
                SELECT checked_at, status,
                       LAG(status) OVER (
                           PARTITION BY node_id ORDER BY checked_at
                       ) AS prev_status
                FROM node_heartbeats
                WHERE checked_at > NOW() - make_interval(hours => :hours + 1)
            ) trans
            WHERE status = 'down' AND (prev_status = 'up' OR prev_status IS NULL)
            GROUP BY 1
        )
        SELECT h.hour,
               COALESCE(b.up, 0) AS up,
               COALESCE(b.down, 0) AS down,
               ROUND(b.avg_latency_ms::numeric, 1) AS avg_latency_ms,
               COALESCE(e.down_events, 0) AS down_events
        FROM hours h
        LEFT JOIN buckets b ON b.hour = h.hour
        LEFT JOIN events  e ON e.hour = h.hour
        ORDER BY h.hour
        """),
        {"hours": hours},
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.get("/history")
async def heartbeat_history(
    node_id: str | None = Query(None),
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Heartbeat history for dashboard graphs."""
    where = ""
    params: dict = {"days": days}
    if node_id:
        where = "AND h.node_id = CAST(:nid AS uuid)"
        params["nid"] = node_id

    rows = await db.execute(
        text(f"""
        SELECT
            date_trunc('hour', h.checked_at) AS hour,
            COUNT(*) FILTER (WHERE h.status = 'up') AS up,
            COUNT(*) FILTER (WHERE h.status = 'down') AS down
        FROM node_heartbeats h
        WHERE h.checked_at > NOW() - make_interval(days => :days)
        {where}
        GROUP BY hour
        ORDER BY hour
        """),
        params,
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.patch("/nodes/{node_id}")
async def patch_heartbeat_node(
    node_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "w")),
):
    """Update check_address for a node."""
    check_address = body.get("check_address")
    await db.execute(
        text("UPDATE nodes SET check_address = :addr WHERE id = CAST(:nid AS uuid)"),
        {"nid": node_id, "addr": check_address},
    )
    await db.commit()
    return {"status": "ok"}
