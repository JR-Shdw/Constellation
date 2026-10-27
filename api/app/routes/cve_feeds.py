# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CVE feed management — RSS/Atom subscriptions + advisory ingestion."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx
from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..connectors.cve_feed import Advisory, FeedError, fetch_feed
from ..database import get_db
from ..notify import notify_advisory
from .settings import feature_enabled

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/cve-feeds", tags=["cve-feeds"])


async def _require_cve_feature(db: AsyncSession) -> None:
    """Block all feed operations when the CVE feature is disabled."""
    if not await feature_enabled("cve", db):
        raise HTTPException(404, "CVE module disabled")


@router.get("")
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "r")),
):
    await _require_cve_feature(db)
    rows = await db.execute(
        text("""
        SELECT f.id, f.name, f.url, f.feed_type, f.source_label,
               f.enabled, f.last_fetched_at, f.last_status, f.last_error,
               f.created_at,
               (SELECT COUNT(*) FROM cve_advisories a WHERE a.feed_id = f.id)
                   AS advisory_count,
               (SELECT MAX(published_at) FROM cve_advisories a
                    WHERE a.feed_id = f.id) AS latest_published
        FROM cve_feeds f
        ORDER BY f.created_at
        """)
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.post("")
async def create_feed(
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    await _require_cve_feature(db)
    name = (body.get("name") or "").strip()
    url = (body.get("url") or "").strip()
    feed_type = (body.get("feed_type") or "rss").strip().lower()
    if not name or not url:
        raise HTTPException(400, "name and url are required")
    if feed_type not in ("rss", "atom"):
        raise HTTPException(400, "feed_type must be 'rss' or 'atom'")

    source_label = (body.get("source_label") or "custom").strip().lower()
    enabled = bool(body.get("enabled", True))

    row = await db.execute(
        text("""
        INSERT INTO cve_feeds (name, url, feed_type, source_label, enabled)
        VALUES (:name, :url, :ft, :src, :en)
        ON CONFLICT (url) DO NOTHING
        RETURNING id
        """),
        {
            "name": name,
            "url": url,
            "ft": feed_type,
            "src": source_label,
            "en": enabled,
        },
    )
    new_id = row.scalar_one_or_none()
    if not new_id:
        raise HTTPException(409, "feed url already exists")
    await log_action(
        db,
        actor=actor,
        action="cve_feed_create",
        target_type="cve_feed",
        target_id=str(new_id),
        detail={"name": name, "url": url},
    )
    await db.commit()
    return {"id": str(new_id)}


# ── Literal-path endpoints — declared BEFORE /{feed_id} so DELETE on
#    e.g. /auto-fetch isn't intercepted by the UUID-validating route.


_AUTO_JOB_NAME = "auto-fetch-cve-feeds"


@router.get("/auto-fetch")
async def get_auto_fetch_status(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "r")),
):
    """Return the schedule job that auto-fetches feeds, if any."""
    await _require_cve_feature(db)
    row = (
        (
            await db.execute(
                text("""
                SELECT id, cron_expr, enabled, timezone,
                       next_run_at, last_run_at
                FROM scheduler_jobs
                WHERE job_type = 'cve_feeds_fetch' AND name = :name
                """),
                {"name": _AUTO_JOB_NAME},
            )
        )
        .mappings()
        .first()
    )
    if not row:
        return {"scheduled": False}
    return {"scheduled": True, **dict(row)}


@router.post("/auto-fetch")
async def set_auto_fetch(
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Create or update the recurring auto-fetch job. Body: {cron_expr}."""
    await _require_cve_feature(db)
    cron = (body.get("cron_expr") or "*/30 * * * *").strip()
    enabled = bool(body.get("enabled", True))
    # Validate the cron BEFORE inserting — an invalid expression would
    # otherwise persist and crash _advance_next_run on every tick.
    if not croniter.is_valid(cron):
        raise HTTPException(400, f"Invalid cron expression: {cron}")
    # Compute next_run_at up front. The scheduler tick filters
    # `WHERE next_run_at <= NOW()`, and `NULL <= NOW()` is NULL/false —
    # so a row with NULL would never run until the next API restart
    # backfilled it via initialize_next_runs(). The same recompute on
    # DO UPDATE makes cron edits take effect immediately instead of
    # waiting for one more tick on the old cadence.
    next_at = croniter(cron, datetime.now(timezone.utc)).get_next(datetime)
    row = await db.execute(
        text("""
        INSERT INTO scheduler_jobs
            (name, description, job_type, cron_expr, timezone,
             config, enabled, next_run_at)
        VALUES
            (:name, 'Auto-fetch RSS/Atom advisory feeds',
             'cve_feeds_fetch', :cron, 'UTC',
             CAST('{}' AS jsonb), :en, :next_at)
        ON CONFLICT (name) DO UPDATE SET
            cron_expr = EXCLUDED.cron_expr,
            enabled = EXCLUDED.enabled,
            next_run_at = EXCLUDED.next_run_at,
            updated_at = NOW()
        RETURNING id
        """),
        {
            "name": _AUTO_JOB_NAME,
            "cron": cron,
            "en": enabled,
            "next_at": next_at,
        },
    )
    job_id = str(row.scalar_one())
    await log_action(
        db,
        actor=actor,
        action="cve_feed_auto_fetch_set",
        target_type="scheduler_job",
        target_id=job_id,
        detail={"cron_expr": cron, "enabled": enabled},
    )
    await db.commit()
    return {"id": job_id, "cron_expr": cron, "enabled": enabled}


@router.delete("/auto-fetch")
async def disable_auto_fetch(
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Remove the recurring auto-fetch job."""
    await _require_cve_feature(db)
    r = await db.execute(
        text("""
        DELETE FROM scheduler_jobs
        WHERE job_type = 'cve_feeds_fetch' AND name = :name
        """),
        {"name": _AUTO_JOB_NAME},
    )
    await log_action(
        db,
        actor=actor,
        action="cve_feed_auto_fetch_clear",
        target_type="system",
        detail={"deleted": r.rowcount or 0},
    )
    await db.commit()
    return {"deleted": r.rowcount or 0}


# ── Path-param endpoints (UUID-validated) ─────────────────────────────


@router.patch("/{feed_id}")
async def patch_feed(
    feed_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    await _require_cve_feature(db)
    validate_uuid(feed_id, "feed_id")
    allowed = {"name", "enabled", "source_label", "feed_type"}
    sets = []
    params: dict = {"id": feed_id}
    for k in allowed:
        if k in body:
            sets.append(f"{k} = :{k}")
            params[k] = body[k]
    if not sets:
        return {"updated": 0}
    await db.execute(
        text(f"UPDATE cve_feeds SET {', '.join(sets)} WHERE id = CAST(:id AS uuid)"),
        params,
    )
    await log_action(
        db,
        actor=actor,
        action="cve_feed_update",
        target_type="cve_feed",
        target_id=feed_id,
        detail=body,
    )
    await db.commit()
    return {"updated": 1}


@router.delete("/{feed_id}")
async def delete_feed(
    feed_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    await _require_cve_feature(db)
    validate_uuid(feed_id, "feed_id")
    r = await db.execute(
        text("DELETE FROM cve_feeds WHERE id = CAST(:id AS uuid)"),
        {"id": feed_id},
    )
    if r.rowcount == 0:
        raise HTTPException(404, "feed not found")
    await log_action(
        db,
        actor=actor,
        action="cve_feed_delete",
        target_type="cve_feed",
        target_id=feed_id,
    )
    await db.commit()
    return {"deleted": 1}


async def _ingest_advisories(
    db: AsyncSession, feed_id: str, advisories: list[Advisory]
) -> dict:
    """Upsert advisories, count new ones, fire notifications for matches."""
    new_count = 0
    matched_total = 0
    for adv in advisories:
        # Match CVE IDs against cve_catalog so we know which advisories
        # actually concern us. The advisory_ref+feed_id combo dedups runs.
        matched_cves = []
        if adv.cve_ids:
            r = await db.execute(
                text("""
                SELECT cve_id FROM cve_catalog
                WHERE cve_id = ANY(:ids)
                """),
                {"ids": adv.cve_ids},
            )
            matched_cves = [row[0] for row in r]
        matched_nodes = 0
        if matched_cves:
            r = await db.execute(
                text("""
                SELECT COUNT(DISTINCT node_id) FROM (
                    SELECT node_id FROM cve_host_packages
                    WHERE cve_id = ANY(:ids) AND status = 'open'
                    UNION
                    SELECT node_id FROM cve_containers
                    WHERE cve_id = ANY(:ids) AND status = 'open'
                ) u
                """),
                {"ids": matched_cves},
            )
            matched_nodes = r.scalar_one()

        ins = await db.execute(
            text("""
            INSERT INTO cve_advisories
                (feed_id, advisory_ref, title, url, summary,
                 published_at, cve_ids, severity,
                 matched_cve_count, matched_node_count)
            VALUES
                (CAST(:fid AS uuid), :ref, :title, :url, :summary,
                 :pub, :cves, :sev, :mc, :mn)
            ON CONFLICT (feed_id, advisory_ref) DO UPDATE SET
                title = EXCLUDED.title,
                url = EXCLUDED.url,
                summary = EXCLUDED.summary,
                cve_ids = EXCLUDED.cve_ids,
                severity = EXCLUDED.severity,
                matched_cve_count = EXCLUDED.matched_cve_count,
                matched_node_count = EXCLUDED.matched_node_count,
                fetched_at = NOW()
            RETURNING (xmax = 0) AS inserted
            """),
            {
                "fid": feed_id,
                "ref": adv.advisory_ref,
                "title": adv.title,
                "url": adv.url,
                "summary": adv.summary,
                "pub": adv.published_at,
                # Always store the full advisory cve_ids — matched_cve_count
                # already tracks how many of them appear in our catalog.
                # Persisting only the matched subset would lose every CVE
                # reference we don't yet know about, breaking later lookups
                # once those CVEs are added to the catalog.
                "cves": adv.cve_ids,
                "sev": adv.severity,
                "mc": len(matched_cves),
                "mn": matched_nodes,
            },
        )
        is_new = ins.scalar_one()
        if is_new:
            new_count += 1
        matched_total += len(matched_cves)

        # Only notify on advisories that hit something we run.
        # ONE notification per advisory — a CERT-FR avis referencing 20
        # inventory CVEs no longer fans out to 20 separate Matrix messages.
        if is_new and matched_cves and matched_nodes > 0:
            sev = adv.severity or "high"
            await notify_advisory(
                advisory_ref=adv.advisory_ref,
                severity=sev,
                title=adv.title or adv.advisory_ref,
                cve_ids=matched_cves,
                source=f"feed:{feed_id}",
                db=db,
                target_name=adv.url or "",
            )
    return {"new": new_count, "matched_cves": matched_total}


@router.post("/{feed_id}/fetch")
async def fetch_one_feed(
    feed_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    await _require_cve_feature(db)
    validate_uuid(feed_id, "feed_id")
    feed = (
        (
            await db.execute(
                text("""
                SELECT id, url, name FROM cve_feeds
                WHERE id = CAST(:id AS uuid) AND enabled = true
                """),
                {"id": feed_id},
            )
        )
        .mappings()
        .first()
    )
    if not feed:
        raise HTTPException(404, "feed not found or disabled")

    try:
        advisories = await fetch_feed(feed["url"])
        ingest = await _ingest_advisories(db, feed_id, advisories)
        await db.execute(
            text("""
            UPDATE cve_feeds
            SET last_fetched_at = NOW(),
                last_status = 'ok',
                last_error = NULL
            WHERE id = CAST(:id AS uuid)
            """),
            {"id": feed_id},
        )
        await log_action(
            db,
            actor=actor,
            action="cve_feed_fetch",
            target_type="cve_feed",
            target_id=feed_id,
            detail={"name": feed["name"], **ingest, "total": len(advisories)},
        )
        await db.commit()
        return {"status": "ok", "total": len(advisories), **ingest}
    except (FeedError, httpx.HTTPError) as e:
        msg = str(e)[:500]
        logger.warning("[cve-feed] fetch failed for %s: %s", feed["url"], msg)
        await db.execute(
            text("""
            UPDATE cve_feeds
            SET last_fetched_at = NOW(),
                last_status = 'error',
                last_error = :err
            WHERE id = CAST(:id AS uuid)
            """),
            {"id": feed_id, "err": msg},
        )
        await db.commit()
        return {"status": "error", "error": msg}


async def _fetch_all_feeds_internal(db: AsyncSession) -> dict:
    """Fetch every enabled feed — shared by /fetch-all route + scheduler."""
    feeds = (
        (
            await db.execute(
                text("SELECT id, url, name FROM cve_feeds WHERE enabled = true")
            )
        )
        .mappings()
        .all()
    )
    summary = {"feeds": 0, "advisories_new": 0, "advisories_total": 0, "errors": 0}
    # Commit per-feed so a single failure (network, DataError, notify hiccup)
    # doesn't roll back the work + last_status updates of feeds processed earlier.
    for feed in feeds:
        try:
            advisories = await fetch_feed(feed["url"])
            ingest = await _ingest_advisories(db, str(feed["id"]), advisories)
            await db.execute(
                text("""
                UPDATE cve_feeds
                SET last_fetched_at = NOW(),
                    last_status = 'ok',
                    last_error = NULL
                WHERE id = :id
                """),
                {"id": feed["id"]},
            )
            await db.commit()
            summary["feeds"] += 1
            summary["advisories_total"] += len(advisories)
            summary["advisories_new"] += ingest["new"]
        except Exception as e:
            await db.rollback()
            summary["errors"] += 1
            msg = str(e)[:500]
            if not isinstance(e, (FeedError, httpx.HTTPError)):
                logger.exception("[cve-feed] unexpected error fetching %s", feed["url"])
            else:
                logger.warning("[cve-feed] fetch failed for %s: %s", feed["url"], msg)
            try:
                await db.execute(
                    text("""
                    UPDATE cve_feeds
                    SET last_fetched_at = NOW(),
                        last_status = 'error',
                        last_error = :err
                    WHERE id = :id
                    """),
                    {"id": feed["id"], "err": msg},
                )
                await db.commit()
            except Exception:
                logger.exception(
                    "[cve-feed] failed to record error status for %s", feed["url"]
                )
                await db.rollback()
    return summary


@router.post("/fetch-all")
async def fetch_all_feeds(
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Trigger a fetch on every enabled feed."""
    await _require_cve_feature(db)
    summary = await _fetch_all_feeds_internal(db)
    await log_action(
        db,
        actor=actor,
        action="cve_feed_fetch_all",
        target_type="system",
        detail=summary,
    )
    await db.commit()
    return summary


@router.get("/advisories")
async def list_advisories(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    matched_only: bool = Query(False),
    feed_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "r")),
):
    """List ingested advisories, newest first. Filterable by feed + match."""
    await _require_cve_feature(db)
    clauses = []
    params: dict = {"limit": per_page, "offset": (page - 1) * per_page}
    if matched_only:
        clauses.append("a.matched_cve_count > 0")
    if feed_id:
        validate_uuid(feed_id, "feed_id")
        clauses.append("a.feed_id = CAST(:fid AS uuid)")
        params["fid"] = feed_id
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = (
        await db.execute(
            text(f"SELECT COUNT(*) FROM cve_advisories a {where}"),
            {k: v for k, v in params.items() if k not in ("limit", "offset")},
        )
    ).scalar_one()
    rows = await db.execute(
        text(f"""
        SELECT a.id, a.advisory_ref, a.title, a.url, a.summary,
               a.published_at, a.cve_ids, a.severity,
               a.matched_cve_count, a.matched_node_count,
               a.fetched_at,
               f.name AS feed_name, f.source_label
        FROM cve_advisories a
        JOIN cve_feeds f ON f.id = a.feed_id
        {where}
        ORDER BY a.published_at DESC NULLS LAST, a.fetched_at DESC
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
