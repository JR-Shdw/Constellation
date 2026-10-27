# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Retention policies — auto-purge old data per configurable thresholds."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import require_permission
from ..database import get_db
from ..notify import get_alert_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/retention", tags=["retention"])

# Defaults (days) — overridable via alert_settings in DB
_DEFAULTS = {
    "retention_audit_days": 90,
    "retention_pipeline_days": 90,
    "retention_automation_log_days": 90,
    "retention_scheduler_runs_days": 90,
    # Single threshold drives every "resolved CVE leftover" cleanup :
    # rows in cve_host_packages, cve_containers, AND cve_status. We
    # used to keep cve_status 180 days separately to prevent a rescan
    # reopening a finding whose scan-row had already been GC'd, but
    # the operator chose to keep one slider for clarity. A rescan can
    # therefore re-create an 'open' finding past this threshold.
    "retention_resolved_cve_days": 90,
    "retention_alert_sent_days": 30,
    "retention_stale_image_days": 7,
}

# Bounds for the resolved-CVE retention slider (days). Single source of
# truth — referenced by settings.py for clamp + retention.py for use.
RETENTION_RESOLVED_CVE_MIN = 30
RETENTION_RESOLVED_CVE_MAX = 365


@router.post("/run")
async def run_retention(
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    """Execute retention cleanup. Callable by scheduler or manually.

    Purges old records from:
    - audit_log (default 90 days)
    - cicd_pipelines (default 90 days)
    - automation_log (default 90 days)
    - scheduler_runs (default 90 days)
    - alert_sent dedup records (default 30 days)
    - resolved/false_positive entries in cve_host_packages, cve_containers,
      and cve_status (default 90 days, clamped to [30, 365] via the
      RETENTION_RESOLVED_CVE_MIN / _MAX constants)

    Thresholds configurable via alert_settings keys (retention_*_days).
    """
    settings = await get_alert_settings(db)
    thresholds = {k: int(settings.get(k, str(v))) for k, v in _DEFAULTS.items()}

    purged = {}

    # Audit log
    r = await db.execute(
        text("""
        DELETE FROM audit_log
        WHERE created_at < NOW() - make_interval(days => :days)
        """),
        {"days": thresholds["retention_audit_days"]},
    )
    purged["audit_log"] = r.rowcount

    # CI/CD pipeline runs
    r = await db.execute(
        text("""
        DELETE FROM cicd_pipelines
        WHERE started_at < NOW() - make_interval(days => :days)
        """),
        {"days": thresholds["retention_pipeline_days"]},
    )
    purged["cicd_pipelines"] = r.rowcount

    # Automation log
    r = await db.execute(
        text("""
        DELETE FROM automation_log
        WHERE created_at < NOW() - make_interval(days => :days)
        """),
        {"days": thresholds["retention_automation_log_days"]},
    )
    purged["automation_log"] = r.rowcount

    # Scheduler runs
    r = await db.execute(
        text("""
        DELETE FROM scheduler_runs
        WHERE started_at < NOW() - make_interval(days => :days)
        """),
        {"days": thresholds["retention_scheduler_runs_days"]},
    )
    purged["scheduler_runs"] = r.rowcount

    # Alert dedup records
    r = await db.execute(
        text("""
        DELETE FROM alert_sent
        WHERE sent_at < NOW() - make_interval(days => :days)
        """),
        {"days": thresholds["retention_alert_sent_days"]},
    )
    purged["alert_sent"] = r.rowcount

    # Stale container images — not refreshed by any host for N days and
    # no container references them. Trivy scans only running images, so
    # a removed image stops producing reports ; its CVEs/secrets would
    # otherwise live forever. Mark them resolved (keeping audit trail via
    # cve_status + justification), then drop the image rows.
    #
    # Safeguard : if Trivy itself has not reported in the last 2 days
    # (crashed cron, network outage, ...), abort the purge — otherwise
    # every image would look stale and we'd wipe legitimate data.
    # Retention runs daily, it will catch up once scans resume.
    stale_days = thresholds["retention_stale_image_days"]
    last_scan = await db.execute(
        text("SELECT MAX(scanned_at) AS ts FROM cve_containers")
    )
    last_scan_ts = last_scan.scalar()
    scans_fresh = await db.execute(
        text("SELECT NOW() - make_interval(days => 2) AS cutoff")
    )
    scans_cutoff = scans_fresh.scalar()
    stale_imgs: list = []
    if last_scan_ts is not None and last_scan_ts >= scans_cutoff:
        stale_imgs = (
            (
                await db.execute(
                    text("""
                    SELECT ci.id, ci.image, ci.tag,
                           (ci.image || ':' || ci.tag) AS full_name
                    FROM container_images ci
                    WHERE ci.last_updated < NOW() - make_interval(days => :days)
                      AND NOT EXISTS (
                          SELECT 1 FROM containers c WHERE c.image_id = ci.id
                      )
                    """),
                    {"days": stale_days},
                )
            )
            .mappings()
            .all()
        )
    else:
        logger.warning(
            "[retention] Skipping stale-image purge : no Trivy activity "
            "since %s (cutoff %s) — scanner likely down",
            last_scan_ts,
            scans_cutoff,
        )
    cves_resolved = 0
    secrets_resolved = 0
    for img in stale_imgs:
        full = img["full_name"]
        # Persist the decision so a later rescan (unlikely but possible)
        # doesn't re-open these findings.
        await db.execute(
            text("""
            INSERT INTO cve_status (node_id, cve_id, status, justification)
            SELECT DISTINCT cc.node_id, cc.cve_id,
                   'resolved', :jst
            FROM cve_containers cc
            WHERE cc.image = :img
            ON CONFLICT (node_id, cve_id) DO UPDATE SET
                status = 'resolved',
                justification = EXCLUDED.justification,
                updated_at = NOW()
            """),
            {"img": full, "jst": f"image_removed_auto_{stale_days}d"},
        )
        r = await db.execute(
            text("""
            UPDATE cve_containers SET status = 'resolved'
            WHERE image = :img AND status = 'open'
            """),
            {"img": full},
        )
        cves_resolved += r.rowcount or 0
        r = await db.execute(
            text("""
            UPDATE secrets_detected SET status = 'resolved'
            WHERE image = :img AND status = 'open'
            """),
            {"img": full},
        )
        secrets_resolved += r.rowcount or 0

    if stale_imgs:
        await db.execute(
            text("""
            DELETE FROM container_images
            WHERE id = ANY(CAST(:ids AS uuid[]))
            """),
            {"ids": [str(i["id"]) for i in stale_imgs]},
        )
    purged["stale_images"] = len(stale_imgs)
    purged["stale_image_cves_resolved"] = cves_resolved
    purged["stale_image_secrets_resolved"] = secrets_resolved

    # Resolved CVE leftovers — single threshold (operator preference) for
    # every table that stores "this CVE is resolved" :
    #   - cve_status        (workflow decision per node, small volume)
    #   - cve_host_packages (per-scan finding row, large volume)
    #   - cve_containers    (per-scan finding row, large volume)
    # Tradeoff documented next to the default in _DEFAULTS.
    cve_days = max(
        RETENTION_RESOLVED_CVE_MIN,
        min(
            RETENTION_RESOLVED_CVE_MAX,
            thresholds["retention_resolved_cve_days"],
        ),
    )

    r = await db.execute(
        text("""
        DELETE FROM cve_status
        WHERE status IN ('resolved', 'false_positive')
          AND updated_at < NOW() - make_interval(days => :days)
        """),
        {"days": cve_days},
    )
    purged["cve_status_resolved"] = r.rowcount

    rows_purged = 0
    for table in ("cve_host_packages", "cve_containers"):
        r = await db.execute(
            text(f"""
            DELETE FROM {table}
            WHERE status = 'resolved'
              AND scanned_at < NOW() - make_interval(days => :days)
            """),
            {"days": cve_days},
        )
        rows_purged += r.rowcount or 0
    purged["resolved_cve_rows"] = rows_purged

    total = sum(purged.values())
    if total > 0:
        await log_action(
            db,
            actor=actor,
            action="retention_cleanup",
            target_type="system",
            detail={"purged": purged, "thresholds": thresholds},
        )
        logger.info("[retention] Purged %d records: %s", total, purged)

    await db.commit()
    return {
        "status": "ok",
        "total_purged": total,
        "purged": purged,
        "thresholds": thresholds,
    }


@router.get("/settings")
async def get_retention_settings(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("settings", "r")),
):
    """Get current retention thresholds."""
    settings = await get_alert_settings(db)
    return {k: int(settings.get(k, str(v))) for k, v in _DEFAULTS.items()}
