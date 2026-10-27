# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CVE finding lifecycle management — status, fix_status, exploited, score."""

import logging

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..database import get_db
from ..models.schemas import CleanupExecute, FindingPatch
from ..utils.score import compute_score
from ..utils.scoring import rescore_cve, rescore_finding
from ..utils.sql import set_statement_timeout, where_clause

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

_ALLOWED_STATUS = {"open", "mitigated", "ignored", "resolved"}
_ALLOWED_FIX = {"fixed_available", "unfixed", "not_affected", "under_investigation"}
_ALLOWED_CONTEXT = {
    "likely_exploitable",
    "requires_auth",
    "requires_local_access",
    "requires_user_interaction",
    "unclear",
}
_ALLOWED_LISTEN = {"internet", "private_network", "localhost", "docker_internal"}

# Hardcoded table map — no dynamic table names in SQL
_TABLES = {
    "host": "cve_host_packages",
    "container": "cve_containers",
}

# Fields that live on the finding row (per-node)
_FINDING_FIELDS = ("status", "fix_status")
# Fields that live on cve_catalog (CVE-level, global)
_CATALOG_FIELDS = ("exploited", "exploitability_context")

# Pre-built SQL per table for finding-level fields
_UPDATE_SQL = {
    table: {
        field: text(f"UPDATE {table} SET {field} = :{field} WHERE id = :id")
        for field in _FINDING_FIELDS
    }
    for table in _TABLES.values()
}


async def _patch_finding(
    table_key: str,
    finding_id: str,
    patch: FindingPatch,
    db: AsyncSession,
    actor: str,
):
    validate_uuid(finding_id, "finding_id")
    table = _TABLES[table_key]
    allowed_fields = {
        "status": _ALLOWED_STATUS,
        "fix_status": _ALLOWED_FIX,
        "exploited": None,
        "exploitability_context": _ALLOWED_CONTEXT,
    }
    updates = {}
    for key, val in patch.model_dump(exclude_none=True).items():
        if key not in allowed_fields:
            continue
        enum_values = allowed_fields[key]
        if enum_values is not None and val not in enum_values:
            continue
        updates[key] = val

    if not updates:
        return {"error": "no valid fields"}

    # Split updates: finding-level vs catalog-level
    finding_updates = {k: v for k, v in updates.items() if k in _FINDING_FIELDS}
    catalog_updates = {k: v for k, v in updates.items() if k in _CATALOG_FIELDS}

    # Update finding-level fields directly on the row
    for field, val in finding_updates.items():
        await db.execute(_UPDATE_SQL[table][field], {"id": finding_id, field: val})

    # fix_status feeds the materialized score — re-score this row
    if "fix_status" in finding_updates:
        await rescore_finding(db, table, finding_id)

    # Update catalog-level fields via cve_id lookup
    if catalog_updates:
        cve_row = await db.execute(
            text(f"SELECT cve_id FROM {table} WHERE id = :id"),
            {"id": finding_id},
        )
        cve_id = cve_row.scalar_one_or_none()
        if cve_id:
            for field, val in catalog_updates.items():
                await db.execute(
                    text(
                        f"UPDATE cve_catalog SET {field} = :{field},"
                        f" last_updated = NOW() WHERE cve_id = :cve_id"
                    ),
                    {"cve_id": cve_id, field: val},
                )
            # exploited / exploitability_context feed the materialized
            # score of every finding of this CVE — global re-score.
            await rescore_cve(db, cve_id)

    await log_action(
        db,
        actor=actor,
        action="patch_finding",
        target_type=table_key,
        target_id=finding_id,
        detail=updates,
    )
    await db.commit()
    return {"status": "ok", "updated": len(updates)}


@router.patch("/host/{finding_id}")
async def patch_host_finding(
    finding_id: str,
    patch: FindingPatch,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("findings", "w")),
):
    """Update status/fix_status/exploited/context for a host package CVE."""
    return await _patch_finding("host", finding_id, patch, db, actor)


@router.patch("/container/{finding_id}")
async def patch_container_finding(
    finding_id: str,
    patch: FindingPatch,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("findings", "w")),
):
    """Update status/fix_status/exploited/context for a container CVE."""
    return await _patch_finding("container", finding_id, patch, db, actor)


def _cleanup_where(
    severity: str | None,
    fix_status: str | None,
    older_than_days: int | None,
    exploited: bool | None,
    status: str | None,
    os_filter: str | None = None,
    arch_filter: str | None = None,
    node_id: str | None = None,
    pkg_name: str | None = None,
) -> tuple[str, dict]:
    """Build WHERE clause for cleanup operations.

    os/arch filters use a subquery on nodes table so the clause works
    with COUNT, UPDATE, and DELETE (no JOIN needed).
    """
    clauses: list[str] = []
    params: dict = {}
    if severity and severity in ("critical", "high", "medium", "low"):
        clauses.append("severity = :severity")
        params["severity"] = severity.lower()
    if fix_status and fix_status in _ALLOWED_FIX:
        clauses.append("fix_status = :fix_status")
        params["fix_status"] = fix_status
    if older_than_days is not None and older_than_days > 0:
        clauses.append("scanned_at < NOW() - :days * INTERVAL '1 day'")
        params["days"] = older_than_days
    if exploited is not None:
        clauses.append(
            "cve_id IN (SELECT cve_id FROM cve_catalog WHERE exploited = :exploited)"
        )
        params["exploited"] = exploited
    if status and status in _ALLOWED_STATUS:
        clauses.append("status = :status")
        params["status"] = status
    if os_filter:
        clauses.append("node_id IN (SELECT id FROM nodes WHERE os ILIKE :os_filter)")
        params["os_filter"] = f"%{os_filter}%"
    if arch_filter:
        clauses.append(
            "node_id IN (SELECT id FROM nodes WHERE arch ILIKE :arch_filter)"
        )
        params["arch_filter"] = f"%{arch_filter}%"
    if node_id:
        clauses.append("node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if pkg_name:
        clauses.append("pkg_name ILIKE :pkg_name")
        params["pkg_name"] = f"%{pkg_name}%"
    where = where_clause(clauses)
    return where, params


@router.get("/cleanup/preview")
async def cleanup_preview(
    severity: str | None = None,
    target_type: str | None = None,
    fix_status: str | None = None,
    older_than_days: int | None = None,
    exploited: bool | None = None,
    status: str = "open",
    os: str | None = None,
    arch: str | None = None,
    node_id: str | None = None,
    pkg_name: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("findings", "r")),
):
    """Preview CVE counts matching cleanup filters."""
    where, params = _cleanup_where(
        severity,
        fix_status,
        older_than_days,
        exploited,
        status,
        os,
        arch,
        node_id,
        pkg_name,
    )
    host_count = 0
    ctr_count = 0

    if target_type != "container":
        r = await db.execute(
            text(f"SELECT COUNT(*) FROM cve_host_packages {where}"), params
        )
        host_count = r.scalar_one()
    if target_type != "package":
        r = await db.execute(
            text(f"SELECT COUNT(*) FROM cve_containers {where}"), params
        )
        ctr_count = r.scalar_one()

    # Breakdown by severity
    by_severity = {}
    for sev in ("critical", "high", "medium", "low"):
        c = 0
        sev_where = where
        sev_params = {**params, "sev_brk": sev}
        if sev_where:
            sev_where += " AND severity = :sev_brk"
        else:
            sev_where = "WHERE severity = :sev_brk"
        if target_type != "container":
            r = await db.execute(
                text(f"SELECT COUNT(*) FROM cve_host_packages {sev_where}"),
                sev_params,
            )
            c += r.scalar_one()
        if target_type != "package":
            r = await db.execute(
                text(f"SELECT COUNT(*) FROM cve_containers {sev_where}"),
                sev_params,
            )
            c += r.scalar_one()
        by_severity[sev] = c

    # Breakdown by fix_status
    by_fix = {}
    for fs in ("fixed_available", "unfixed", "not_affected", "will_not_fix"):
        c = 0
        fs_where = where
        fs_params = {**params, "fs_brk": fs}
        if fs_where:
            fs_where += " AND fix_status = :fs_brk"
        else:
            fs_where = "WHERE fix_status = :fs_brk"
        if target_type != "container":
            r = await db.execute(
                text(f"SELECT COUNT(*) FROM cve_host_packages {fs_where}"),
                fs_params,
            )
            c += r.scalar_one()
        if target_type != "package":
            r = await db.execute(
                text(f"SELECT COUNT(*) FROM cve_containers {fs_where}"),
                fs_params,
            )
            c += r.scalar_one()
        by_fix[fs] = c

    return {
        "total": host_count + ctr_count,
        "host_count": host_count,
        "container_count": ctr_count,
        "by_severity": by_severity,
        "by_fix_status": by_fix,
    }


@router.post("/cleanup/execute")
async def cleanup_execute(
    body: CleanupExecute,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("findings", "w")),
):
    """Bulk update or delete CVE findings matching filters."""
    await set_statement_timeout(db, "long")
    if body.action not in ("resolve", "ignore", "delete"):
        return {"error": "action must be resolve, ignore, or delete"}

    # Mode 1: act on specific IDs (checkbox selection)
    if body.ids and len(body.ids) > 0:
        affected = 0
        for table in ("cve_host_packages", "cve_containers"):
            if body.action == "delete":
                r = await db.execute(
                    text(f"DELETE FROM {table} WHERE id = ANY(CAST(:ids AS uuid[]))"),
                    {"ids": body.ids},
                )
            else:
                new_status = "resolved" if body.action == "resolve" else "ignored"
                r = await db.execute(
                    text(
                        f"UPDATE {table} SET status = :new_st "
                        f"WHERE id = ANY(CAST(:ids AS uuid[])) AND status != :new_st"
                    ),
                    {"ids": body.ids, "new_st": new_status},
                )
            affected += r.rowcount

        await log_action(
            db,
            actor=actor,
            action="cleanup_cves",
            target_type="selected",
            detail={"action": body.action, "affected": affected, "ids": body.ids[:10]},
        )
        await db.commit()
        return {"status": "ok", "action": body.action, "affected": affected}

    # Mode 2: act on all matching filters
    where, params = _cleanup_where(
        body.severity,
        body.fix_status,
        body.older_than_days,
        body.exploited,
        body.status,
        body.os,
        body.arch,
        body.node_id,
        body.pkg_name,
    )
    if not where:
        return {"error": "at least one filter required"}

    affected = 0
    tables = []
    if body.target_type != "container":
        tables.append("cve_host_packages")
    if body.target_type != "package":
        tables.append("cve_containers")

    for table in tables:
        if body.action == "delete":
            r = await db.execute(text(f"DELETE FROM {table} {where}"), params)
        else:
            new_status = "resolved" if body.action == "resolve" else "ignored"
            # Append the status guard to the OUTER where. A str.replace on
            # "WHERE" would also rewrite the WHERE inside the os/arch/exploited
            # subqueries (e.g. nodes/cve_catalog), referencing a status column
            # they don't have → malformed SQL. `where` is non-empty here (the
            # mode-2 guard above returns when it's empty).
            upd_where = f"{where} AND status != :new_st"
            r = await db.execute(
                text(f"UPDATE {table} SET status = :new_st {upd_where}"),
                {**params, "new_st": new_status},
            )
        affected += r.rowcount

    await log_action(
        db,
        actor=actor,
        action="cleanup_cves",
        target_type="bulk",
        detail={
            "action": body.action,
            "affected": affected,
            "filters": body.model_dump(exclude_none=True),
        },
    )
    await db.commit()
    logger.info("[cleanup] %s: %d CVEs affected", body.action, affected)
    return {"status": "ok", "action": body.action, "affected": affected}


# Orphan = a finding pinned to an image:tag with zero live containers.
# Catches both cases : the image row was already wiped from container_images
# (retention sweep already ran) and the ghost case where the row still
# exists but no containers reference it (the per-image Delete + resolve CVEs
# button handles that one variant at a time, this is the bulk version).
#
# Image refs follow `[REGISTRY[:PORT]/]NAME[:TAG]`, so the tag is always after
# the LAST colon. Match the collector's rsplit(':', 1) by stripping the
# right-most `:tag` suffix; SPLIT_PART would left-anchor and falsely orphan
# every container hosted on a registry-with-port (Harbor on :443,
# GitLab Registry on :5000, localhost dev registries, ...).
_ORPHAN_CVE_WHERE = """
    cc.status = 'open'
    AND cc.image IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM containers cont
        JOIN container_images ci ON ci.id = cont.image_id
        WHERE ci.image = regexp_replace(cc.image, ':[^:]*$', '')
          AND ci.tag = COALESCE(
              NULLIF(substring(cc.image FROM ':([^:]+)$'), ''),
              'latest'
          )
    )
"""

_ORPHAN_SECRET_WHERE = """
    sd.status = 'open'
    AND sd.image IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM containers cont
        JOIN container_images ci ON ci.id = cont.image_id
        WHERE ci.image = regexp_replace(sd.image, ':[^:]*$', '')
          AND ci.tag = COALESCE(
              NULLIF(substring(sd.image FROM ':([^:]+)$'), ''),
              'latest'
          )
    )
"""


@router.get("/orphan-cves/preview")
async def orphan_cves_preview(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("findings", "r")),
):
    """Preview container findings whose image:tag has no live container."""
    cve_row = (
        (
            await db.execute(
                text(f"""
                SELECT COUNT(*) AS total,
                       COUNT(DISTINCT cc.image) AS image_count
                FROM cve_containers cc
                WHERE {_ORPHAN_CVE_WHERE}
                """)
            )
        )
        .mappings()
        .first()
    )
    images = await db.execute(
        text(f"""
        SELECT cc.image AS image, COUNT(*) AS cve_count
        FROM cve_containers cc
        WHERE {_ORPHAN_CVE_WHERE}
        GROUP BY cc.image
        ORDER BY cve_count DESC
        LIMIT 20
        """)
    )
    secrets_total = (
        await db.execute(
            text(f"""
            SELECT COUNT(*) FROM secrets_detected sd
            WHERE {_ORPHAN_SECRET_WHERE}
            """)
        )
    ).scalar_one()

    return {
        "cves_total": cve_row["total"] or 0,
        "image_count": cve_row["image_count"] or 0,
        "images": [dict(r._mapping) for r in images],
        "secrets_total": secrets_total,
    }


@router.post("/orphan-cves/purge")
async def orphan_cves_purge(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("findings", "w")),
):
    """Mark orphan container findings as resolved + drop matched ghost rows.

    Mirrors the retention job's persistence pattern : write into cve_status
    so a later rescan won't reopen them, then flip cve_containers status.
    Also drops container_images rows that match the orphan image:tag pairs
    we just resolved AND have no live containers — the same cleanup the
    per-image Delete button does, but scoped to images touched by this
    purge (an unbounded DELETE here would silently sweep dozens of
    unrelated ghost images, contradicting the docstring + UI flow).
    """
    # Capture the (image, tag) pairs we're about to resolve BEFORE the
    # UPDATE flips their status — _ORPHAN_*_WHERE filters on status='open'
    # so re-running it after the UPDATE would return nothing. Right-anchored
    # split mirrors the collector's rsplit(':', 1) (registry-with-port safe).
    pairs_rows = await db.execute(
        text(f"""
        SELECT DISTINCT
            regexp_replace(cc.image, ':[^:]*$', '') AS image,
            COALESCE(
                NULLIF(substring(cc.image FROM ':([^:]+)$'), ''),
                'latest'
            ) AS tag
        FROM cve_containers cc
        WHERE {_ORPHAN_CVE_WHERE}
        UNION
        SELECT DISTINCT
            regexp_replace(sd.image, ':[^:]*$', ''),
            COALESCE(
                NULLIF(substring(sd.image FROM ':([^:]+)$'), ''),
                'latest'
            )
        FROM secrets_detected sd
        WHERE {_ORPHAN_SECRET_WHERE}
        """)
    )
    touched_pairs = [(r.image, r.tag) for r in pairs_rows]

    await db.execute(
        text(f"""
        INSERT INTO cve_status (node_id, cve_id, status, justification)
        SELECT DISTINCT cc.node_id, cc.cve_id,
               'resolved', 'image_orphan_manual_purge'
        FROM cve_containers cc
        WHERE {_ORPHAN_CVE_WHERE}
        ON CONFLICT (node_id, cve_id) DO UPDATE SET
            status = 'resolved',
            justification = EXCLUDED.justification,
            updated_at = NOW()
        """)
    )
    cves = await db.execute(
        text(f"""
        UPDATE cve_containers AS cc SET status = 'resolved'
        WHERE {_ORPHAN_CVE_WHERE}
        """)
    )
    secrets = await db.execute(
        text(f"""
        UPDATE secrets_detected AS sd SET status = 'resolved'
        WHERE {_ORPHAN_SECRET_WHERE}
        """)
    )
    # Scope ghost-image deletion to the (image, tag) pairs we just resolved.
    # A bare `DELETE ... WHERE NOT EXISTS (containers...)` would drop every
    # container_images row with no live container — including dozens that
    # never had any orphan CVE/secret.
    ghosts_dropped = 0
    if touched_pairs:
        values_sql = ",".join(f"(:img{i}, :tag{i})" for i in range(len(touched_pairs)))
        params: dict = {}
        for i, (img, tag) in enumerate(touched_pairs):
            params[f"img{i}"] = img
            params[f"tag{i}"] = tag
        ghosts = await db.execute(
            text(f"""
            DELETE FROM container_images ci
            USING (VALUES {values_sql}) AS p(img, tag)
            WHERE ci.image = p.img
              AND ci.tag = p.tag
              AND NOT EXISTS (
                  SELECT 1 FROM containers c WHERE c.image_id = ci.id
              )
            """),
            params,
        )
        ghosts_dropped = ghosts.rowcount or 0

    cves_resolved = cves.rowcount or 0
    secrets_resolved = secrets.rowcount or 0

    await log_action(
        db,
        actor=actor,
        action="purge_orphan_cves",
        target_type="bulk",
        detail={
            "cves_resolved": cves_resolved,
            "secrets_resolved": secrets_resolved,
            "ghost_images_dropped": ghosts_dropped,
        },
    )
    await db.commit()
    logger.info(
        "[orphan-purge] %d CVEs, %d secrets resolved, %d ghost images dropped",
        cves_resolved,
        secrets_resolved,
        ghosts_dropped,
    )
    return {
        "status": "ok",
        "cves_resolved": cves_resolved,
        "secrets_resolved": secrets_resolved,
        "ghost_images_dropped": ghosts_dropped,
    }


@router.post("/auto-resolve")
async def auto_resolve(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("findings", "w")),
):
    """Auto-resolve CVEs where fix_status indicates not affected or won't fix."""
    resolved = {"not_affected": 0, "will_not_fix": 0}

    for fs in ("not_affected", "will_not_fix"):
        for table in ("cve_host_packages", "cve_containers"):
            r = await db.execute(
                text(f"""
                    UPDATE {table} SET status = 'resolved'
                    WHERE fix_status = :fs AND status = 'open'
                """),
                {"fs": fs},
            )
            resolved[fs] += r.rowcount

    total = sum(resolved.values())
    await log_action(
        db,
        actor=actor,
        action="auto_resolve_cves",
        target_type="bulk",
        detail={"resolved": total, "breakdown": resolved},
    )
    await db.commit()
    logger.info("[auto-resolve] %d CVEs resolved (%s)", total, resolved)
    return {"status": "ok", "resolved": total, "breakdown": resolved}


@router.get("/cleanup/list")
async def cleanup_list(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    target_type: str | None = None,
    fix_status: str | None = None,
    older_than_days: int | None = None,
    exploited: bool | None = None,
    status: str = "open",
    os: str | None = None,
    arch: str | None = None,
    node_id: str | None = None,
    pkg_name: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("findings", "r")),
):
    """List CVE findings matching cleanup filters."""
    where, params = _cleanup_where(
        severity,
        fix_status,
        older_than_days,
        exploited,
        status,
        os,
        arch,
        node_id,
        pkg_name,
    )
    offset = (page - 1) * per_page
    params["limit"] = per_page
    params["offset"] = offset

    items = []

    if target_type != "container":
        rows = await db.execute(
            text(f"""
                SELECT h.id, h.cve_id, h.severity, cat.cvss_score,
                       h.pkg_name, h.installed_ver, h.fixed_ver,
                       h.fix_status, h.status,
                       COALESCE(cat.exploited, false) AS exploited,
                       h.scanned_at,
                       'package' AS target_type,
                       n.hostname, n.os, n.arch
                FROM cve_host_packages h
                JOIN cve_catalog cat ON cat.cve_id = h.cve_id
                JOIN nodes n ON n.id = h.node_id
                {where}
                ORDER BY cat.cvss_score DESC NULLS LAST
                LIMIT :limit OFFSET :offset
            """),
            params,
        )
        items.extend(dict(r._mapping) for r in rows)

    if target_type != "package" and len(items) < per_page:
        remaining = per_page - len(items)
        ctr_off = max(0, offset - len(items)) if target_type is None else offset
        ctr_params = {**params, "limit": remaining, "offset": ctr_off}
        rows = await db.execute(
            text(f"""
                SELECT c.id, c.cve_id, c.severity, cat.cvss_score,
                       c.pkg_name, c.installed_ver, c.fixed_ver,
                       c.fix_status, c.status,
                       COALESCE(cat.exploited, false) AS exploited,
                       c.scanned_at,
                       c.image, 'container' AS target_type,
                       n.hostname, n.os, n.arch
                FROM cve_containers c
                JOIN cve_catalog cat ON cat.cve_id = c.cve_id
                JOIN nodes n ON n.id = c.node_id
                {where}
                ORDER BY cat.cvss_score DESC NULLS LAST
                LIMIT :limit OFFSET :offset
            """),
            ctr_params,
        )
        items.extend(dict(r._mapping) for r in rows)

    # Total count
    total = 0
    if target_type != "container":
        r = await db.execute(
            text(f"SELECT COUNT(*) FROM cve_host_packages {where}"),
            {k: v for k, v in params.items() if k not in ("limit", "offset")},
        )
        total += r.scalar_one()
    if target_type != "package":
        r = await db.execute(
            text(f"SELECT COUNT(*) FROM cve_containers {where}"),
            {k: v for k, v in params.items() if k not in ("limit", "offset")},
        )
        total += r.scalar_one()

    return {"items": items, "total": total, "page": page, "per_page": per_page}


@router.get("/host/{finding_id}/score")
async def get_host_finding_score(
    finding_id: str,
    listen: str = "docker_internal",
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("findings", "r")),
):
    """Compute contextual score for a host package CVE finding."""
    validate_uuid(finding_id, "finding_id")
    row = (
        (
            await db.execute(
                text("""
            SELECT hp.id, hp.cve_id, hp.severity, hp.fix_status,
                   cat.cvss_score,
                   COALESCE(cat.exploited, false) AS exploited,
                   COALESCE(cat.exploitability_context, 'unclear')
                       AS exploitability_context
            FROM cve_host_packages hp
            JOIN cve_catalog cat ON cat.cve_id = hp.cve_id
            WHERE hp.id = :id
            """),
                {"id": finding_id},
            )
        )
        .mappings()
        .first()
    )
    if not row:
        return {"error": "not found"}

    if listen not in _ALLOWED_LISTEN:
        listen = "docker_internal"

    score = compute_score(
        cvss_score=row["cvss_score"],
        exploited=row["exploited"],
        listen=listen,
        fix_status=row["fix_status"] or "unfixed",
        exploitability_context=row["exploitability_context"],
        severity=row["severity"],
    )
    return {
        "finding_id": finding_id,
        "cve_id": row["cve_id"],
        "score": score,
        "inputs": {
            "cvss_score": row["cvss_score"],
            "exploited": row["exploited"],
            "listen": listen,
            "fix_status": row["fix_status"],
            "exploitability_context": row["exploitability_context"],
        },
    }


@router.get("/container/{finding_id}/score")
async def get_container_finding_score(
    finding_id: str,
    listen: str = "docker_internal",
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("findings", "r")),
):
    """Compute contextual score for a container CVE finding."""
    validate_uuid(finding_id, "finding_id")
    row = (
        (
            await db.execute(
                text("""
            SELECT cc.id, cc.cve_id, cc.severity, cc.fix_status,
                   cat.cvss_score,
                   COALESCE(cat.exploited, false) AS exploited,
                   COALESCE(cat.exploitability_context, 'unclear')
                       AS exploitability_context,
                   COALESCE(r.listen, 'docker_internal') AS repo_listen
            FROM cve_containers cc
            JOIN cve_catalog cat ON cat.cve_id = cc.cve_id
            LEFT JOIN repositories r
                ON r.image_name = regexp_replace(cc.image, ':[^:]*$', '')
                AND r.node_id = cc.node_id
            WHERE cc.id = :id
            """),
                {"id": finding_id},
            )
        )
        .mappings()
        .first()
    )
    if not row:
        return {"error": "not found"}

    fallback = row["repo_listen"] or "docker_internal"
    effective_listen = listen if listen in _ALLOWED_LISTEN else fallback

    score = compute_score(
        cvss_score=row["cvss_score"],
        exploited=row["exploited"],
        listen=effective_listen,
        fix_status=row["fix_status"] or "unfixed",
        exploitability_context=row["exploitability_context"],
        severity=row["severity"],
    )
    return {
        "finding_id": finding_id,
        "cve_id": row["cve_id"],
        "score": score,
        "inputs": {
            "cvss_score": row["cvss_score"],
            "exploited": row["exploited"],
            "listen": effective_listen,
            "fix_status": row["fix_status"],
            "exploitability_context": row["exploitability_context"],
        },
    }
