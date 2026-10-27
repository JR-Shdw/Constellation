# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Misconfigurations ingest + read + compliance summary."""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_collect_token, require_permission
from ..database import get_db
from ..utils.hostname import resolve_node_id
from ..utils.severity import normalize_severity
from ..utils.sql import set_statement_timeout, where_clause
from .automation import run_evaluation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["misconfigurations"])


@router.post("/misconfigurations/report")
async def misconf_report(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Ingest misconfigurations from Trivy config scan.

    Always bumps `nodes.last_trivy_config_scan` even when the
    payload is empty — that's how we know the scan ran (and the
    host is just clean) vs. the scan never ran. Same convention as
    `last_trivy_host_scan` after a CVE-clean rootfs scan.
    """
    await set_statement_timeout(db, "batch")
    hostname = payload.get("hostname", "")
    source = payload.get("source", "trivy")
    items = payload.get("misconfigurations", [])

    node_id = await resolve_node_id(db, hostname)
    if not node_id:
        return {"status": "error", "detail": f"Node {hostname} not found"}

    # Track the scan ran (even with 0 findings). Otherwise a host
    # that hardens to clean disappears from /scan/status forever.
    await db.execute(
        text("""
        UPDATE nodes SET last_trivy_config_scan = NOW()
        WHERE id = CAST(:nid AS uuid)
        """),
        {"nid": node_id},
    )

    inserted = 0
    for m in items:
        if not isinstance(m, dict):
            continue
        rule_id = m.get("ID", m.get("rule_id", ""))
        if not rule_id:
            continue

        # Upsert rule metadata into misconf_rules (once per rule)
        await db.execute(
            text("""
            INSERT INTO misconf_rules
                (rule_id, rule_title, severity, message, resolution, source)
            VALUES (:rule, :title, :sev, :msg, :resolution, :source)
            ON CONFLICT (rule_id) DO UPDATE SET
                rule_title = EXCLUDED.rule_title,
                severity   = EXCLUDED.severity,
                message    = EXCLUDED.message,
                resolution = EXCLUDED.resolution,
                last_updated = NOW()
            """),
            {
                "rule": rule_id,
                "title": (m.get("Title") or m.get("rule_title") or "")[:200],
                "sev": normalize_severity(m.get("Severity") or m.get("severity")),
                "msg": (m.get("Message") or m.get("message") or "")[:500],
                "resolution": (m.get("Resolution") or m.get("resolution") or "")[:500],
                "source": source,
            },
        )

        # Upsert per-node finding (lean — no rule metadata)
        await db.execute(
            text("""
            INSERT INTO misconfigurations
                (node_id, rule_id, target)
            VALUES
                (CAST(:nid AS uuid), :rule, :target)
            ON CONFLICT (node_id, rule_id) DO UPDATE SET
                target = EXCLUDED.target,
                detected_at = NOW()
            """),
            {
                "nid": node_id,
                "rule": rule_id,
                "target": (m.get("Target") or m.get("target") or "")[:200],
            },
        )
        inserted += 1

    await db.commit()

    # Fire automation event for critical/high misconfigurations
    dicts = [m for m in items if isinstance(m, dict)]
    critical_count = sum(
        1
        for m in dicts
        if normalize_severity(m.get("Severity", m.get("severity")))
        in ("critical", "high")
    )
    if critical_count > 0:
        try:
            await run_evaluation(
                {
                    "trigger_type": "misconf_detected",
                    "hostname": hostname,
                    "severity": "critical"
                    if any(
                        normalize_severity(m.get("Severity", m.get("severity")))
                        == "critical"
                        for m in dicts
                    )
                    else "high",
                },
                db,
            )
            await db.commit()
        except Exception as e:
            logger.warning("[misconf] automation eval failed: %s", e)

    return {"status": "ok", "node_id": node_id, "inserted": inserted}


@router.get("/misconfigurations")
async def list_misconfigurations(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    status: str | None = None,
    node_id: str | None = None,
    hostname: str | None = None,
    sort_by: str | None = None,
    sort_dir: str = Query("asc"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("misconf", "r")),
):
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if severity:
        clauses.append("r.severity = :sev")
        params["sev"] = severity
    if status:
        clauses.append("m.status = :status")
        params["status"] = status
    if node_id:
        clauses.append("m.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if hostname:
        clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    where = where_clause(clauses)

    _SORT_MAP = {
        "severity": (
            "CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
            " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        ),
        "status": "m.status",
        "hostname": "n.hostname",
        "rule_id": "m.rule_id",
        "detected_at": "m.detected_at",
    }
    direction = "DESC" if sort_dir == "desc" else "ASC"
    order = (
        f"{_SORT_MAP[sort_by]} {direction}, m.detected_at DESC"
        if sort_by in _SORT_MAP
        else "CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
        " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,"
        " m.detected_at DESC"
    )

    # Always JOIN misconf_rules for severity; JOIN nodes when hostname filter
    base_joins = "JOIN misconf_rules r ON r.rule_id = m.rule_id"
    join_nodes = (
        f"{base_joins} JOIN nodes n ON n.id = m.node_id" if hostname else base_joins
    )
    total = (
        await db.execute(
            text(f"SELECT COUNT(*) FROM misconfigurations m {join_nodes} {where}"),
            params,
        )
    ).scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT m.id, m.node_id, m.rule_id, m.target, m.status, m.detected_at,
               r.rule_title, r.severity, r.message, r.resolution, r.source,
               n.hostname
        FROM misconfigurations m
        JOIN misconf_rules r ON r.rule_id = m.rule_id
        JOIN nodes n ON n.id = m.node_id
        {where}
        ORDER BY {order}
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


_VALID_MISCONF_STATUS = (
    "open",
    "acknowledged",
    "mitigated",
    "resolved",
    "false_positive",
    "accepted_risk",
)


@router.patch("/misconfigurations/{misconf_id}")
async def patch_misconf(
    misconf_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("misconf", "w")),
):
    """Update misconf status."""
    from ..audit import log_action, validate_uuid

    validate_uuid(misconf_id)
    new_status = body.get("status", "")
    if new_status not in _VALID_MISCONF_STATUS:
        from fastapi import HTTPException

        raise HTTPException(400, f"status must be one of {_VALID_MISCONF_STATUS}")
    await db.execute(
        text("UPDATE misconfigurations SET status = :st WHERE id = CAST(:mid AS uuid)"),
        {"mid": misconf_id, "st": new_status},
    )
    await log_action(
        db,
        actor=actor,
        action="patch_misconf",
        target_type="misconfiguration",
        target_id=misconf_id,
        detail={"status": new_status},
    )
    await db.commit()
    return {"status": "ok"}


@router.get("/compliance")
async def compliance_summary(
    search: str | None = Query(None),
    environment: str | None = Query(None),
    sort_by: str | None = Query(None),
    sort_dir: str = Query("desc"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("misconf", "r")),
):
    # Cache unfiltered requests (default page load)
    use_cache = not search and not environment and not sort_by
    if use_cache:
        from .read import _get_cache

        cached = _get_cache("compliance")
        if cached:
            return cached

    clauses = []
    params: dict = {}
    if search:
        clauses.append("hostname ILIKE :search")
        params["search"] = f"%{search}%"
    if environment:
        clauses.append("environment = :env")
        params["env"] = environment
    where = where_clause(clauses)

    _SORT_MAP = {
        "hostname": "hostname",
        "env": "environment",
        "sca_score": "sca_score",
        "misconf_total": "misconf_total",
        "misconf_critical": "misconf_critical",
        "cve_open_total": "cve_open_total",
        "cve_critical": "cve_critical_open",
    }
    direction = "DESC" if sort_dir == "desc" else "ASC"
    order = (
        f"{_SORT_MAP[sort_by]} {direction} NULLS LAST, hostname"
        if sort_by in _SORT_MAP
        else "cve_critical_open DESC, misconf_critical DESC, hostname"
    )

    rows = await db.execute(
        text(f"""
        SELECT * FROM v_compliance_summary
        {where}
        ORDER BY {order}
        """),
        params,
    )
    result = {"items": [dict(r._mapping) for r in rows]}

    if use_cache:
        from .read import _set_cache

        _set_cache("compliance", result)

    return result
