# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Incidents — SSVC-prioritized incident management (Lot 2c)."""

import json
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..database import get_db
from ..models.schemas import (
    IncidentCommentBody,
    IncidentCreate,
    IncidentPatch,
    PriorityRuleSetCreate,
)
from ..utils.incidents import (
    create_incident,
    insert_event,
    invalidate_rule_set_cache,
    patch_incident,
)
from ..utils.sql import where_clause

router = APIRouter(prefix="/api/v1", tags=["incidents"])

_stats_cache: dict = {}
_STATS_TTL = 30


# Incidents — list / detail / create / patch / comment


@router.get("/incidents")
async def list_incidents(
    status: str | None = None,
    priority: str | None = None,
    assignee: str | None = None,
    cve_id: str | None = None,
    q: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("incidents", "r")),
):
    clauses: list[str] = []
    params: dict = {}
    if status:
        clauses.append("status = :status")
        params["status"] = status
    if priority:
        clauses.append("priority = :priority")
        params["priority"] = priority
    if assignee:
        clauses.append("assignee = :assignee")
        params["assignee"] = assignee
    if cve_id:
        clauses.append("cve_id = :cve_id")
        params["cve_id"] = cve_id
    if q:
        clauses.append("(title ILIKE :q OR description ILIKE :q)")
        params["q"] = f"%{q}%"
    where = where_clause(clauses)

    total_row = await db.execute(
        text(f"SELECT COUNT(*) FROM incidents {where}"), params
    )
    total = total_row.scalar_one()

    offset = (page - 1) * per_page
    params.update({"limit": per_page, "offset": offset})
    rows = await db.execute(
        text(f"""
        SELECT id::text AS id, uid, title, status, priority, close_reason,
               cve_id, affected_asset, affected_package, severity,
               environment, exposure, assignee, rule_matched,
               created_at, updated_at, triaged_at, resolved_at, closed_at
          FROM incidents
          {where}
         ORDER BY created_at DESC
         LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(r) for r in rows.mappings().all()],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/incidents/stats")
async def incidents_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("incidents", "r")),
):
    entry = _stats_cache.get("stats")
    if entry and (time.monotonic() - entry["ts"]) < _STATS_TTL:
        return entry["data"]

    row = await db.execute(
        text("""
        WITH by_status AS (
            SELECT status, COUNT(*) AS n FROM incidents GROUP BY status
        ),
        by_priority AS (
            SELECT priority, COUNT(*) AS n FROM incidents GROUP BY priority
        ),
        timing AS (
            SELECT
                AVG(EXTRACT(EPOCH FROM (triaged_at - created_at)))
                    FILTER (WHERE triaged_at IS NOT NULL) AS mtta_avg,
                PERCENTILE_CONT(0.5) WITHIN GROUP (
                    ORDER BY EXTRACT(EPOCH FROM (triaged_at - created_at))
                ) FILTER (WHERE triaged_at IS NOT NULL) AS mtta_p50,
                AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)))
                    FILTER (WHERE resolved_at IS NOT NULL) AS mttr_avg,
                PERCENTILE_CONT(0.5) WITHIN GROUP (
                    ORDER BY EXTRACT(EPOCH FROM (resolved_at - created_at))
                ) FILTER (WHERE resolved_at IS NOT NULL) AS mttr_p50
              FROM incidents
        ),
        open_count AS (
            SELECT COUNT(*) AS n FROM incidents
             WHERE status NOT IN ('resolved','closed')
        )
        SELECT
            (SELECT json_object_agg(status, n) FROM by_status) AS by_status,
            (SELECT json_object_agg(priority, n) FROM by_priority) AS by_priority,
            (SELECT mtta_avg FROM timing) AS mtta_avg,
            (SELECT mtta_p50 FROM timing) AS mtta_p50,
            (SELECT mttr_avg FROM timing) AS mttr_avg,
            (SELECT mttr_p50 FROM timing) AS mttr_p50,
            (SELECT n FROM open_count) AS total_open
        """)
    )
    rec = row.mappings().first() or {}
    data = {
        "by_status": rec.get("by_status") or {},
        "by_priority": rec.get("by_priority") or {},
        "mtta_avg_seconds": float(rec["mtta_avg"]) if rec.get("mtta_avg") else None,
        "mtta_p50_seconds": float(rec["mtta_p50"]) if rec.get("mtta_p50") else None,
        "mttr_avg_seconds": float(rec["mttr_avg"]) if rec.get("mttr_avg") else None,
        "mttr_p50_seconds": float(rec["mttr_p50"]) if rec.get("mttr_p50") else None,
        "total_open": int(rec.get("total_open") or 0),
    }
    _stats_cache["stats"] = {"data": data, "ts": time.monotonic()}
    return data


@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("incidents", "r")),
):
    validate_uuid(incident_id, "incident_id")
    row = await db.execute(
        text("""
        SELECT id::text AS id, uid, title, description, status, priority,
               close_reason, cve_id, affected_asset, affected_package,
               severity, environment, exposure,
               priority_rule_set_id::text AS priority_rule_set_id,
               rule_matched, assignee, source_trigger, source_event,
               created_at, updated_at, triaged_at, resolved_at, closed_at
          FROM incidents
         WHERE id = CAST(:iid AS uuid)
        """),
        {"iid": incident_id},
    )
    incident = row.mappings().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    ev_rows = await db.execute(
        text("""
        SELECT id::text AS id, event_type, actor, from_value, to_value,
               detail, created_at
          FROM incident_events
         WHERE incident_id = CAST(:iid AS uuid)
         ORDER BY created_at ASC
        """),
        {"iid": incident_id},
    )
    events = [dict(r) for r in ev_rows.mappings().all()]

    tk_rows = await db.execute(
        text("""
        SELECT t.id::text AS id, t.external_id, t.external_url, t.external_status,
               t.last_synced_at, t.created_at,
               i.name AS integration_name, i.platform
          FROM incident_tickets t
          JOIN itsm_integrations i ON i.id = t.integration_id
         WHERE t.incident_id = CAST(:iid AS uuid)
         ORDER BY t.created_at ASC
        """),
        {"iid": incident_id},
    )
    tickets = [dict(r) for r in tk_rows.mappings().all()]
    return {"incident": dict(incident), "events": events, "tickets": tickets}


@router.post("/incidents")
async def create_incident_endpoint(
    payload: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("incidents", "w")),
):
    result = await create_incident(
        db,
        title=payload.title,
        description=payload.description,
        cve_id=payload.cve_id,
        affected_asset=payload.affected_asset,
        affected_package=payload.affected_package,
        severity=payload.severity,
        environment=payload.environment,
        exposure=payload.exposure,
        cvss=payload.cvss,
        in_kev=payload.in_kev,
        assignee=payload.assignee,
        source_trigger="manual",
        actor=actor,
    )
    _stats_cache.clear()
    return result


@router.patch("/incidents/{incident_id}")
async def patch_incident_endpoint(
    incident_id: str,
    payload: IncidentPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("incidents", "w")),
):
    validate_uuid(incident_id, "incident_id")
    result = await patch_incident(
        db,
        incident_id,
        actor=actor,
        status_=payload.status,
        priority=payload.priority,
        assignee=payload.assignee,
        description=payload.description,
        close_reason=payload.close_reason,
    )
    _stats_cache.clear()
    return result


@router.post("/incidents/{incident_id}/comment")
async def comment_incident(
    incident_id: str,
    payload: IncidentCommentBody,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("incidents", "w")),
):
    validate_uuid(incident_id, "incident_id")
    row = await db.execute(
        text("SELECT 1 FROM incidents WHERE id = CAST(:iid AS uuid)"),
        {"iid": incident_id},
    )
    if not row.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

    await insert_event(
        db,
        incident_id=incident_id,
        event_type="commented",
        actor=actor,
        detail={"body": payload.body},
    )
    await log_action(
        db,
        actor=actor,
        action="incident.commented",
        target_type="incident",
        target_id=incident_id,
        detail={"body": payload.body},
    )
    await db.commit()
    return {"ok": True}


# Priority rule sets


@router.get("/priority-rules")
async def list_priority_rules(
    active_only: bool = False,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("incidents", "r")),
):
    sql = """
        SELECT id::text AS id, name, description, is_active, rules,
               created_at, updated_at
          FROM priority_rule_sets
    """
    if active_only:
        sql += " WHERE is_active = true"
    sql += " ORDER BY created_at DESC"
    rows = await db.execute(text(sql))
    return {"items": [dict(r) for r in rows.mappings().all()]}


@router.get("/priority-rules/{rule_id}")
async def get_priority_rules(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("incidents", "r")),
):
    validate_uuid(rule_id, "rule_id")
    row = await db.execute(
        text("""
        SELECT id::text AS id, name, description, is_active, rules,
               created_at, updated_at
          FROM priority_rule_sets
         WHERE id = CAST(:rid AS uuid)
        """),
        {"rid": rule_id},
    )
    rec = row.mappings().first()
    if not rec:
        raise HTTPException(status_code=404, detail="Rule set not found")
    return dict(rec)


@router.post("/priority-rules")
async def create_priority_rules(
    payload: PriorityRuleSetCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    rules_json = json.dumps([r.model_dump() for r in payload.rules])
    row = await db.execute(
        text("""
        INSERT INTO priority_rule_sets (name, description, is_active, rules)
        VALUES (:name, :desc, false, CAST(:rules AS jsonb))
        ON CONFLICT (name) DO UPDATE SET
            description = EXCLUDED.description,
            rules = EXCLUDED.rules,
            updated_at = NOW()
        RETURNING id::text AS id, name, is_active
        """),
        {"name": payload.name, "desc": payload.description, "rules": rules_json},
    )
    rec = row.mappings().first()
    await log_action(
        db,
        actor=actor,
        action="priority_rules.created",
        target_type="priority_rule_set",
        target_id=rec["id"] if rec else None,
        detail={"name": payload.name},
    )
    await db.commit()
    return dict(rec) if rec else {"ok": True}


@router.post("/priority-rules/{rule_id}/activate")
async def activate_priority_rules(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("settings", "w")),
):
    validate_uuid(rule_id, "rule_id")
    row = await db.execute(
        text("SELECT name FROM priority_rule_sets WHERE id = CAST(:rid AS uuid)"),
        {"rid": rule_id},
    )
    if not row.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule set not found")

    await db.execute(
        text("UPDATE priority_rule_sets SET is_active = false WHERE is_active = true")
    )
    await db.execute(
        text("""
        UPDATE priority_rule_sets
           SET is_active = true, updated_at = NOW()
         WHERE id = CAST(:rid AS uuid)
        """),
        {"rid": rule_id},
    )
    await log_action(
        db,
        actor=actor,
        action="priority_rules.activated",
        target_type="priority_rule_set",
        target_id=rule_id,
    )
    await db.commit()
    invalidate_rule_set_cache()
    return {"ok": True, "id": rule_id}
