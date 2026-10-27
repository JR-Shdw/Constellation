# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Incident service layer — state machine, UID, dedup, SSVC scoring."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action

logger = logging.getLogger(__name__)

# State machine
STATES = ("new", "triaged", "in_progress", "resolved", "closed")
PRIORITIES = ("P1", "P2", "P3", "P4")
CLOSE_REASONS = (
    "fixed",
    "mitigated",
    "false_positive",
    "duplicate",
    "wont_fix",
    "accepted_risk",
)

_ALLOWED: dict[str, set[str]] = {
    "new": {"triaged", "in_progress", "closed"},
    "triaged": {"in_progress", "closed"},
    "in_progress": {"resolved", "closed"},
    "resolved": {"in_progress", "closed"},
    "closed": set(),  # terminal
}

_TIMESTAMP_FOR = {
    "triaged": "triaged_at",
    "resolved": "resolved_at",
    "closed": "closed_at",
}

# Sentinel for "set this column to SQL NOW()". Must be an object, not a string:
# a string sentinel ("now") collides with free-text columns (a user patching
# description/assignee to the literal "now" would get a timestamp written).
_NOW = object()

# Rule-set cache (TTL 120s) — pattern from read.py
_RULESET_CACHE: dict[str, Any] = {}
_RULESET_TTL = 120


def can_transition(from_state: str, to_state: str) -> bool:
    return to_state in _ALLOWED.get(from_state, set())


def timestamp_field_for(to_state: str) -> str | None:
    return _TIMESTAMP_FOR.get(to_state)


async def next_uid(db: AsyncSession) -> str:
    row = await db.execute(
        text("SELECT 'INC-' || lpad(nextval('incidents_uid_seq')::text, 6, '0') AS uid")
    )
    return row.scalar_one()


def invalidate_rule_set_cache() -> None:
    _RULESET_CACHE.clear()


async def get_active_rule_set(db: AsyncSession) -> dict | None:
    entry = _RULESET_CACHE.get("active")
    if entry and (time.monotonic() - entry["ts"]) < _RULESET_TTL:
        return entry["data"]
    row = await db.execute(
        text("""
        SELECT id, name, description, rules
          FROM priority_rule_sets
         WHERE is_active = true
         LIMIT 1
        """)
    )
    rec = row.mappings().first()
    data = dict(rec) if rec else None
    _RULESET_CACHE["active"] = {"data": data, "ts": time.monotonic()}
    return data


def _check_one_condition(event: dict, cond: dict) -> bool:
    """Evaluate a single condition dict (AND between keys, `any` is OR)."""
    if not cond:
        return True
    if "any" in cond:
        sub = cond["any"]
        if not isinstance(sub, list) or not sub:
            return False
        if not any(_check_one_condition(event, s) for s in sub):
            return False
    if cond.get("in_kev") is True and not event.get("in_kev"):
        return False
    cvss_min = cond.get("cvss_min")
    if cvss_min is not None:
        cvss = event.get("cvss")
        try:
            if cvss is None or float(cvss) < float(cvss_min):
                return False
        except (TypeError, ValueError):
            return False
    for key in ("severity", "environment", "exposure"):
        allowed = cond.get(key)
        if allowed is not None:
            if event.get(key) not in allowed:
                return False
    return True


def compute_priority(event: dict, rule_set: dict | None) -> tuple[str, str]:
    """First-match-wins over rule_set['rules']. Defaults to P4/unknown."""
    if not rule_set:
        return "P4", "no-rule-set"
    rules = rule_set.get("rules") or []
    if isinstance(rules, str):
        rules = json.loads(rules)
    for rule in rules:
        if _check_one_condition(event, rule.get("conditions") or {}):
            return rule.get("priority", "P4"), rule.get("name", "unknown")
    return "P4", "fallthrough"


async def find_dedup(
    db: AsyncSession,
    *,
    cve_id: str | None,
    affected_asset: str | None,
    affected_package: str | None,
    source_trigger: str | None = None,
) -> str | None:
    """Return UUID of an open incident matching the dedup tuple, or None.

    For CVE incidents the (cve_id, asset, package) tuple identifies the
    problem, so source_trigger is ignored — the same CVE on the same asset
    dedups regardless of detection path (manual vs cve_detected automation).

    For non-CVE incidents (cve_id NULL — backup_overdue, worker_offline,
    scan_stale, node_offline…) asset+package alone is NULL+host+NULL for every
    such trigger, which would collapse unrelated problems on one host into a
    single incident. source_trigger is added to the key in that case so e.g.
    a backup failure and a worker-offline on the same host stay distinct.
    """
    if not (cve_id or affected_asset or affected_package):
        return None
    row = await db.execute(
        text("""
        SELECT id::text AS id
          FROM incidents
         WHERE cve_id IS NOT DISTINCT FROM :cve
           AND affected_asset IS NOT DISTINCT FROM :asset
           AND affected_package IS NOT DISTINCT FROM :pkg
           AND (:cve IS NOT NULL OR source_trigger IS NOT DISTINCT FROM :strig)
           AND status NOT IN ('resolved','closed')
         ORDER BY created_at DESC
         LIMIT 1
        """),
        {
            "cve": cve_id,
            "asset": affected_asset,
            "pkg": affected_package,
            "strig": source_trigger,
        },
    )
    rec = row.mappings().first()
    return rec["id"] if rec else None


async def insert_event(
    db: AsyncSession,
    *,
    incident_id: str,
    event_type: str,
    actor: str,
    from_value: str | None = None,
    to_value: str | None = None,
    detail: dict | None = None,
) -> None:
    await db.execute(
        text("""
        INSERT INTO incident_events
            (incident_id, event_type, actor, from_value, to_value, detail)
        VALUES
            (CAST(:iid AS uuid), :etype, :actor, :fv, :tv, CAST(:detail AS jsonb))
        """),
        {
            "iid": incident_id,
            "etype": event_type,
            "actor": actor,
            "fv": from_value,
            "tv": to_value,
            "detail": json.dumps(detail) if detail else None,
        },
    )


async def _fetch_incident(db: AsyncSession, incident_id: str) -> dict | None:
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
    rec = row.mappings().first()
    return dict(rec) if rec else None


async def push_to_itsm(db: AsyncSession, incident: dict) -> list[dict]:
    """Best-effort push of a new incident to all enabled ITSM integrations.

    Returns list of created tickets ({integration_id, external_id, external_url}).
    Errors are logged but never raised — incident creation must succeed regardless.
    """
    from ..connectors import get_itsm
    from ..crypto import decrypt_auth_config

    rows = (
        (
            await db.execute(
                text(
                    "SELECT id, platform, base_url, auth_config, project_key"
                    " FROM itsm_integrations"
                    " WHERE enabled = true AND sync_outbound = true"
                )
            )
        )
        .mappings()
        .all()
    )

    created = []
    for integ in rows:
        auth = integ["auth_config"]
        if isinstance(auth, str):
            try:
                auth = json.loads(auth)
            except Exception:
                auth = {}
        auth = decrypt_auth_config(auth)
        try:
            connector = get_itsm(
                integ["platform"], integ["base_url"], auth, integ["project_key"]
            )
            title = f"[{incident.get('uid')}] {incident.get('title', '')}"
            desc_parts = [incident.get("description") or ""]
            if incident.get("cve_id"):
                desc_parts.append(f"CVE: {incident['cve_id']}")
            if incident.get("affected_asset"):
                desc_parts.append(f"Asset: {incident['affected_asset']}")
            if incident.get("affected_package"):
                desc_parts.append(f"Package: {incident['affected_package']}")
            description = "\n".join(p for p in desc_parts if p)
            external_id, external_url = await connector.create_ticket(
                title=title,
                description=description,
                priority=incident.get("priority", "P4"),
                labels=["cmdb", "incident"],
            )
            await db.execute(
                text(
                    "INSERT INTO incident_tickets"
                    " (incident_id, integration_id, external_id, external_url)"
                    " VALUES (CAST(:iid AS uuid), CAST(:integ AS uuid),"
                    "         :eid, :eurl)"
                    " ON CONFLICT (integration_id, external_id) DO NOTHING"
                ),
                {
                    "iid": incident["id"],
                    "integ": str(integ["id"]),
                    "eid": external_id,
                    "eurl": external_url,
                },
            )
            created.append(
                {
                    "integration_id": str(integ["id"]),
                    "platform": integ["platform"],
                    "external_id": external_id,
                    "external_url": external_url,
                }
            )
        except Exception as e:
            logger.warning(
                "[itsm] push failed for integration %s (%s): %s",
                integ["id"],
                integ["platform"],
                e,
            )
    if created:
        await db.commit()
    return created


async def create_incident(
    db: AsyncSession,
    *,
    title: str,
    description: str | None = None,
    cve_id: str | None = None,
    affected_asset: str | None = None,
    affected_package: str | None = None,
    severity: str | None = None,
    environment: str | None = None,
    exposure: str | None = None,
    cvss: float | None = None,
    in_kev: bool | None = None,
    source_trigger: str | None = None,
    source_event: dict | None = None,
    assignee: str | None = None,
    actor: str = "system",
) -> dict:
    """Orchestrator — dedup → score → INSERT + events + audit."""
    # 1. Dedup
    existing_id = await find_dedup(
        db,
        cve_id=cve_id,
        affected_asset=affected_asset,
        affected_package=affected_package,
        source_trigger=source_trigger,
    )
    if existing_id:
        await insert_event(
            db,
            incident_id=existing_id,
            event_type="action_executed",
            actor=actor,
            detail={
                "reason": "dedup",
                "source_trigger": source_trigger,
                "source_event": source_event,
            },
        )
        await db.commit()
        existing = await _fetch_incident(db, existing_id)
        if existing:
            existing["deduped"] = True
        return existing or {"id": existing_id, "deduped": True}

    # 2. Compute priority
    scoring_event = dict(source_event or {})
    scoring_event.update(
        {
            "severity": severity,
            "environment": environment,
            "exposure": exposure,
            "cvss": cvss if cvss is not None else scoring_event.get("cvss"),
            "in_kev": in_kev if in_kev is not None else scoring_event.get("in_kev"),
        }
    )
    rule_set = await get_active_rule_set(db)
    priority, rule_matched = compute_priority(scoring_event, rule_set)

    # 3. INSERT incident
    uid = await next_uid(db)
    new_id = str(uuid.uuid4())
    await db.execute(
        text("""
        INSERT INTO incidents
            (id, uid, title, description, status, priority, cve_id,
             affected_asset, affected_package, severity, environment, exposure,
             priority_rule_set_id, rule_matched, assignee,
             source_trigger, source_event)
        VALUES
            (CAST(:id AS uuid), :uid, :title, :desc, 'new', :priority, :cve,
             :asset, :pkg, :sev, :env, :expo,
             CAST(:rsid AS uuid), :rmatch, :assignee,
             :strig, CAST(:sevent AS jsonb))
        """),
        {
            "id": new_id,
            "uid": uid,
            "title": title,
            "desc": description,
            "priority": priority,
            "cve": cve_id,
            "asset": affected_asset,
            "pkg": affected_package,
            "sev": severity,
            "env": environment,
            "expo": exposure,
            "rsid": rule_set["id"] if rule_set else None,
            "rmatch": rule_matched,
            "assignee": assignee,
            "strig": source_trigger,
            "sevent": json.dumps(source_event) if source_event else None,
        },
    )

    # 4. Timeline event + audit
    await insert_event(
        db,
        incident_id=new_id,
        event_type="created",
        actor=actor,
        to_value=priority,
        detail={"rule_matched": rule_matched, "source_trigger": source_trigger},
    )
    await log_action(
        db,
        actor=actor,
        action="incident.created",
        target_type="incident",
        target_id=new_id,
        detail={"uid": uid, "priority": priority, "rule_matched": rule_matched},
    )
    await db.commit()

    created = await _fetch_incident(db, new_id)
    if created:
        created["deduped"] = False
        # Best-effort push to ITSM integrations (outbound).
        try:
            tickets = await push_to_itsm(db, created)
            if tickets:
                created["tickets"] = tickets
        except Exception as e:
            logger.warning("[itsm] push_to_itsm raised unexpectedly: %s", e)
    return created or {"id": new_id, "uid": uid, "priority": priority, "deduped": False}


async def patch_incident(
    db: AsyncSession,
    incident_id: str,
    *,
    actor: str,
    status_: str | None = None,
    priority: str | None = None,
    assignee: str | None = None,
    description: str | None = None,
    close_reason: str | None = None,
) -> dict:
    """Apply allowed deltas — enforces state machine, emits events."""
    current = await _fetch_incident(db, incident_id)
    if not current:
        raise HTTPException(status_code=404, detail="Incident not found")

    updates: dict[str, Any] = {}
    events: list[dict] = []

    # State transition
    if status_ and status_ != current["status"]:
        if not can_transition(current["status"], status_):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Illegal transition {current['status']} → {status_}",
            )
        if status_ == "closed" and not close_reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="close_reason required when closing an incident",
            )
        updates["status"] = status_
        ts_field = timestamp_field_for(status_)
        if ts_field:
            updates[ts_field] = _NOW  # replaced with SQL NOW() below
        # Reopen clears resolved_at
        if status_ == "in_progress" and current["status"] == "resolved":
            updates["resolved_at"] = None
        if close_reason and status_ == "closed":
            updates["close_reason"] = close_reason
        events.append(
            {
                "event_type": "status_changed",
                "from_value": current["status"],
                "to_value": status_,
                "detail": {"close_reason": close_reason} if close_reason else None,
            }
        )

    if priority and priority != current["priority"]:
        if priority not in PRIORITIES:
            raise HTTPException(status_code=400, detail=f"Invalid priority: {priority}")
        updates["priority"] = priority
        events.append(
            {
                "event_type": "priority_changed",
                "from_value": current["priority"],
                "to_value": priority,
                "detail": None,
            }
        )

    if assignee is not None and assignee != current["assignee"]:
        updates["assignee"] = assignee
        events.append(
            {
                "event_type": "assigned",
                "from_value": current["assignee"],
                "to_value": assignee,
                "detail": None,
            }
        )

    if description is not None and description != current["description"]:
        updates["description"] = description

    if not updates:
        return current

    # Build dynamic UPDATE — column names whitelisted by the code above
    set_parts: list[str] = []
    params: dict[str, Any] = {"iid": incident_id}
    for col, val in updates.items():
        if val is _NOW:
            set_parts.append(f"{col} = NOW()")
        else:
            set_parts.append(f"{col} = :{col}")
            params[col] = val
    set_parts.append("updated_at = NOW()")

    set_sql = ", ".join(set_parts)
    await db.execute(
        text(f"UPDATE incidents SET {set_sql} WHERE id = CAST(:iid AS uuid)"),
        params,
    )

    for ev in events:
        await insert_event(
            db,
            incident_id=incident_id,
            event_type=ev["event_type"],
            actor=actor,
            from_value=ev.get("from_value"),
            to_value=ev.get("to_value"),
            detail=ev.get("detail"),
        )
        await log_action(
            db,
            actor=actor,
            action=f"incident.{ev['event_type']}",
            target_type="incident",
            target_id=incident_id,
            detail={"from": ev.get("from_value"), "to": ev.get("to_value")},
        )

    await db.commit()
    return await _fetch_incident(db, incident_id) or current
