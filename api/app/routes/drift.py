# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Drift detection — ingest + read + patch."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_collect_token, require_permission
from ..database import get_db
from ..utils.severity import normalize_severity
from ..utils.sql import set_statement_timeout, where_clause
from .automation import run_evaluation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/drift", tags=["drift"])

_VALID_TYPES = ("file", "package", "service", "config", "user", "permission")
_VALID_STATUSES = ("open", "acknowledged", "resolved", "accepted")


@router.post("/report")
async def drift_report(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Ingest drift detection results (Ansible --check --diff)."""
    await set_statement_timeout(db, "batch")
    hostname = payload.get("hostname", "")
    source = payload.get("source", "ansible")
    raw_items = payload.get("items", [])

    # Normalize items: Ansible Jinja2 may send dicts as JSON strings
    items = []
    for raw in raw_items:
        if isinstance(raw, dict):
            items.append(raw)
        elif isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    items.append(parsed)
            except (json.JSONDecodeError, TypeError):
                continue

    node_row = await db.execute(
        text("SELECT id FROM nodes WHERE hostname = :h LIMIT 1"),
        {"h": hostname},
    )
    node_id = node_row.scalar_one_or_none()
    if not node_id:
        return {"status": "error", "detail": f"Node {hostname} not found"}
    node_id = str(node_id)

    inserted = 0
    for item in items:
        drift_type = item.get("drift_type", "config")
        if drift_type not in _VALID_TYPES:
            drift_type = "config"
        resource_name = item.get("resource_name", "")
        if not resource_name:
            continue
        severity = normalize_severity(
            item.get("severity"), allow_unknown=False, fallback="medium"
        )

        await db.execute(
            text("""
            INSERT INTO drift_reports
                (node_id, drift_type, resource_name, expected, actual,
                 severity, source)
            VALUES
                (CAST(:nid AS uuid), :dtype, :resource, :expected, :actual,
                 :severity, :source)
            ON CONFLICT (node_id, drift_type, resource_name) DO UPDATE SET
                expected = EXCLUDED.expected,
                actual = EXCLUDED.actual,
                severity = EXCLUDED.severity,
                status = 'open',
                detected_at = NOW(),
                resolved_at = NULL
            """),
            {
                "nid": node_id,
                "dtype": drift_type,
                "resource": resource_name[:300],
                "expected": (item.get("expected") or "")[:1000],
                "actual": (item.get("actual") or "")[:1000],
                "severity": severity,
                "source": source,
            },
        )
        inserted += 1

    await db.commit()

    # Fire automation for critical/high drift
    high_count = sum(
        1
        for item in items
        if normalize_severity(item.get("severity")) in ("critical", "high")
    )
    if high_count > 0:
        try:
            await run_evaluation(
                {
                    "trigger_type": "drift_detected",
                    "hostname": hostname,
                    "severity": "critical"
                    if any(
                        normalize_severity(item.get("severity")) == "critical"
                        for item in items
                    )
                    else "high",
                },
                db,
            )
            await db.commit()
        except Exception as e:
            logger.warning("[drift] automation eval failed: %s", e)

    return {"status": "ok", "node_id": node_id, "inserted": inserted}


@router.get("")
async def list_drift(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    status: str | None = None,
    drift_type: str | None = None,
    node_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """List drift reports, paginated with filters."""
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if severity:
        clauses.append("d.severity = :sev")
        params["sev"] = severity
    if status:
        clauses.append("d.status = :status")
        params["status"] = status
    if drift_type:
        clauses.append("d.drift_type = :dtype")
        params["dtype"] = drift_type
    if node_id:
        clauses.append("d.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id

    where = where_clause(clauses)

    count_result = await db.execute(
        text(
            f"SELECT COUNT(*) FROM drift_reports d"
            f" JOIN nodes n ON n.id = d.node_id {where}"
        ),
        params,
    )
    total = count_result.scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT d.*, n.hostname, n.environment
        FROM drift_reports d
        JOIN nodes n ON n.id = d.node_id
        {where}
        ORDER BY
            CASE d.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
            WHEN 'medium' THEN 2 ELSE 3 END,
            d.detected_at DESC
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


@router.patch("/{drift_id}")
async def patch_drift(
    drift_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("read", "w")),
):
    """Update drift report status."""
    validate_uuid(drift_id)
    new_status = payload.get("status", "")
    if new_status not in _VALID_STATUSES:
        raise HTTPException(400, f"status must be one of {_VALID_STATUSES}")

    resolved_at = "NOW()" if new_status == "resolved" else "NULL"
    await db.execute(
        text(
            f"UPDATE drift_reports SET status = :status, resolved_at = {resolved_at}"
            f" WHERE id = CAST(:did AS uuid)"
        ),
        {"did": drift_id, "status": new_status},
    )
    await log_action(
        db,
        actor=actor,
        action="patch_drift",
        target_type="drift",
        target_id=drift_id,
        detail={"status": new_status},
    )
    await db.commit()
    return {"status": "ok"}
