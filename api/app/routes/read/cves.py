# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...audit import log_action, validate_uuid
from ...auth import require_permission
from ...config import settings
from ...database import get_db
from ...models.schemas import WorkflowPatch
from ...utils.score import compute_score
from ...utils.sql import where_clause
from . import _composite_key, _get_cache, _set_cache, router


async def _cached_count(db: AsyncSession, sql: str, params: dict, key: str) -> int:
    """COUNT(*) total cached under a page-independent key.

    The total is identical for every page of a given filter set, so paging
    1->2->3 must not rerun the O(N) count. Shares the "cves" TTL.
    """
    cached = _get_cache(key)
    if cached is not None:
        return cached
    total = (await db.execute(text(sql), params)).scalar_one()
    _set_cache(key, total)
    return total


@router.put("/cves/{cve_id}/workflow")
async def set_cve_workflow(
    cve_id: str,
    patch: WorkflowPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("read", "w")),
):
    """Set workflow status for a CVE on a specific node."""
    validate_uuid(patch.node_id, "node_id")
    valid = (
        "open",
        "acknowledged",
        "in_progress",
        "mitigated",
        "resolved",
        "false_positive",
        "accepted_risk",
    )
    if patch.status not in valid:
        return {"error": f"status must be one of {valid}"}
    await db.execute(
        text("""
        INSERT INTO cve_status (node_id, cve_id, status, note, justification)
        VALUES (CAST(:nid AS uuid), :cve, :status, :note, :justification)
        ON CONFLICT (node_id, cve_id) DO UPDATE SET
            status = EXCLUDED.status,
            note = EXCLUDED.note,
            justification = EXCLUDED.justification,
            updated_at = NOW()
        """),
        {
            "nid": patch.node_id,
            "cve": cve_id,
            "status": patch.status,
            "note": patch.note,
            "justification": patch.justification,
        },
    )

    # Propagate workflow decision to the scan tables so the UI reflects it
    # immediately, without waiting for the next Trivy/Wazuh rescan (and for
    # CVEs on removed images/packages, no rescan will ever come).
    scan_status = {
        "mitigated": "mitigated",
        "resolved": "resolved",
        "false_positive": "ignored",
        "accepted_risk": "ignored",
    }.get(patch.status, "open")
    for table in ("cve_host_packages", "cve_containers"):
        await db.execute(
            text(f"""
            UPDATE {table}
            SET status = :scan_status
            WHERE node_id = CAST(:nid AS uuid) AND cve_id = :cve
            """),
            {
                "scan_status": scan_status,
                "nid": patch.node_id,
                "cve": cve_id,
            },
        )

    await log_action(
        db,
        actor=actor,
        action="set_cve_workflow",
        target_type="cve_status",
        target_id=cve_id,
        detail={"node_id": patch.node_id, "status": patch.status},
    )
    await db.commit()

    from . import _cache

    _cache.clear()
    return {"status": "ok"}


@router.get("/cves/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Détail d'une CVE : metadata + liste hôtes/containers/packages affectés."""
    meta = (
        (
            await db.execute(
                text("""
            SELECT cve_id, cvss_score, description,
                   exploited, exploitability_context, kev
            FROM cve_catalog WHERE cve_id = :cve
            """),
                {"cve": cve_id},
            )
        )
        .mappings()
        .first()
    )
    if not meta:
        meta = (
            (
                await db.execute(
                    text("""
                SELECT cve_id, cvss_score, NULL AS description,
                       false AS exploited, 'unclear' AS exploitability_context,
                       false AS kev
                FROM v_all_cves WHERE cve_id = :cve
                LIMIT 1
                """),
                    {"cve": cve_id},
                )
            )
            .mappings()
            .first()
        )
    if not meta:
        return {"error": "not found"}

    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    wf_rows = await db.execute(
        text("""
        SELECT node_id, status AS workflow_status, note, justification
        FROM cve_status WHERE cve_id = :cve
        """),
        {"cve": cve_id},
    )
    wf_map = {str(r.node_id): dict(r._mapping) for r in wf_rows}

    hosts_rows = await db.execute(
        text("""
        SELECT DISTINCT
               hp.id AS finding_id, n.id AS node_id, n.hostname, n.type, n.os,
               hp.pkg_name, hp.installed_ver, hp.fixed_ver, hp.severity,
               hp.fix_status, hp.status
        FROM cve_host_packages hp
        JOIN nodes n ON n.id = hp.node_id
        WHERE hp.cve_id = :cve
        ORDER BY n.hostname, hp.pkg_name
        """),
        {"cve": cve_id},
    )
    hosts = []
    for r in hosts_rows:
        row = dict(r._mapping)
        row["exploited"] = meta.get("exploited") or False
        row["exploitability_context"] = meta.get("exploitability_context") or "unclear"
        row["score"] = compute_score(
            cvss_score=meta["cvss_score"],
            exploited=row["exploited"],
            listen="private_network",
            fix_status=row.get("fix_status") or "unfixed",
            exploitability_context=row["exploitability_context"],
            severity=row.get("severity"),
        )
        wf = wf_map.get(str(row["node_id"]), {})
        row["workflow_status"] = wf.get("workflow_status", "open")
        row["justification"] = wf.get("justification")
        hosts.append(row)

    containers_rows = await db.execute(
        text("""
        SELECT DISTINCT
               cc.id AS finding_id, n.id AS node_id, n.hostname,
               COALESCE(cc.image, cc.target, 'unknown') AS image,
               ct.name AS container_name, cti.tag AS container_tag,
               cc.pkg_name, cc.pkg_type, cc.installed_ver, cc.fixed_ver,
               cc.severity, cc.target,
               cc.fix_status, cc.status,
               COALESCE(r.listen, 'docker_internal') AS listen
        FROM cve_containers cc
        JOIN nodes n ON n.id = cc.node_id
        LEFT JOIN containers ct ON ct.id = cc.container_id
        LEFT JOIN container_images cti ON cti.id = ct.image_id
        LEFT JOIN repositories r
            ON r.image_name = regexp_replace(cc.image, ':[^:]*$', '')
            AND r.node_id = cc.node_id
        WHERE cc.cve_id = :cve
        ORDER BY n.hostname, image, cc.pkg_name
        """),
        {"cve": cve_id},
    )
    containers = []
    for r in containers_rows:
        row = dict(r._mapping)
        row["exploited"] = meta.get("exploited") or False
        row["exploitability_context"] = meta.get("exploitability_context") or "unclear"
        row["score"] = compute_score(
            cvss_score=meta["cvss_score"],
            exploited=row["exploited"],
            listen=row.get("listen") or "docker_internal",
            fix_status=row.get("fix_status") or "unfixed",
            exploitability_context=row["exploitability_context"],
            severity=row.get("severity"),
        )
        wf = wf_map.get(str(row["node_id"]), {})
        row["workflow_status"] = wf.get("workflow_status", "open")
        row["justification"] = wf.get("justification")
        containers.append(row)

    images = list({c["image"] for c in containers if c["image"] != "unknown"})
    image_cves: dict = {}
    if images:
        img_rows = await db.execute(
            text("""
            SELECT COALESCE(cc.image, cc.target, 'unknown') AS image,
                   cc.cve_id, cc.severity, cat.cvss_score,
                   cc.pkg_name, cc.pkg_type, cc.installed_ver, cc.fixed_ver
            FROM cve_containers cc
            JOIN cve_catalog cat ON cat.cve_id = cc.cve_id
            WHERE COALESCE(cc.image, cc.target) = ANY(:imgs)
            ORDER BY cat.cvss_score DESC NULLS LAST, cc.cve_id
            """),
            {"imgs": images},
        )
        for r in img_rows:
            row = dict(r._mapping)
            img = row["image"]
            if img not in image_cves:
                image_cves[img] = []
            image_cves[img].append(row)

    ocve_row = await db.execute(
        text("""
        SELECT kev, cwe_ids, title,
               ARRAY_AGG(DISTINCT vendor) FILTER (WHERE vendor IS NOT NULL) AS vendors,
               ARRAY_AGG(DISTINCT product)
                   FILTER (WHERE product IS NOT NULL) AS products,
               MAX(cvss_v3) AS cvss_v3
        FROM opencve_alerts
        WHERE cve_id = :cve
        GROUP BY kev, cwe_ids, title
        ORDER BY MAX(cvss_v3) DESC NULLS LAST
        LIMIT 1
        """),
        {"cve": cve_id},
    )
    ocve = ocve_row.mappings().first()
    opencve = None
    if ocve:
        opencve = {
            "kev": ocve["kev"] or False,
            "cwe_ids": ocve["cwe_ids"] or [],
            "title": ocve["title"],
            "vendors": ocve["vendors"] or [],
            "products": ocve["products"] or [],
            "cvss_v3": ocve["cvss_v3"],
        }

    opencve_url = settings.opencve_web_url or ""

    sources = []
    hp_src = await db.execute(
        text("""
        SELECT DISTINCT "source" AS src
        FROM cve_host_packages
        WHERE cve_id = :cve AND "source" IS NOT NULL
        """),
        {"cve": cve_id},
    )
    sources.extend(r.src for r in hp_src)
    if containers:
        sources.append("trivy")
    sources = sorted(set(sources))

    worst_sev = "unknown"
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    for h in hosts:
        if sev_order.get(h.get("severity"), 4) < sev_order.get(worst_sev, 4):
            worst_sev = h["severity"]
    for c in containers:
        if sev_order.get(c.get("severity"), 4) < sev_order.get(worst_sev, 4):
            worst_sev = c["severity"]

    return {
        "cve_id": cve_id,
        "severity": worst_sev,
        "cvss_score": meta["cvss_score"],
        "description": meta["description"],
        "exploited": meta.get("exploited") or False,
        "kev": meta.get("kev") or False,
        "nvd_url": nvd_url,
        "opencve": opencve,
        "opencve_url": opencve_url,
        "sources": sources,
        "hosts": hosts,
        "containers": containers,
        "image_cves": image_cves,
    }


@router.get("/cves")
async def list_cves(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    target_type: str | None = None,
    source: str | None = None,
    search: str | None = None,
    node_id: str | None = None,
    hostname: str | None = None,
    exploited: bool | None = None,
    environment: str | None = None,
    workflow_status: str | None = None,
    sort: str = Query("cvss", pattern="^(cvss|severity|detected_at|score|exploited)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    triage: bool = Query(False),
    group_by: str | None = Query(None, pattern="^(package|remediation)$"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    from ..settings import feature_enabled

    if not await feature_enabled("cve", db):
        return {"items": [], "total": 0, "page": page, "per_page": per_page}

    cache_key = _composite_key(
        "cves",
        page=page,
        per_page=per_page,
        severity=severity,
        target_type=target_type,
        source=source,
        search=search,
        node_id=node_id,
        hostname=hostname,
        exploited=exploited,
        environment=environment,
        workflow_status=workflow_status,
        sort=sort,
        order=order,
        triage=triage,
        group_by=group_by,
    )
    cached = _get_cache(cache_key)
    if cached:
        return cached

    # Count depends on the filter set + grouping, not on page/per_page/sort.
    count_key = _composite_key(
        "cves",
        kind="count",
        severity=severity,
        target_type=target_type,
        source=source,
        search=search,
        node_id=node_id,
        hostname=hostname,
        exploited=exploited,
        environment=environment,
        workflow_status=workflow_status,
        triage=triage,
        group_by=group_by,
    )

    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if severity:
        clauses.append("v.severity = :severity")
        params["severity"] = severity.lower()
    if target_type:
        clauses.append("v.target_type = :target_type")
        params["target_type"] = target_type
    if source:
        clauses.append("v.source = :source")
        params["source"] = source
    if search:
        clauses.append(
            "(v.cve_id ILIKE :search OR v.target ILIKE :search"
            " OR n.hostname ILIKE :search)"
        )
        params["search"] = f"%{search}%"
    if node_id:
        clauses.append("v.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if hostname:
        clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    if exploited is not None:
        clauses.append("v.exploited = :exploited")
        params["exploited"] = exploited
    if environment:
        clauses.append("v.environment = :env")
        params["env"] = environment
    if workflow_status:
        clauses.append("v.workflow_status = :wf_status")
        params["wf_status"] = workflow_status

    if triage:
        clauses.append(
            "(v.exploited = true"
            " OR (v.severity = 'critical' AND v.score >= 70)"
            " OR (v.fix_status = 'fixed_available'"
            "     AND v.severity IN ('critical', 'high')))"
        )

    where = where_clause(clauses)

    sort_col = {
        "cvss": "v.cvss_score",
        "severity": "CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
        "detected_at": "v.detected_at",
        "score": "v.score",
        "exploited": "v.exploited",
    }[sort]
    order_dir = "DESC NULLS LAST" if order == "desc" else "ASC NULLS LAST"

    if group_by == "package":
        total = await _cached_count(
            db,
            f"SELECT COUNT(*) FROM ("
            f"  SELECT 1 FROM v_all_cves v"
            f"  JOIN nodes n ON n.id = v.node_id {where}"
            f"  GROUP BY v.target, v.installed_ver) sub",
            params,
            count_key,
        )
        rows = await db.execute(
            text(f"""
            SELECT
                v.target, v.installed_ver,
                COUNT(DISTINCT v.cve_id) AS cve_count,
                COUNT(DISTINCT v.node_id) AS node_count,
                MAX(v.cvss_score) AS max_cvss,
                MAX(v.score) AS max_score,
                BOOL_OR(v.exploited) AS exploited,
                (ARRAY_AGG(v.severity ORDER BY
                    CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END)
                    FILTER (WHERE v.severity IS NOT NULL))[1] AS max_severity,
                ARRAY_AGG(DISTINCT n.hostname ORDER BY n.hostname) AS hostnames,
                ARRAY_AGG(DISTINCT v.cve_id ORDER BY v.cve_id) AS cve_ids
            FROM v_all_cves v
            JOIN nodes n ON n.id = v.node_id
            {where}
            GROUP BY v.target, v.installed_ver
            ORDER BY BOOL_OR(v.exploited) DESC, MAX(v.score) DESC NULLS LAST
            LIMIT :limit OFFSET :offset
            """),
            params,
        )
        result = {
            "items": [dict(r._mapping) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "grouped": "package",
        }
        _set_cache(cache_key, result)
        return result

    if group_by == "remediation":
        total = await _cached_count(
            db,
            f"SELECT COUNT(*) FROM ("
            f"  SELECT 1 FROM v_all_cves v"
            f"  JOIN nodes n ON n.id = v.node_id {where}"
            f"  GROUP BY v.target, v.installed_ver, v.fix_status) sub",
            params,
            count_key,
        )
        rows = await db.execute(
            text(f"""
            SELECT
                v.target, v.installed_ver, v.fix_status,
                MAX(v.fixed_ver) AS fixed_ver,
                COUNT(DISTINCT v.cve_id) AS cve_count,
                COUNT(DISTINCT v.node_id) AS node_count,
                MAX(v.cvss_score) AS max_cvss,
                MAX(v.score) AS max_score,
                BOOL_OR(v.exploited) AS exploited,
                (ARRAY_AGG(v.severity ORDER BY
                    CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END)
                    FILTER (WHERE v.severity IS NOT NULL))[1] AS max_severity,
                ARRAY_AGG(DISTINCT n.hostname ORDER BY n.hostname) AS hostnames,
                ARRAY_AGG(DISTINCT v.cve_id ORDER BY v.cve_id) AS cve_ids
            FROM v_all_cves v
            JOIN nodes n ON n.id = v.node_id
            {where}
            GROUP BY v.target, v.installed_ver, v.fix_status
            ORDER BY BOOL_OR(v.exploited) DESC, MAX(v.score) DESC NULLS LAST
            LIMIT :limit OFFSET :offset
            """),
            params,
        )
        result = {
            "items": [dict(r._mapping) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "grouped": "remediation",
        }
        _set_cache(cache_key, result)
        return result

    total = await _cached_count(
        db,
        f"SELECT COUNT(*) FROM v_all_cves v JOIN nodes n ON n.id = v.node_id {where}",
        params,
        count_key,
    )

    rows = await db.execute(
        text(f"""
        SELECT v.*, n.hostname
        FROM v_all_cves v
        JOIN nodes n ON n.id = v.node_id
        {where}
        ORDER BY {sort_col} {order_dir}
        LIMIT :limit OFFSET :offset
    """),
        params,
    )
    result = {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }
    _set_cache(cache_key, result)
    return result
