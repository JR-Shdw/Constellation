# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import asyncio
import json
import logging

import httpx
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_collect_token, require_permission
from ..config import settings
from ..database import get_db
from ..notify import notify_cve
from ..utils.scoring import rescore_cve
from ..utils.severity import normalize_severity
from ..utils.sql import where_clause

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/opencve", tags=["opencve"])

# Bounded concurrency for rescan's per-CVE OpenCVE fetches. OpenCVE is
# self-hosted (no external rate limit), so a modest cap parallelises the fetch
# fan-out without overwhelming a small instance.
_RESCAN_CONCURRENCY = 8


async def _propagate_kev(cve_id: str, db: AsyncSession) -> None:
    """Set exploited=true + kev=true on cve_catalog for this KEV CVE."""
    result = await db.execute(
        text("""
        UPDATE cve_catalog
        SET exploited = true, kev = true, last_updated = NOW()
        WHERE cve_id = :cve
          AND (exploited IS DISTINCT FROM true
               OR kev IS DISTINCT FROM true)
        """),
        {"cve": cve_id},
    )
    # exploited feeds the materialized score (+25) — re-score this CVE's
    # findings when the flag actually flipped.
    if result.rowcount:
        await rescore_cve(db, cve_id)


@router.post("/webhook")
async def opencve_webhook(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Webhook/polling receiver pour OpenCVE alerts."""
    from .settings import feature_enabled

    if not await feature_enabled("cve", db):
        return {"status": "skipped", "detail": "CVE module disabled"}

    cve_id = payload.get("cve_id", payload.get("id", ""))
    vendor = payload.get("vendor")
    product = payload.get("product")

    # CVSS extraction
    cvss_v3 = None
    metrics = payload.get("metrics", {})
    if isinstance(metrics, dict):
        for v in metrics.values():
            if isinstance(v, list):
                for m in v:
                    if "cvssData" in m:
                        cvss_v3 = m["cvssData"].get("baseScore")
                        break
    if cvss_v3 is None:
        cvss_v3 = payload.get("cvss_v3", payload.get("cvss3"))

    # Severity
    severity = normalize_severity(payload.get("severity"))
    if cvss_v3:
        score = float(cvss_v3)
        if score >= 9.0:
            severity = "critical"
        elif score >= 7.0:
            severity = "high"
        elif score >= 4.0:
            severity = "medium"
        else:
            severity = "low"

    cwe_ids = payload.get("cwe_ids", [])
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]

    kev = bool(payload.get("kev") or payload.get("cisaExploitAdd"))

    await db.execute(
        text("""
        INSERT INTO opencve_alerts
            (cve_id, vendor, product, title, description, cvss_v3,
             severity, cwe_ids, kev, updated_at, raw)
        VALUES (:cve, :vendor, :product, :title, :desc, :cvss,
                :sev, :cwes, :kev, :updated, CAST(:raw AS jsonb))
        ON CONFLICT (cve_id, COALESCE(product, '')) DO UPDATE SET
            cvss_v3     = EXCLUDED.cvss_v3,
            severity    = EXCLUDED.severity,
            description = EXCLUDED.description,
            kev         = EXCLUDED.kev,
            updated_at  = EXCLUDED.updated_at,
            raw         = EXCLUDED.raw
    """),
        {
            "cve": cve_id,
            "vendor": vendor,
            "product": product,
            "title": payload.get("title", payload.get("summary", ""))[:200],
            "desc": payload.get("description", "")[:2000],
            "cvss": cvss_v3,
            "sev": severity,
            "cwes": cwe_ids,
            "kev": kev,
            "updated": payload.get("updated_at"),
            "raw": json.dumps(payload),
        },
    )

    # Upsert cve_catalog with OpenCVE data
    await db.execute(
        text("""
        INSERT INTO cve_catalog (cve_id, cvss_score, description, kev, cwe_ids)
        VALUES (:cve, :cvss, :desc, :kev, :cwes)
        ON CONFLICT (cve_id) DO UPDATE SET
            cvss_score = COALESCE(EXCLUDED.cvss_score, cve_catalog.cvss_score),
            description = COALESCE(EXCLUDED.description, cve_catalog.description),
            kev = EXCLUDED.kev OR cve_catalog.kev,
            cwe_ids = COALESCE(EXCLUDED.cwe_ids, cve_catalog.cwe_ids),
            last_updated = NOW()
        """),
        {
            "cve": cve_id,
            "cvss": cvss_v3,
            "desc": payload.get("description", "")[:2000] or None,
            "kev": kev,
            "cwes": cwe_ids or None,
        },
    )

    # Propagate exploited=true to catalog if KEV
    if kev:
        await _propagate_kev(cve_id, db)

    # cvss_score may have changed above — re-score this CVE's findings.
    # Single-CVE scope + IS DISTINCT FROM guard: no-op when nothing moved.
    await rescore_cve(db, cve_id)

    await db.commit()

    await notify_cve(
        cve_id,
        severity,
        payload.get("title", payload.get("summary", "")),
        "opencve",
        db,
    )

    return {"status": "ok", "cve_id": cve_id}


@router.post("/webhook/batch")
async def opencve_webhook_batch(
    payload: list[dict],
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Batch import d'alertes OpenCVE."""
    count = 0
    kev_cves = []
    for item in payload:
        cve_id = item.get("cve_id", item.get("id", ""))
        if not cve_id:
            continue
        severity = normalize_severity(item.get("severity"))
        cvss_v3 = item.get("cvss_v3", item.get("cvss3"))
        kev = bool(item.get("kev") or item.get("cisaExploitAdd"))
        if kev:
            kev_cves.append(cve_id)

        await db.execute(
            text("""
            INSERT INTO opencve_alerts
                (cve_id, vendor, product, title, description,
                 cvss_v3, severity, kev, raw)
            VALUES (
                :cve, :vendor, :product, :title, :desc,
                :cvss, :sev, :kev, CAST(:raw AS jsonb)
            )
            ON CONFLICT (cve_id, COALESCE(product, '')) DO UPDATE SET
                cvss_v3  = EXCLUDED.cvss_v3,
                severity = EXCLUDED.severity,
                kev      = EXCLUDED.kev OR opencve_alerts.kev,
                raw      = EXCLUDED.raw
        """),
            {
                "cve": cve_id,
                "vendor": item.get("vendor"),
                "product": item.get("product"),
                "title": item.get("title", "")[:200],
                "desc": item.get("description", "")[:2000],
                "cvss": cvss_v3,
                "sev": severity,
                "kev": kev,
                "raw": json.dumps(item),
            },
        )
        count += 1

    # Propagate KEV to findings
    for cve_id in set(kev_cves):
        await _propagate_kev(cve_id, db)

    await db.commit()
    return {"status": "ok", "imported": count, "kev_propagated": len(set(kev_cves))}


@router.get("/alerts")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    matched_only: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Liste les alertes OpenCVE.

    matched_only=true (defaut) : uniquement les CVEs presentes sur l'infra.
    matched_only=false : toutes les alertes OpenCVE.
    """
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    where_clauses = []

    if severity:
        where_clauses.append("oa.severity = :severity")
        params["severity"] = severity.lower()

    # JOIN avec v_all_cves pour ne garder que les CVEs detectees sur l'infra
    matched_join = ""
    matched_select = ""
    if matched_only:
        matched_join = (
            "JOIN (SELECT DISTINCT cve_id FROM v_all_cves) ac ON ac.cve_id = oa.cve_id"
        )
        matched_select = (
            ", (SELECT COUNT(DISTINCT node_id) FROM v_all_cves v"
            " WHERE v.cve_id = oa.cve_id) AS affected_nodes"
        )

    where = where_clause(where_clauses)

    count_result = await db.execute(
        text(f"SELECT COUNT(*) FROM opencve_alerts oa {matched_join} {where}"),
        params,
    )
    total = count_result.scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT oa.id, oa.cve_id, oa.vendor, oa.product, oa.title,
               oa.cvss_v3, oa.severity, oa.created_at
               {matched_select}
        FROM opencve_alerts oa
        {matched_join}
        {where}
        ORDER BY oa.created_at DESC
        LIMIT :limit OFFSET :offset
    """),
        params,
    )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "matched_only": matched_only,
    }


@router.get("/impact")
async def cve_impact(
    cve_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Corrélation : quels assets sont touchés par les alertes OpenCVE."""
    if cve_id:
        rows = await db.execute(
            text("""
            SELECT * FROM v_opencve_impact WHERE cve_id = :cve
            ORDER BY hostname
        """),
            {"cve": cve_id},
        )
    else:
        rows = await db.execute(
            text("""
            SELECT * FROM v_opencve_impact
            ORDER BY alert_date DESC, hostname
            LIMIT 200
        """)
        )
    return {"items": [dict(r._mapping) for r in rows]}


def _extract_cvss(metrics: dict) -> float | None:
    """Extract best CVSS v3 score from OpenCVE v2 metrics."""
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        entry = metrics.get(key, {})
        if isinstance(entry, dict):
            data = entry.get("data", {})
            if isinstance(data, dict) and "score" in data:
                return float(data["score"])
    return None


@router.post("/rescan")
async def rescan_cves(
    payload: dict | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "w")),
):
    """Re-fetch CVE data from OpenCVE API and update local alerts.

    Body (optional):
      cve_ids: list of CVE IDs to rescan. If empty, rescans all open CVEs.
      limit: max CVEs to rescan (default 100).
    """
    if not settings.opencve_url or not settings.opencve_user:
        return {"error": "OpenCVE not configured (set opencve_url + opencve_user)"}

    payload = payload or {}
    cve_ids = payload.get("cve_ids", [])
    max_cves = min(payload.get("limit", 100), 500)

    # If no specific CVEs, get all unique open CVEs from infrastructure
    if not cve_ids:
        rows = await db.execute(
            text("""
                SELECT DISTINCT cve_id FROM (
                    SELECT cve_id FROM cve_host_packages WHERE status = 'open'
                    UNION
                    SELECT cve_id FROM cve_containers WHERE status = 'open'
                ) u LIMIT :lim
            """),
            {"lim": max_cves},
        )
        cve_ids = [r.cve_id for r in rows]

    if not cve_ids:
        return {"status": "ok", "scanned": 0, "message": "no open CVEs to rescan"}

    scanned = 0
    updated = 0
    errors = 0
    kev_propagated = []

    # Phase 1 — fetch every CVE from OpenCVE concurrently (bounded). OpenCVE is
    # self-hosted (no external rate limit), so a serial loop over thousands of
    # open CVEs is needlessly slow. No DB work here, so no transaction is held
    # across the HTTP fan-out.
    sem = asyncio.Semaphore(_RESCAN_CONCURRENCY)

    async def _fetch(client, cve_id):
        async with sem:
            try:
                r = await client.get(f"{settings.opencve_url}/api/cve/{cve_id}")
                if r.status_code != 200:
                    return cve_id, None
                return cve_id, r.json()
            except Exception as e:
                logger.warning("[rescan] %s fetch failed: %s", cve_id, str(e)[:100])
                return cve_id, None

    async with httpx.AsyncClient(
        auth=(settings.opencve_user, settings.opencve_password),
        timeout=15,
    ) as client:
        fetched = await asyncio.gather(*(_fetch(client, c) for c in cve_ids[:max_cves]))

    # Phase 2 — apply each CVE's data in its own short write tx (no network),
    # so one bad CVE can't abort the others and no tx spans an HTTP call.
    for cve_id, data in fetched:
        if data is None:
            errors += 1
            continue
        try:
            scanned += 1
            cvss_v3 = _extract_cvss(data.get("metrics", {}))
            severity = "unknown"
            if cvss_v3:
                if cvss_v3 >= 9.0:
                    severity = "critical"
                elif cvss_v3 >= 7.0:
                    severity = "high"
                elif cvss_v3 >= 4.0:
                    severity = "medium"
                elif cvss_v3 > 0:
                    severity = "low"

            kev = bool(data.get("kev"))
            cwe_ids = [w.get("cwe_id", "") for w in data.get("weaknesses", [])]

            await db.execute(
                text("""
                    INSERT INTO opencve_alerts
                        (cve_id, title, description, cvss_v3,
                         severity, cwe_ids, kev, updated_at, raw)
                    VALUES (:cve, :title, :desc, :cvss,
                            :sev, :cwes, :kev, NOW(), CAST(:raw AS jsonb))
                    ON CONFLICT (cve_id, COALESCE(product, '')) DO UPDATE SET
                        cvss_v3     = EXCLUDED.cvss_v3,
                        severity    = EXCLUDED.severity,
                        kev         = EXCLUDED.kev OR opencve_alerts.kev,
                        updated_at  = NOW(),
                        raw         = EXCLUDED.raw
                """),
                {
                    "cve": cve_id,
                    "title": data.get("title", data.get("description", ""))[:200],
                    "desc": data.get("description", "")[:2000],
                    "cvss": cvss_v3,
                    "sev": severity,
                    "cwes": cwe_ids,
                    "kev": kev,
                    "raw": json.dumps(data),
                },
            )

            # Update cve_catalog with latest NVD data
            if severity != "unknown":
                cat_upd = await db.execute(
                    text("""
                        UPDATE cve_catalog
                        SET cvss_score = COALESCE(:cvss, cvss_score),
                            last_updated = NOW()
                        WHERE cve_id = :cve
                          AND cvss_score IS DISTINCT FROM :cvss
                    """),
                    {"cve": cve_id, "cvss": cvss_v3},
                )
                # cvss feeds the materialized score — re-score on change
                if cat_upd.rowcount:
                    await rescore_cve(db, cve_id)

            if kev:
                await _propagate_kev(cve_id, db)
                kev_propagated.append(cve_id)

            # Per-CVE commit — short write tx, no network inside it.
            await db.commit()
            updated += 1

        except Exception as e:
            await db.rollback()
            logger.warning("[rescan] %s write failed: %s", cve_id, str(e)[:100])
            errors += 1

    logger.info("[rescan] %d scanned, %d updated, %d errors", scanned, updated, errors)
    return {
        "status": "ok",
        "scanned": scanned,
        "updated": updated,
        "errors": errors,
        "kev_propagated": len(kev_propagated),
    }


@router.get("/subscriptions")
async def list_subscriptions(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    rows = await db.execute(
        text("SELECT * FROM opencve_subscriptions ORDER BY vendor, product")
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.post("/subscriptions")
async def add_subscription(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "w")),
):
    await db.execute(
        text("""
        INSERT INTO opencve_subscriptions (vendor, product)
        VALUES (:vendor, :product)
        ON CONFLICT (vendor, product) DO NOTHING
    """),
        {"vendor": payload["vendor"], "product": payload["product"]},
    )
    await db.commit()
    return {"status": "ok"}
