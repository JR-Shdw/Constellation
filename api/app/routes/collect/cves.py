# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import json

from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_collect_token
from ...database import get_db
from ...models.schemas import CVEReport
from ...notify import fire_and_forget, notify_cve
from ...utils.scoring import rescore_node
from ...utils.severity import normalize_severity
from ...utils.sql import set_statement_timeout
from ..automation import run_evaluation
from . import _chunks, logger, router


@router.post("/cves/report")
async def cve_report(
    payload: CVEReport,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Endpoint pour Trivy/Wazuh — ingest CVEs."""
    from ..settings import feature_enabled

    await set_statement_timeout(db, "batch")
    if not await feature_enabled("cve", db):
        return {"status": "skipped", "detail": "CVE module disabled"}

    result = await db.execute(
        text("SELECT id FROM nodes WHERE hostname = :h LIMIT 1"),
        {"h": payload.hostname},
    )
    row = result.scalar_one_or_none()
    if not row:
        return {"status": "error", "detail": f"Node {payload.hostname} not found"}
    node_id = str(row)

    scan_col = {
        ("trivy", "package"): "last_trivy_host_scan",
        ("trivy", "container"): "last_trivy_image_scan",
        ("wazuh", "package"): "last_wazuh_scan",
    }.get((payload.source, payload.target_type))
    if scan_col:
        await db.execute(
            text(f"UPDATE nodes SET {scan_col} = NOW() WHERE id = CAST(:nid AS uuid)"),
            {"nid": node_id},
        )

    host_rows = []
    container_rows = []
    catalog_rows = {}

    for vuln in payload.vulnerabilities:
        cve_id = vuln.get("VulnerabilityID", vuln.get("cve_id", ""))
        severity = normalize_severity(vuln.get("Severity", vuln.get("severity")))
        cvss = vuln.get("CVSS", {})
        cvss_score = None
        if isinstance(cvss, dict):
            for src in cvss.values():
                if isinstance(src, dict) and "V3Score" in src:
                    cvss_score = src["V3Score"]
                    break
        if cvss_score is None:
            cvss_score = vuln.get("cvss_score")

        fixed = vuln.get("FixedVersion", vuln.get("fixed_ver"))
        installed = vuln.get("InstalledVersion", vuln.get("installed_ver", ""))
        pkg_name = vuln.get("PkgName", vuln.get("pkg_name", payload.target_name))
        pkg_type = vuln.get("PkgType", vuln.get("pkg_type"))
        description = vuln.get("Description", vuln.get("description", ""))
        secret_type = vuln.get("secret_type")
        secret_match = vuln.get("secret_match")
        layer = vuln.get("Layer", {})
        layer_digest = layer.get("Digest") if isinstance(layer, dict) else None
        target = vuln.get("Target", vuln.get("target"))
        # Trust distro status over upstream FixedVersion — distro can be
        # unaffected/will_not_fix even when upstream has a fix.
        trivy_status = vuln.get("Status", "").lower()
        if trivy_status == "will_not_fix":
            fix_status = "will_not_fix"
        elif trivy_status == "not_affected":
            fix_status = "not_affected"
        elif trivy_status == "fixed":
            fix_status = "fixed_available"
        elif trivy_status == "affected":
            fix_status = "unfixed"
        elif fixed:
            fix_status = "fixed_available"
        else:
            fix_status = "unfixed"

        if cve_id and cve_id not in catalog_rows:
            catalog_rows[cve_id] = {
                "cve": cve_id,
                "cvss": cvss_score,
                "desc": description[:500] if description else None,
            }

        if payload.target_type == "container":
            image_name = payload.image or payload.target_name or None
            container_rows.append(
                {
                    "nid": node_id,
                    "cve": cve_id,
                    "sev": severity,
                    "pkg": pkg_name,
                    "ptype": pkg_type,
                    "installed": installed,
                    "fixed": fixed,
                    "image": image_name,
                    "fix_status": fix_status,
                    "secret_type": secret_type,
                    "secret_match": secret_match,
                    "layer": layer_digest,
                    "target": target,
                    "raw": json.dumps(vuln),
                }
            )
        else:
            host_rows.append(
                {
                    "nid": node_id,
                    "cve": cve_id,
                    "sev": severity,
                    "pkg": pkg_name,
                    "installed": installed,
                    "fixed": fixed,
                    "source": payload.source,
                    "fix_status": fix_status,
                    "raw": json.dumps(vuln),
                }
            )

    seen_host = {}
    for r in host_rows:
        key = (r["nid"], r["cve"], r["pkg"])
        seen_host[key] = r
    host_rows = list(seen_host.values())

    seen_ctr = {}
    for r in container_rows:
        key = (r["nid"], r["cve"], r["pkg"], r.get("image"))
        seen_ctr[key] = r
    container_rows = list(seen_ctr.values())

    for batch in _chunks(list(catalog_rows.values()), 200):
        values = ", ".join(
            f"(:cve_{i}, :cvss_{i}, :desc_{i})" for i in range(len(batch))
        )
        params = {}
        for i, r in enumerate(batch):
            params.update(
                {
                    f"cve_{i}": r["cve"],
                    f"cvss_{i}": r["cvss"],
                    f"desc_{i}": r["desc"],
                }
            )
        await db.execute(
            text(f"""
            INSERT INTO cve_catalog (cve_id, cvss_score, description)
            VALUES {values}
            ON CONFLICT (cve_id) DO UPDATE SET
                cvss_score  = COALESCE(EXCLUDED.cvss_score, cve_catalog.cvss_score),
                description = COALESCE(EXCLUDED.description, cve_catalog.description),
                last_updated = NOW()
            """),
            params,
        )

    for batch in _chunks(host_rows, 200):
        values = ", ".join(
            f"(:nid_{i}, :cve_{i}, :sev_{i}, :pkg_{i},"
            f" :inst_{i}, :fix_{i}, :src_{i},"
            f" :fs_{i}, CAST(:raw_{i} AS jsonb))"
            for i in range(len(batch))
        )
        params = {}
        for i, r in enumerate(batch):
            params.update(
                {
                    f"nid_{i}": r["nid"],
                    f"cve_{i}": r["cve"],
                    f"sev_{i}": r["sev"],
                    f"pkg_{i}": r["pkg"],
                    f"inst_{i}": r["installed"],
                    f"fix_{i}": r["fixed"],
                    f"src_{i}": r["source"],
                    f"fs_{i}": r["fix_status"],
                    f"raw_{i}": r["raw"],
                }
            )
        await db.execute(
            text(f"""
            INSERT INTO cve_host_packages
                (node_id, cve_id, severity, pkg_name,
                 installed_ver, fixed_ver, source,
                 fix_status, raw)
            VALUES {values}
            ON CONFLICT (node_id, cve_id, pkg_name) DO UPDATE SET
                severity      = EXCLUDED.severity,
                fixed_ver     = EXCLUDED.fixed_ver,
                installed_ver = EXCLUDED.installed_ver,
                fix_status    = CASE
                    WHEN cve_host_packages.fix_status
                        IN ('unfixed', 'fixed_available')
                    THEN EXCLUDED.fix_status
                    ELSE cve_host_packages.fix_status
                END,
                scanned_at    = NOW()
            """),
            params,
        )

    for batch in _chunks(container_rows, 200):
        values = ", ".join(
            f"(:nid_{i}, :cve_{i}, :sev_{i},"
            f" :pkg_{i}, :pt_{i}, :inst_{i}, :fix_{i},"
            f" :img_{i}, :fs_{i},"
            f" :st_{i}, :sm_{i}, :lay_{i}, :tgt_{i},"
            f" CAST(:raw_{i} AS jsonb))"
            for i in range(len(batch))
        )
        params = {}
        for i, r in enumerate(batch):
            params.update(
                {
                    f"nid_{i}": r["nid"],
                    f"cve_{i}": r["cve"],
                    f"sev_{i}": r["sev"],
                    f"pkg_{i}": r["pkg"],
                    f"pt_{i}": r["ptype"],
                    f"inst_{i}": r["installed"],
                    f"fix_{i}": r["fixed"],
                    f"img_{i}": r["image"],
                    f"fs_{i}": r["fix_status"],
                    f"st_{i}": r["secret_type"],
                    f"sm_{i}": r["secret_match"],
                    f"lay_{i}": r["layer"],
                    f"tgt_{i}": r["target"],
                    f"raw_{i}": r["raw"],
                }
            )
        await db.execute(
            text(f"""
            INSERT INTO cve_containers
                (node_id, cve_id, severity, pkg_name,
                 pkg_type, installed_ver, fixed_ver,
                 image, fix_status, secret_type, secret_match,
                 layer_digest, target, raw)
            VALUES {values}
            ON CONFLICT (node_id, cve_id, pkg_name, COALESCE(image, ''),
                COALESCE(container_id, '00000000-0000-0000-0000-000000000000'::uuid))
            DO UPDATE SET
                severity      = EXCLUDED.severity,
                fixed_ver     = EXCLUDED.fixed_ver,
                installed_ver = EXCLUDED.installed_ver,
                fix_status    = CASE
                    WHEN cve_containers.fix_status
                        IN ('unfixed', 'fixed_available')
                    THEN EXCLUDED.fix_status
                    ELSE cve_containers.fix_status
                END,
                scanned_at    = NOW()
            """),
            params,
        )

    # Materialized score: one set-based pass over this node's findings,
    # same transaction as the upserts (catalog rows already visible).
    # Rows whose score is unchanged are skipped (IS DISTINCT FROM).
    if host_rows or container_rows:
        await rescore_node(db, node_id)

    # Each Trivy scan is a complete snapshot. Delete stale CVEs still in
    # 'open' — preserve user decisions (mitigated/ignored/resolved).
    if payload.target_type == "package" and host_rows:
        stale_host = await db.execute(
            text("""
            DELETE FROM cve_host_packages
            WHERE node_id = CAST(:nid AS uuid)
              AND source = :src
              AND scanned_at < NOW() - INTERVAL '5 minutes'
              AND status = 'open'
            """),
            {"nid": node_id, "src": payload.source},
        )
        if stale_host.rowcount:
            logger.info(
                "[collect] cleaned %d stale host CVEs for %s",
                stale_host.rowcount,
                payload.hostname,
            )
    elif payload.target_type == "container" and container_rows:
        image_name = payload.image or payload.target_name
        if image_name:
            stale_ctr = await db.execute(
                text("""
                DELETE FROM cve_containers
                WHERE node_id = CAST(:nid AS uuid)
                  AND image = :img
                  AND scanned_at < NOW() - INTERVAL '5 minutes'
                  AND status = 'open'
                """),
                {"nid": node_id, "img": image_name},
            )
            if stale_ctr.rowcount:
                logger.info(
                    "[collect] cleaned %d stale container CVEs for %s/%s",
                    stale_ctr.rowcount,
                    payload.hostname,
                    image_name,
                )

    # Sync user workflow decisions back to findings — prevents reimports
    # from reverting user-decided CVEs to 'open'.
    if node_id:
        sync_host = await db.execute(
            text("""
            UPDATE cve_host_packages hp
            SET status = CASE cs.status
                WHEN 'mitigated' THEN 'mitigated'
                WHEN 'resolved' THEN 'resolved'
                WHEN 'false_positive' THEN 'ignored'
                WHEN 'accepted_risk' THEN 'ignored'
            END
            FROM cve_status cs
            WHERE cs.node_id = hp.node_id
              AND cs.cve_id = hp.cve_id
              AND cs.status IN (
                  'mitigated','resolved','false_positive','accepted_risk'
              )
              AND hp.status = 'open'
              AND hp.node_id = CAST(:nid AS uuid)
            """),
            {"nid": node_id},
        )
        sync_ctr = await db.execute(
            text("""
            UPDATE cve_containers cc
            SET status = CASE cs.status
                WHEN 'mitigated' THEN 'mitigated'
                WHEN 'resolved' THEN 'resolved'
                WHEN 'false_positive' THEN 'ignored'
                WHEN 'accepted_risk' THEN 'ignored'
            END
            FROM cve_status cs
            WHERE cs.node_id = cc.node_id
              AND cs.cve_id = cc.cve_id
              AND cs.status IN (
                  'mitigated','resolved','false_positive','accepted_risk'
              )
              AND cc.status = 'open'
              AND cc.node_id = CAST(:nid AS uuid)
            """),
            {"nid": node_id},
        )
        synced = (sync_host.rowcount or 0) + (sync_ctr.rowcount or 0)
        if synced:
            logger.info(
                "[collect] synced %d CVE workflow statuses for %s",
                synced,
                payload.hostname,
            )

    await db.commit()

    # Fire CVE notifications as detached background tasks. Each notify_cve
    # opens its own DB session, so the ingestion handler doesn't keep its
    # pool slot tied up for the duration of N Matrix/SMTP/webhook calls.
    # Without this, a 100-CVE Wazuh payload could keep one connection
    # checked-out for 5-10 min after the client (sync_wazuh) had already
    # closed its socket — that's what caused heartbeat-check timeouts ~10
    # min after the ingest "looked done".
    seen_cve_events = set()
    for vuln in payload.vulnerabilities:
        cve_id = vuln.get("VulnerabilityID", vuln.get("cve_id", ""))
        sev = normalize_severity(vuln.get("Severity", vuln.get("severity")))
        desc = vuln.get("Description", vuln.get("description", ""))
        pkg = vuln.get("PkgName", vuln.get("pkg_name", ""))
        target = vuln.get("Target", vuln.get("target", payload.target_name)) or ""
        fire_and_forget(
            notify_cve(
                cve_id,
                sev,
                f"{pkg} on {payload.hostname}: {desc[:120]}",
                payload.source,
                node_id=node_id,
                target_name=target,
            )
        )

        if sev in ("critical", "high") and cve_id not in seen_cve_events:
            seen_cve_events.add(cve_id)
            try:
                await run_evaluation(
                    {
                        "trigger_type": "cve_detected",
                        "hostname": payload.hostname,
                        "cve_id": cve_id,
                        "severity": sev,
                        "package": pkg,
                        "image": (
                            payload.image
                            if payload.target_type == "container"
                            else None
                        ),
                        "container": (
                            target if payload.target_type == "container" else None
                        ),
                    },
                    db,
                )
            except Exception as e:
                logger.warning("[collect] automation eval failed for %s: %s", cve_id, e)

    await db.commit()

    return {
        "status": "ok",
        "node_id": node_id,
        "cves_ingested": len(payload.vulnerabilities),
    }
