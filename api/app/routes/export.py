# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CSV + PDF export — audit-ready reports for CVEs, nodes, backup, compliance.

No external dependency — uses Python stdlib csv module.
PDF reports are print-ready HTML pages (browser Save as PDF).
All exports respect the same auth + permissions as the read endpoints.
Filename includes ISO date for traceability.
"""

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_permission
from ..database import get_db
from ..utils.sql import where_clause

router = APIRouter(prefix="/api/v1/export", tags=["export"])


# CSV formula injection guard — Excel/LibreOffice treat cells starting with
# these chars as formulas, so a malicious hostname / cve title / note can
# execute HYPERLINK/IMPORTXML/DDE when an admin opens the export.
_CSV_DANGEROUS_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(v):
    """Prefix a leading `'` when a string starts with a formula trigger char."""
    if isinstance(v, str) and v and v.startswith(_CSV_DANGEROUS_PREFIX):
        return "'" + v
    return v


def _csv_response(rows: list[dict], filename: str) -> StreamingResponse:
    """Build a StreamingResponse with CSV content."""
    if not rows:
        buf = io.StringIO("No data\n")
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    safe_rows = [{k: _sanitize_csv_cell(v) for k, v in r.items()} for r in rows]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=safe_rows[0].keys())
    writer.writeheader()
    writer.writerows(safe_rows)

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _datestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


# CVEs


@router.get("/cves")
async def export_cves(
    severity: str | None = None,
    workflow_status: str | None = None,
    environment: str | None = None,
    triage: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Export all CVEs as CSV (no pagination — full dump)."""
    params: dict = {}
    clauses = []
    if severity:
        clauses.append("v.severity = :severity")
        params["severity"] = severity.lower()
    if workflow_status:
        clauses.append("v.workflow_status = :wf_status")
        params["wf_status"] = workflow_status
    if environment:
        clauses.append("v.environment = :env")
        params["env"] = environment
    if triage:
        clauses.append(
            "(v.exploited = true"
            " OR (v.severity = 'critical' AND v.score >= 70)"
            " OR (v.fix_status = 'fixed_available'"
            "     AND v.severity IN ('critical', 'high')))"
        )

    where = where_clause(clauses)

    rows = await db.execute(
        text(f"""
        SELECT v.cve_id, v.severity, v.cvss_score, v.score,
               v.exploited, v.target, v.target_type, v.installed_ver,
               v.fixed_ver, v.fix_status, v.source,
               v.workflow_status, v.justification,
               n.hostname, n.environment, n.os, n.os_version,
               v.detected_at
        FROM v_all_cves v
        JOIN nodes n ON n.id = v.node_id
        {where}
        ORDER BY v.score DESC NULLS LAST, v.cvss_score DESC NULLS LAST
        """),
        params,
    )
    items = [dict(r._mapping) for r in rows]
    return _csv_response(items, f"cmdb-cves-{_datestamp()}.csv")


# Nodes


@router.get("/nodes")
async def export_nodes(
    environment: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Export node inventory as CSV."""
    params: dict = {}
    clauses = []
    if environment:
        clauses.append("n.environment = :env")
        params["env"] = environment

    where = where_clause(clauses)

    rows = await db.execute(
        text(f"""
        SELECT n.hostname, n.type, n.os, n.os_version, n.arch,
               n.kernel, n.environment, n.is_active,
               n.package_count, n.container_count,
               n.cve_package_critical, n.cve_package_count,
               n.cve_container_critical, n.cve_container_count,
               n.last_seen
        FROM v_node_summary n
        {where}
        ORDER BY n.hostname
        """),
        params,
    )
    items = [dict(r._mapping) for r in rows]
    return _csv_response(items, f"cmdb-nodes-{_datestamp()}.csv")


# Backup


@router.get("/backup")
async def export_backup(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("backup", "r")),
):
    """Export backup summary as CSV."""
    rows = await db.execute(
        text("""
        SELECT l.hostname, l.repo_name,
               l.status, l.last_run, l.overdue,
               l.duration_secs, l.size_total, l.snapshots_total,
               s.total_runs, s.success_count, s.failure_count,
               s.success_rate, s.avg_duration_secs
        FROM v_backup_latest l
        LEFT JOIN v_backup_stats_30d s ON s.repo_id = l.repo_id
        ORDER BY l.overdue DESC, l.hostname, l.repo_name
        """)
    )
    items = [dict(r._mapping) for r in rows]
    return _csv_response(items, f"cmdb-backup-{_datestamp()}.csv")


# Compliance


@router.get("/compliance")
async def export_compliance(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("misconf", "r")),
):
    """Export compliance summary as CSV (CVE + misconf + drift per node)."""
    rows = await db.execute(
        text("""
        SELECT * FROM v_compliance_summary
        ORDER BY cve_critical_open DESC, misconf_critical DESC, hostname
        """)
    )
    items = [dict(r._mapping) for r in rows]
    return _csv_response(items, f"cmdb-compliance-{_datestamp()}.csv")


# Audit Log


@router.get("/audit")
async def export_audit(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Export audit log as CSV (default: last 30 days)."""
    rows = await db.execute(
        text("""
        SELECT actor, action, target_type, target_id,
               detail, created_at
        FROM audit_log
        WHERE created_at > NOW() - MAKE_INTERVAL(days => :days)
        ORDER BY created_at DESC
        """),
        {"days": days},
    )
    items = [dict(r._mapping) for r in rows]
    # Stringify detail JSONB for CSV
    for item in items:
        if item.get("detail"):
            import json

            item["detail"] = json.dumps(item["detail"], default=str)
    return _csv_response(items, f"cmdb-audit-{days}d-{_datestamp()}.csv")


# PDF Report (print-ready HTML)


def _html_escape(s):
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_REPORT_CSS = """
body{font-family:sans-serif;font-size:11px;color:#222;margin:24px}
h1{font-size:18px;border-bottom:2px solid #333;padding-bottom:4px}
h2{font-size:14px;margin-top:20px;color:#444}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #ccc;padding:4px 6px;text-align:left}
th{background:#f0f0f0;font-weight:600}
.sev-critical{color:#d32f2f;font-weight:700}
.sev-high{color:#e65100;font-weight:600}
.sev-medium{color:#f9a825}
.sev-low{color:#999}
.meta{color:#666;font-size:10px;margin:4px 0}
@media print{body{margin:12px} @page{size:A4 landscape;margin:12mm}}
"""


@router.get("/report")
async def export_report(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Generate a print-ready audit report (HTML → browser Print → PDF).

    Includes: executive summary, CVE overview, node inventory,
    backup status, compliance scores.
    Open in browser and use Ctrl+P → Save as PDF.
    """
    esc = _html_escape
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Stats
    row = await db.execute(
        text("""
        SELECT
            (SELECT COUNT(*) FROM nodes WHERE is_active) AS nodes,
            (SELECT COUNT(*) FROM containers) AS containers,
            (SELECT COUNT(*) FROM packages) AS packages,
            (SELECT COUNT(*) FROM cve_host_packages) AS host_cves,
            (SELECT COUNT(*) FROM cve_containers) AS ctr_cves,
            (SELECT COUNT(*) FROM cve_host_packages
             WHERE severity = 'critical') AS critical_host,
            (SELECT COUNT(*) FROM cve_containers
             WHERE severity = 'critical') AS critical_ctr
        """)
    )
    stats = row.mappings().first()

    # Top CVEs
    rows = await db.execute(
        text("""
        SELECT v.cve_id, v.severity, v.cvss_score, v.score,
               v.target, v.target_type, n.hostname,
               v.workflow_status, v.fix_status
        FROM v_all_cves v JOIN nodes n ON n.id = v.node_id
        ORDER BY v.score DESC NULLS LAST
        LIMIT 50
        """)
    )
    top_cves = [dict(r._mapping) for r in rows]

    # Nodes summary
    rows = await db.execute(
        text("""
        SELECT hostname, type, os, environment,
               package_count, container_count,
               cve_package_critical, cve_container_critical
        FROM v_node_summary
        ORDER BY cve_package_critical DESC, hostname
        LIMIT 30
        """)
    )
    nodes = [dict(r._mapping) for r in rows]

    # Backup
    rows = await db.execute(
        text("""
        SELECT hostname, repo_name, status, overdue, last_run
        FROM v_backup_latest
        ORDER BY overdue DESC, hostname
        LIMIT 20
        """)
    )
    backups = [dict(r._mapping) for r in rows]

    # Build HTML
    html = f"""<!DOCTYPE html><html><head>
<meta charset="utf-8">
<title>Constellation Audit Report — {esc(now)}</title>
<style>{_REPORT_CSS}</style>
</head><body>
<h1>Constellation — Audit Report</h1>
<p class="meta">Generated: {esc(now)}</p>

<h2>Executive Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Active nodes</td><td>{stats["nodes"]}</td></tr>
<tr><td>Containers</td><td>{stats["containers"]}</td></tr>
<tr><td>Packages tracked</td><td>{stats["packages"]}</td></tr>
<tr><td>Host CVEs</td><td>{stats["host_cves"]}</td></tr>
<tr><td>Container CVEs</td><td>{stats["ctr_cves"]}</td></tr>
<tr><td>Critical (host + container)</td>
    <td class="sev-critical">{stats["critical_host"] + stats["critical_ctr"]}</td></tr>
</table>

<h2>Top CVEs by Risk Score (max 50)</h2>
<table>
<tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Score</th>
<th>Target</th><th>Host</th><th>Status</th><th>Fix</th></tr>
"""
    for c in top_cves:
        sev = c["severity"] or ""
        html += f"""<tr>
<td>{esc(c["cve_id"])}</td>
<td class="sev-{sev}">{esc(sev)}</td>
<td>{c["cvss_score"] or "-"}</td>
<td>{c["score"] or "-"}</td>
<td>{esc(c["target"])}</td>
<td>{esc(c["hostname"])}</td>
<td>{esc(c["workflow_status"] or "open")}</td>
<td>{esc(c["fix_status"] or "-")}</td>
</tr>"""
    html += "</table>"

    html += """<h2>Node Inventory</h2>
<table><tr><th>Host</th><th>Type</th><th>OS</th><th>Env</th>
<th>Pkgs</th><th>Ctrs</th><th>Crit CVE (pkg)</th><th>Crit CVE (ctr)</th></tr>
"""
    for n in nodes:
        html += f"""<tr>
<td>{esc(n["hostname"])}</td><td>{esc(n["type"])}</td>
<td>{esc(n["os"])}</td><td>{esc(n["environment"])}</td>
<td>{n["package_count"]}</td><td>{n["container_count"]}</td>
<td class="sev-critical">{n["cve_package_critical"]}</td>
<td class="sev-critical">{n["cve_container_critical"]}</td>
</tr>"""
    html += "</table>"

    html += """<h2>Backup Status</h2>
<table><tr><th>Host</th><th>Repo</th><th>Status</th>
<th>Overdue</th><th>Last Run</th></tr>
"""
    for b in backups:
        overdue = "YES" if b["overdue"] else "no"
        html += f"""<tr>
<td>{esc(b["hostname"])}</td><td>{esc(b["repo_name"])}</td>
<td>{esc(b["status"])}</td><td>{esc(overdue)}</td>
<td>{esc(str(b["last_run"] or "-"))}</td>
</tr>"""
    html += "</table>"

    html += """
<p class="meta" style="margin-top:24px;border-top:1px solid #ccc;
padding-top:8px">Constellation CAASM — Confidential</p>
</body></html>"""

    return HTMLResponse(content=html)
