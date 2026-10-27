# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Prometheus metrics — OpenMetrics text format for Grafana/Victoria/Zabbix."""

import time

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_permission
from ..database import get_db

router = APIRouter(tags=["metrics"])

# Cache metrics for 30s — avoids hammering PG on every scrape
_metrics_cache: dict = {}
_METRICS_TTL = 30


def _gauge(name: str, help_text: str, value, labels: dict | None = None) -> str:
    """Format a single Prometheus gauge metric."""
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
    if labels:
        lbl = ",".join(f'{k}="{v}"' for k, v in labels.items())
        lines.append(f"{name}{{{lbl}}} {value}")
    else:
        lines.append(f"{name} {value}")
    return "\n".join(lines)


@router.get(
    "/api/v1/metrics",
    response_class=PlainTextResponse,
    tags=["metrics"],
)
async def prometheus_metrics(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Prometheus-compatible metrics endpoint."""
    now = time.monotonic()
    if _metrics_cache.get("ts") and (now - _metrics_cache["ts"]) < _METRICS_TTL:
        return PlainTextResponse(
            _metrics_cache["data"], media_type="text/plain; version=0.0.4"
        )

    blocks: list[str] = []

    # --- Nodes ---
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE is_active) AS active,
            COUNT(*) FILTER (WHERE heartbeat_status = 'up') AS up,
            COUNT(*) FILTER (WHERE heartbeat_status = 'down') AS down
        FROM nodes
        """)
    )
    n = row.mappings().first()
    blocks.append(_gauge("cmdb_nodes_total", "Total registered nodes", n["total"]))
    blocks.append(_gauge("cmdb_nodes_active", "Active nodes", n["active"]))
    blocks.append(
        _gauge(
            "cmdb_nodes_heartbeat",
            "Nodes by heartbeat status",
            n["up"],
            {"status": "up"},
        )
    )
    blocks.append(
        _gauge(
            "cmdb_nodes_heartbeat",
            "Nodes by heartbeat status",
            n["down"],
            {"status": "down"},
        )
    )

    # --- CVEs by severity ---
    for table, prefix in [
        ("cve_host_packages", "cmdb_cves_host"),
        ("cve_containers", "cmdb_cves_container"),
    ]:
        row = await db.execute(
            text(f"""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
                COUNT(*) FILTER (WHERE severity = 'high') AS high,
                COUNT(*) FILTER (WHERE severity = 'medium') AS medium,
                COUNT(*) FILTER (WHERE severity = 'low') AS low
            FROM {table}
            """)
        )
        c = row.mappings().first()
        desc = "host" if "host" in prefix else "container"
        blocks.append(
            _gauge(f"{prefix}_total", f"Total {desc} CVE findings", c["total"])
        )
        for sev in ("critical", "high", "medium", "low"):
            blocks.append(
                _gauge(
                    f"{prefix}_by_severity",
                    f"{desc.title()} CVEs by severity",
                    c[sev],
                    {"severity": sev},
                )
            )

    # --- Containers ---
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE exposure = 'internet') AS internet,
            -- _classify_exposure writes 'vpn' for WireGuard/private exposure
            -- ('wireguard'/'private' are legacy CHECK aliases). Filtering only
            -- 'wireguard' left this gauge permanently zero.
            COUNT(*) FILTER (WHERE exposure IN ('vpn', 'wireguard', 'private'))
                AS private,
            COUNT(*) FILTER (WHERE exposure = 'localhost') AS localhost,
            COUNT(*) FILTER (WHERE exposure = 'docker_internal') AS docker
        FROM containers
        """)
    )
    ct = row.mappings().first()
    blocks.append(_gauge("cmdb_containers_total", "Total containers", ct["total"]))
    for exp, val in [
        ("internet", ct["internet"]),
        ("private_network", ct["private"]),
        ("localhost", ct["localhost"]),
        ("docker_internal", ct["docker"]),
    ]:
        blocks.append(
            _gauge(
                "cmdb_containers_exposure",
                "Containers by network exposure",
                val,
                {"exposure": exp},
            )
        )

    # --- Backups ---
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'success' AND NOT overdue) AS ok,
            COUNT(*) FILTER (WHERE status = 'failure') AS failed,
            COUNT(*) FILTER (WHERE overdue) AS overdue
        FROM v_backup_latest
        """)
    )
    bk = row.mappings().first()
    blocks.append(
        _gauge("cmdb_backup_repos_total", "Total backup repositories", bk["total"])
    )
    blocks.append(_gauge("cmdb_backup_ok", "Healthy backups", bk["ok"]))
    blocks.append(_gauge("cmdb_backup_failed", "Failed backups", bk["failed"]))
    blocks.append(_gauge("cmdb_backup_overdue", "Overdue backups", bk["overdue"]))

    # --- Scan freshness ---
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) FILTER (WHERE last_trivy_host_scan IS NOT NULL) AS scanned,
            COUNT(*) FILTER (WHERE last_trivy_host_scan IS NULL
                OR last_trivy_host_scan < NOW() - INTERVAL '25 hours') AS stale
        FROM v_scan_status
        """)
    )
    sc = row.mappings().first()
    blocks.append(
        _gauge("cmdb_scan_nodes_scanned", "Nodes with recent Trivy scan", sc["scanned"])
    )
    blocks.append(
        _gauge("cmdb_scan_nodes_stale", "Nodes with stale or missing scan", sc["stale"])
    )

    # --- Repositories ---
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE update_available) AS updates
        FROM repositories
        """)
    )
    rp = row.mappings().first()
    blocks.append(
        _gauge("cmdb_repos_total", "Tracked Docker repositories", rp["total"])
    )
    blocks.append(
        _gauge(
            "cmdb_repos_update_available", "Repos with update available", rp["updates"]
        )
    )

    # --- Automation ---
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) FILTER (WHERE status = 'pending') AS pending,
            -- automation_log statuses are completed/failed/… (table CHECK);
            -- 'executed'/'error' are never written, so these gauges were
            -- permanently zero.
            COUNT(*) FILTER (WHERE status = 'completed') AS executed,
            COUNT(*) FILTER (WHERE status = 'failed') AS errors
        FROM automation_log
        WHERE created_at > NOW() - INTERVAL '24 hours'
        """)
    )
    au = row.mappings().first()
    blocks.append(
        _gauge("cmdb_automation_pending", "Pending automation actions", au["pending"])
    )
    blocks.append(
        _gauge(
            "cmdb_automation_24h",
            "Automation executions last 24h",
            au["executed"],
            {"status": "executed"},
        )
    )
    blocks.append(
        _gauge(
            "cmdb_automation_24h",
            "Automation executions last 24h",
            au["errors"],
            {"status": "error"},
        )
    )

    # --- SCA compliance ---
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(passed), 0) AS passed,
            COALESCE(SUM(failed), 0) AS failed
        FROM sca_results
        """)
    )
    sca = row.mappings().first()
    blocks.append(_gauge("cmdb_sca_checks_total", "Total SCA policies", sca["total"]))
    blocks.append(_gauge("cmdb_sca_passed", "Passed SCA checks", sca["passed"]))
    blocks.append(_gauge("cmdb_sca_failed", "Failed SCA checks", sca["failed"]))

    # --- Packages ---
    row = await db.execute(text("SELECT COUNT(*) FROM packages"))
    blocks.append(
        _gauge("cmdb_packages_total", "Total tracked OS packages", row.scalar_one())
    )

    output = "\n\n".join(blocks) + "\n"
    _metrics_cache["data"] = output
    _metrics_cache["ts"] = now

    return PlainTextResponse(output, media_type="text/plain; version=0.0.4")
