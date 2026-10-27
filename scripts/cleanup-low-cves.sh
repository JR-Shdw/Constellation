#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
# cleanup-low-cves.sh — Purge noise CVEs from the database
#
# Noise = LOW severity + will_not_fix + not_affected
# These are: backported fixes, disputed CVEs, distro "won't fix" decisions.
#
# Usage:
#   ./scripts/cleanup-low-cves.sh              # dry-run (count only)
#   ./scripts/cleanup-low-cves.sh --apply      # delete noise CVEs
#
# After cleanup, re-run Trivy scans (now filtered to CRITICAL,HIGH,MEDIUM):
#   make collect-trivy

set -euo pipefail

APPLY="${1:-}"

# Find the postgres container
PG_CONTAINER=$(docker ps --format '{{.Names}}' | grep -E 'cmdb.*postgres' | head -1)

if [ -z "$PG_CONTAINER" ]; then
    echo "[ERROR] PostgreSQL container not found (looking for cmdb*postgres*)" >&2
    exit 1
fi

NOISE_FILTER="severity = 'low' OR fix_status IN ('will_not_fix', 'not_affected')"

echo "[cleanup] PostgreSQL container: $PG_CONTAINER"
echo ""

echo "=== Current noise CVE counts ==="
docker exec "$PG_CONTAINER" psql -U cmdb -d cmdb -c "
    SELECT 'cve_host_packages' AS table_name,
           COUNT(*) AS total,
           COUNT(*) FILTER (WHERE $NOISE_FILTER) AS noise,
           ROUND(100.0 * COUNT(*) FILTER (WHERE $NOISE_FILTER) / NULLIF(COUNT(*), 0), 1) AS noise_pct
    FROM cve_host_packages
    UNION ALL
    SELECT 'cve_containers',
           COUNT(*),
           COUNT(*) FILTER (WHERE $NOISE_FILTER),
           ROUND(100.0 * COUNT(*) FILTER (WHERE $NOISE_FILTER) / NULLIF(COUNT(*), 0), 1)
    FROM cve_containers;
"

echo ""
echo "=== Breakdown by category ==="
docker exec "$PG_CONTAINER" psql -U cmdb -d cmdb -c "
    SELECT category, COUNT(*) AS total FROM (
        SELECT CASE
            WHEN fix_status = 'will_not_fix' THEN 'will_not_fix'
            WHEN fix_status = 'not_affected' THEN 'not_affected'
            WHEN severity = 'low' THEN 'low_severity'
            ELSE 'other'
        END AS category
        FROM cve_host_packages WHERE $NOISE_FILTER
        UNION ALL
        SELECT CASE
            WHEN fix_status = 'will_not_fix' THEN 'will_not_fix'
            WHEN fix_status = 'not_affected' THEN 'not_affected'
            WHEN severity = 'low' THEN 'low_severity'
            ELSE 'other'
        END
        FROM cve_containers WHERE $NOISE_FILTER
    ) t GROUP BY category ORDER BY total DESC;
"

echo ""
echo "=== TOP 10 repeated noise CVEs ==="
docker exec "$PG_CONTAINER" psql -U cmdb -d cmdb -c "
    SELECT cve_id, COUNT(*) AS occurrences, MIN(cvss_score) AS cvss,
           MIN(severity) AS sev, MIN(fix_status) AS fix_status
    FROM (
        SELECT cve_id, cvss_score, severity, fix_status
        FROM cve_host_packages WHERE $NOISE_FILTER
        UNION ALL
        SELECT cve_id, cvss_score, severity, fix_status
        FROM cve_containers WHERE $NOISE_FILTER
    ) all_noise
    GROUP BY cve_id
    ORDER BY occurrences DESC
    LIMIT 10;
"

if [ "$APPLY" != "--apply" ]; then
    echo ""
    echo "[dry-run] No changes made. Run with --apply to delete noise CVEs."
    exit 0
fi

echo ""
echo "=== Deleting noise CVEs ==="

HOST_DEL=$(docker exec "$PG_CONTAINER" psql -U cmdb -d cmdb -t -c \
    "DELETE FROM cve_host_packages WHERE $NOISE_FILTER RETURNING id;" | wc -l)
CTR_DEL=$(docker exec "$PG_CONTAINER" psql -U cmdb -d cmdb -t -c \
    "DELETE FROM cve_containers WHERE $NOISE_FILTER RETURNING id;" | wc -l)

echo "  Deleted $HOST_DEL host package CVEs"
echo "  Deleted $CTR_DEL container CVEs"

echo ""
echo "=== After cleanup ==="
docker exec "$PG_CONTAINER" psql -U cmdb -d cmdb -c "
    SELECT 'cve_host_packages' AS table_name, COUNT(*) AS remaining FROM cve_host_packages
    UNION ALL
    SELECT 'cve_containers', COUNT(*) FROM cve_containers;
"

echo ""
echo "[done] Noise CVEs purged. Re-run Trivy scans to repopulate:"
echo "  make collect-trivy"
