#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
# Scan all running Docker containers with Trivy and push CVEs to CMDB
# Usage: sync_trivy.sh
# Cron: 0 */12 * * * /data/container/cmdb/sync_trivy.sh >> /var/log/cmdb-trivy-sync.log 2>&1
#
# Environment:
#   CMDB_API            — CMDB API URL (default: http://10.0.1.1:8000)
#   CMDB_COLLECT_TOKEN  — CMDB Bearer token

set -euo pipefail

CMDB_API="${CMDB_API:-http://10.0.1.1:8000}"
CMDB_TOKEN="${CMDB_COLLECT_TOKEN:-}"
HOSTNAME="$(hostname)"

if [[ -z "$CMDB_TOKEN" ]]; then
  echo "CMDB_COLLECT_TOKEN required" >&2
  exit 1
fi

echo "[$(date -Iseconds)] Trivy scan → CMDB ($HOSTNAME)"

# Check trivy is available
if ! command -v trivy &>/dev/null; then
  echo "trivy not found, skipping" >&2
  exit 1
fi

TOTAL=0

# Scan each running container image
for IMAGE in $(docker ps --format '{{.Image}}' | sort -u); do
  echo "  Scanning $IMAGE..."

  JSON=$(trivy image --format json --quiet --severity "${TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM}" --ignore-unfixed "$IMAGE" 2>/dev/null || true)

  if [[ -z "$JSON" ]] || [[ "$JSON" == "null" ]]; then
    echo "    no results"
    continue
  fi

  # Extract vulnerabilities from trivy JSON
  VULNS=$(echo "$JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
vulns = []
results = data.get('Results', [])
for r in results:
    target = r.get('Target', '')
    for v in r.get('Vulnerabilities', []):
        v['Target'] = target
        vulns.append(v)
json.dump(vulns, sys.stdout)
" 2>/dev/null || echo "[]")

  COUNT=$(echo "$VULNS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

  if [[ "$COUNT" == "0" ]]; then
    echo "    clean"
    continue
  fi

  # Push to CMDB (pass vulns via stdin to avoid ARG_MAX)
  export _SCAN_HOST="$HOSTNAME" _SCAN_IMAGE="$IMAGE"
  PAYLOAD=$(echo "$VULNS" | python3 -c "
import json, os, sys
vulns = json.load(sys.stdin)
payload = {
    'hostname': os.environ['_SCAN_HOST'],
    'source': 'trivy',
    'target_type': 'container',
    'target_name': os.environ['_SCAN_IMAGE'],
    'image': os.environ['_SCAN_IMAGE'],
    'vulnerabilities': vulns
}
print(json.dumps(payload))
" 2>/dev/null) || { echo "    payload build failed"; continue; }

  RESP=$(curl -sf -X POST "$CMDB_API/api/v1/cves/report" \
    -H "Authorization: Bearer $CMDB_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    --max-time 30 2>/dev/null || echo '{"status":"error"}')

  INGESTED=$(echo "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('cves_ingested',0))" 2>/dev/null || echo 0)
  echo "    $INGESTED CVEs pushed"
  TOTAL=$((TOTAL + INGESTED))
done

echo "Done. Total: $TOTAL CVEs"
