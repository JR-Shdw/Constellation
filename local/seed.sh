#!/usr/bin/env bash
# Seed le CMDB local iso-prod via curl (pas de dependence Python).
set -euo pipefail

API="${CMDB_API:-http://127.0.0.1:8000}"
TOKEN="${API_SECRET_KEY:-local_secret_key_for_iso_prod_testing_only_change_me_if_needed}"
COLLECT="${COLLECT_TOKEN:-local_collect_token_iso_prod_testing_only_change_me_if_needed}"

post_collect() {
  curl -fsS -X POST "$API/api/v1/$1" \
    -H "Authorization: Bearer $COLLECT" \
    -H "Content-Type: application/json" \
    -d "$2" > /dev/null
}

post_admin() {
  curl -fsS -X POST "$API/api/v1/$1" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$2" > /dev/null
}

echo "Seeding 10 nodes (50 packages each)..."
for i in $(seq 0 9); do
  hostname=$(printf "local-node-%02d" "$i")
  ip="10.99.0.$((i + 10))"
  payload=$(python3 -c "
import json
print(json.dumps({
  'hostname': '$hostname',
  'type': 'vm',
  'os': 'debian',
  'os_version': '12',
  'arch': 'x86_64',
  'kernel': '6.1.0',
  'ip_address': '$ip',
  'packages': [f'pkg-{j:03d}=1.{j}.0' for j in range(50)],
  'containers': [],
}))
")
  post_collect "nodes/report" "$payload"
done
echo "  done."

echo "Seeding host CVEs (5 per node)..."
for i in $(seq 0 9); do
  hostname=$(printf "local-node-%02d" "$i")
  payload=$(NODE_IDX="$i" HOSTNAME_VAL="$hostname" python3 -c "
import json, os
i = int(os.environ['NODE_IDX'])
hostname = os.environ['HOSTNAME_VAL']
vulns = []
for j in range(5):
  cve_id = f'CVE-2025-{1000 + i*5 + j}'
  vulns.append({
    'cve_id': cve_id,
    'package_name': f'pkg-{j:03d}',
    'installed_version': f'1.{j}.0',
    'fixed_version': f'1.{j}.1',
    'severity': ['critical','high','medium','low'][j % 4],
    'cvss_score': 7.5,
  })
print(json.dumps({
  'hostname': hostname,
  'source': 'trivy',
  'target_type': 'package',
  'target_name': '',
  'vulnerabilities': vulns,
}))
")
  post_collect "cves/report" "$payload"
done
echo "  done."

echo "Seeding 5 scheduler jobs (cron */1 → /api/v1/health)..."
for i in 0 1 2 3 4; do
  payload=$(cat <<EOF
{"name":"local-stress-job-$i","job_type":"http_request","cron_expr":"*/1 * * * *","config":{"method":"GET","url":"/api/v1/health","expected_status":[200]},"enabled":true,"timeout_secs":30}
EOF
)
  if ! post_admin "scheduler/jobs" "$payload" 2>/dev/null; then
    echo "  job local-stress-job-$i: already exists or rejected"
  fi
done
echo "  done."

echo
echo "Seed complete. Now run: bash local/stress.sh"
