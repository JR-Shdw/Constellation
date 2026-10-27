#!/usr/bin/env bash
# Stress le CMDB local iso-prod en parallele + dump pool toutes les 5s.
# Pas de dependances : curl + bash uniquement.
set -uo pipefail

API="${CMDB_API:-http://127.0.0.1:8000}"
TOKEN="${API_SECRET_KEY:-local_secret_key_for_iso_prod_testing_only_change_me_if_needed}"
CONCURRENCY="${CONCURRENCY:-10}"
SNAPSHOT_INTERVAL="${SNAPSHOT_INTERVAL:-5}"

ENDPOINTS=(
  "/api/v1/stats"
  "/api/v1/stats/trends?days=30"
  "/api/v1/heartbeat/status"
  "/api/v1/heartbeat/trends?hours=24"
  "/api/v1/cves?page=1&per_page=50"
  "/api/v1/deployments/stats"
  "/api/v1/scan/status"
  "/api/v1/exposure"
  "/api/v1/compliance"
  "/api/v1/cicd/stats"
  "/api/v1/automation/policies"
  "/api/v1/scheduler/jobs"
)

cleanup() {
  echo
  echo "Stopping..."
  pkill -P $$ 2>/dev/null
  exit 0
}
trap cleanup INT TERM

# Worker - hammers endpoints in a loop.
hammer() {
  local idx="$1"
  local i="$idx"
  while true; do
    ep="${ENDPOINTS[$((i % ${#ENDPOINTS[@]}))]}"
    curl -s -o /dev/null -m 15 \
      -H "Authorization: Bearer $TOKEN" \
      "$API$ep" 2>/dev/null || true
    i=$((i + 1))
    sleep 0.1
  done
}

# Heartbeat /check loop - slowest endpoint, big leak risk.
hb_loop() {
  while true; do
    curl -s -o /dev/null -m 60 -X POST \
      -H "Authorization: Bearer $TOKEN" \
      "$API/api/v1/heartbeat/check" 2>/dev/null || true
    sleep 15
  done
}

# Snapshot loop - prints pool state every SNAPSHOT_INTERVAL.
snapshot() {
  local started=$SECONDS
  while true; do
    sleep "$SNAPSHOT_INTERVAL"
    pool=$(curl -s -m 5 "$API/api/v1/health/pool" 2>/dev/null || echo '{"error":"timeout"}')
    elapsed=$((SECONDS - started))
    printf "[%5ds] %s\n" "$elapsed" "$pool"
  done
}

echo "Stressing $API with $CONCURRENCY workers + 1 heartbeat loop..."
echo "Pool snapshot every ${SNAPSHOT_INTERVAL}s. Ctrl-C to stop."
echo

for i in $(seq 1 "$CONCURRENCY"); do
  hammer "$i" &
done
hb_loop &
snapshot &

wait
