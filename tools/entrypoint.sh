#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
set -e

INTERVAL="${SYNC_INTERVAL_SECONDS:-3600}"

# Derive trigger filename from the .py script in the command
TRIGGER_NAME=""
for arg in "$@"; do
  case "$arg" in
    *.py) TRIGGER_NAME=$(basename "$arg" .py);;
  esac
done
TRIGGER_FILE="/triggers/${TRIGGER_NAME:-sync}.trigger"
RESULT_FILE="/triggers/${TRIGGER_NAME:-sync}.result"

API_URL="${CMDB_API:-http://api:8000}"

echo "[sync] Starting loop: $* every ${INTERVAL}s"
echo "[sync] Trigger file: $TRIGGER_FILE"

wait_for_api() {
  retries=0
  max_retries=30
  while [ "$retries" -lt "$max_retries" ]; do
    if python3 -c "
import urllib.request, sys
try:
    urllib.request.urlopen('${API_URL}/api/v1/health', timeout=5)
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
      return 0
    fi
    retries=$((retries + 1))
    echo "[sync] Waiting for API... (${retries}/${max_retries})"
    sleep 5
  done
  echo "[sync] ERROR: API not reachable after ${max_retries} attempts"
  return 1
}

while true; do
  EXTRA=""
  if [ -f "$TRIGGER_FILE" ]; then
    EXTRA=$(cat "$TRIGGER_FILE" 2>/dev/null || true)
    rm -f "$TRIGGER_FILE"
    echo "[sync] $(date -Iseconds) TRIGGERED${EXTRA:+: $EXTRA}"
  else
    echo "[sync] $(date -Iseconds) Scheduled run"
  fi

  # Wait for API before running
  if ! wait_for_api; then
    echo "error:api_unreachable" > "$RESULT_FILE"
    echo "[sync] WARNING: skipping run — API unreachable"
    sleep "$INTERVAL"
    continue
  fi

  # Run with extra args appended (argparse last-value-wins)
  # shellcheck disable=SC2086
  if "$@" $EXTRA; then
    echo "ok" > "$RESULT_FILE"
  else
    CODE=$?
    echo "error:$CODE" > "$RESULT_FILE"
    echo "[sync] WARNING: exit code $CODE"
  fi

  # Interruptible sleep — check trigger every 5s
  elapsed=0
  while [ "$elapsed" -lt "$INTERVAL" ]; do
    [ -f "$TRIGGER_FILE" ] && break
    sleep 5
    elapsed=$((elapsed + 5))
  done
done
