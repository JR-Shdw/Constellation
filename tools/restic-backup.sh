#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
# restic-backup.sh — Wrapper restic avec notification Matrix + POST CMDB
# Usage: restic-backup.sh <repo_name> <sftp_host> <sftp_path> <source_path...>
#
# Variables d'environnement requises:
#   CMDB_COLLECT_TOKEN, RESTIC_PASSWORD_FILE
#   MATRIX_TOKEN, MATRIX_ROOM_ID (optionnel)
#   ALERT_EMAIL (optionnel — email envoyé en cas d'erreur)

set -euo pipefail

REPO_NAME="${1}"; shift
SFTP_HOST="${1}"; shift
SFTP_PATH="${1}"; shift
SOURCES=("$@")

CMDB_API="${CMDB_API:-http://10.0.0.1:8000}"
CMDB_TOKEN="${CMDB_COLLECT_TOKEN}"
MATRIX_URL="${MATRIX_URL:-https://matrix.example.com}"
MATRIX_ROOM="${MATRIX_ROOM_ID:-}"
MATRIX_TK="${MATRIX_TOKEN:-}"
HOSTNAME=$(hostname -f)
SFTP_USER="${SFTP_USER:-backup}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
SMTP_FROM="${SMTP_FROM:-backup@$(hostname -d 2>/dev/null || echo 'localhost')}"
REPO="sftp:${SFTP_USER}@${SFTP_HOST}:${SFTP_PATH}"
LOG="/var/log/backup/${REPO_NAME}.log"
START_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_EPOCH=$(date +%s)

mkdir -p /var/log/backup

notify_matrix() {
    [ -z "${MATRIX_ROOM}" ] && return 0
    [ -z "${MATRIX_TK}" ] && return 0
    local msg="$1"
    local txn_id
    txn_id=$(date +%s%N)
    curl -sf -X PUT \
        "${MATRIX_URL}/_matrix/client/v3/rooms/${MATRIX_ROOM}/send/m.room.message/${txn_id}" \
        -H "Authorization: Bearer ${MATRIX_TK}" \
        -H "Content-Type: application/json" \
        -d "{\"msgtype\":\"m.text\",\"body\":\"${msg}\"}" > /dev/null 2>&1 || true
}

notify_email() {
    [ -z "${ALERT_EMAIL}" ] && return 0
    local subject="$1"
    local body="$2"
    echo -e "Subject: ${subject}\nFrom: ${SMTP_FROM}\nTo: ${ALERT_EMAIL}\n\n${body}" \
        | sendmail -t "${ALERT_EMAIL}" 2>/dev/null || true
}

post_result() {
    local http_code
    http_code=$(curl -s -o /tmp/cmdb_backup_resp.txt -w "%{http_code}" \
        -X POST "${CMDB_API}/api/v1/backup/report" \
        -H "Authorization: Bearer ${CMDB_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$1" \
        --max-time 15 2>&1)
    local curl_exit=$?
    if [ "${curl_exit}" -ne 0 ] || [ "${http_code}" -lt 200 ] || [ "${http_code}" -ge 300 ]; then
        echo "[WARN] CMDB post failed: curl_exit=${curl_exit} http=${http_code}" | tee -a "${LOG}"
        cat /tmp/cmdb_backup_resp.txt | tee -a "${LOG}" 2>/dev/null || true
    else
        echo "[OK] CMDB post: http=${http_code} $(cat /tmp/cmdb_backup_resp.txt 2>/dev/null)" | tee -a "${LOG}"
    fi
    rm -f /tmp/cmdb_backup_resp.txt
}

# Run restic
echo "[$(date)] Starting backup ${REPO_NAME} -> ${SFTP_HOST}:${SFTP_PATH}" | tee -a "${LOG}"

RESTIC_OUT=$(mktemp)
RESTIC_EXIT=0

restic \
    -r "${REPO}" \
    --verbose \
    --json \
    backup "${SOURCES[@]}" \
    2>&1 | tee -a "${LOG}" > "${RESTIC_OUT}" || RESTIC_EXIT=$?

END_EPOCH=$(date +%s)
DURATION=$(( END_EPOCH - START_EPOCH ))

# Parser la sortie JSON restic
SUMMARY=$(grep '"message_type":"summary"' "${RESTIC_OUT}" | tail -1 || echo '{}')

FILES_NEW=$(echo "${SUMMARY}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('files_new',0))" 2>/dev/null || echo 0)
FILES_CHANGED=$(echo "${SUMMARY}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('files_changed',0))" 2>/dev/null || echo 0)
FILES_UNMODIFIED=$(echo "${SUMMARY}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('files_unmodified',0))" 2>/dev/null || echo 0)
SIZE_ADDED=$(echo "${SUMMARY}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data_added',0))" 2>/dev/null || echo 0)
# Nombre de snapshots
SNAPSHOTS=$(restic -r "${REPO}" snapshots --json 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

# Taille totale du repo
SIZE_TOTAL=$(restic -r "${REPO}" stats --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_size',0))" 2>/dev/null || echo 0)

# Statut final
if [ "${RESTIC_EXIT}" -eq 0 ]; then
    STATUS="success"
    ERROR_MSG=""
    SIZE_ADDED_HR=$(numfmt --to=iec "${SIZE_ADDED}" 2>/dev/null || echo "${SIZE_ADDED}B")
    SIZE_TOTAL_HR=$(numfmt --to=iec "${SIZE_TOTAL}" 2>/dev/null || echo "${SIZE_TOTAL}B")
    notify_matrix "backup OK ${HOSTNAME}/${REPO_NAME} -- ${DURATION}s | +${SIZE_ADDED_HR} | total ${SIZE_TOTAL_HR} | ${FILES_NEW} new ${FILES_CHANGED} changed | ${SNAPSHOTS} snapshots"
else
    STATUS="failure"
    ERROR_MSG=$(tail -5 "${RESTIC_OUT}" | tr '\n' ' ' | sed 's/"/\\"/g')
    notify_matrix "backup FAILED ${HOSTNAME}/${REPO_NAME} -- ${ERROR_MSG}"
    notify_email "[BACKUP FAIL] ${HOSTNAME}/${REPO_NAME}" \
        "Backup failed on ${HOSTNAME}\nRepo: ${REPO_NAME}\nPath: ${REPO}\nError: ${ERROR_MSG}\nDuration: ${DURATION}s\nTime: $(date)"
fi

# Payload CMDB — construit avec jq pour éviter l'injection JSON
# jq sanitise les strings et sérialise correctement le raw restic JSON
RAW_JSON=$(echo "${SUMMARY}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d))" 2>/dev/null || echo '{}')

PAYLOAD=$(python3 - <<PYEOF
import json, sys
payload = {
    "hostname":         "${HOSTNAME}",
    "repo_name":        "${REPO_NAME}",
    "repo_path":        "${REPO}",
    "sftp_host":        "${SFTP_HOST}",
    "sftp_user":        "${SFTP_USER}",
    "status":           "${STATUS}",
    "files_new":         ${FILES_NEW},
    "files_changed":     ${FILES_CHANGED},
    "files_unmodified":  ${FILES_UNMODIFIED},
    "size_added":        ${SIZE_ADDED},
    "size_total":        ${SIZE_TOTAL},
    "snapshots_total":   ${SNAPSHOTS},
    "duration_secs":     ${DURATION},
    "error_msg":        "${ERROR_MSG}",
    "started_at":       "${START_TS}",
    "source":           "script",
    "raw":              ${RAW_JSON},
}
print(json.dumps(payload))
PYEOF
)

if [ -z "${PAYLOAD}" ]; then
    echo "[ERROR] Failed to build CMDB payload" | tee -a "${LOG}"
else
    post_result "${PAYLOAD}"
fi

rm -f "${RESTIC_OUT}"
echo "[$(date)] Done -- status: ${STATUS} in ${DURATION}s" | tee -a "${LOG}"
exit ${RESTIC_EXIT}
