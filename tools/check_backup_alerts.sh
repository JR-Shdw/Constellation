#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
# check_backup_alerts.sh — Verifie les alertes backup et notifie via Matrix + mail
# Usage en cron toutes les 6h sur vega (apres les backups)
#
# Variables d'environnement:
#   CMDB_API, CMDB_COLLECT_TOKEN
#   MATRIX_URL, MATRIX_TOKEN, MATRIX_ROOM (room BACKUP)
#   ALERT_EMAIL (optionnel)

set -euo pipefail

CMDB_API="${CMDB_API:-http://10.0.1.1:8000}"
CMDB_TOKEN="${CMDB_COLLECT_TOKEN}"
MATRIX_URL="${MATRIX_URL:-https://matrix.example.com}"
MATRIX_TK="${MATRIX_TOKEN:-}"
MATRIX_ROOM="${MATRIX_ROOM:-}"
ALERT_EMAIL="${ALERT_EMAIL:-}"

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

notify_mail() {
    [ -z "${ALERT_EMAIL}" ] && return 0
    local subject="$1"
    local body="$2"
    echo "${body}" | mail -s "${subject}" "${ALERT_EMAIL}" 2>/dev/null || true
}

# Recuperer les alertes depuis l'API
ALERTS=$(curl -sf -H "Authorization: Bearer ${CMDB_TOKEN}" \
    "${CMDB_API}/api/v1/backup/alerts" 2>/dev/null || echo '{"items":[]}')

COUNT=$(echo "${ALERTS}" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('items',[])))")

if [ "${COUNT}" -eq 0 ]; then
    echo "[$(date)] No backup alerts"
    exit 0
fi

echo "[$(date)] ${COUNT} backup alert(s) found"

# Construire le message
MSG=$(echo "${ALERTS}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
lines = ['BACKUP ALERTS - {} issue(s)'.format(len(data['items'])), '']
for a in data['items']:
    t = a.get('alert_type','?')
    h = a.get('hostname','?')
    r = a.get('repo_name','')
    e = a.get('error_msg','')
    lr = a.get('last_run','never')
    if t == 'missing':
        lines.append(f'  [NO BACKUP] {h} - no backup configured')
    elif t == 'failure':
        lines.append(f'  [FAILED] {h}/{r} - {e[:80]}')
    elif t == 'overdue':
        lines.append(f'  [OVERDUE] {h}/{r} - last run: {lr}')
print('\n'.join(lines))
")

# Envoyer
notify_matrix "${MSG}"
notify_mail "CMDB Backup Alerts - ${COUNT} issue(s)" "${MSG}"

echo "${MSG}"
