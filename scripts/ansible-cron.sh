#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
# CMDB — Wrapper cron pour les playbooks Ansible
# Lance un playbook avec le vault auto-déchiffré
#
# Usage:
#   ./scripts/ansible-cron.sh <playbook> [extra args...]
#
# Exemples:
#   ./scripts/ansible-cron.sh scan_misconf.yml
#   ./scripts/ansible-cron.sh scan_trivy.yml
#   ./scripts/ansible-cron.sh collect.yml
#   ./scripts/ansible-cron.sh check_drift.yml
#   ./scripts/ansible-cron.sh collect_backup_logs.yml
#
# Prérequis:
#   1. .vault_pass contient le mot de passe Ansible Vault
#   2. ansible/group_vars/all/vault.yml est chiffré avec ce password
#   3. Les clés SSH sont en place (~/.ssh/cmdb_collect_ed25519, cmdb_scan_ed25519)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ANSIBLE_DIR="$PROJECT_DIR/ansible"
LOG_DIR="$PROJECT_DIR/logs"

PLAYBOOK="${1:?Usage: $0 <playbook.yml> [extra args...]}"
shift

mkdir -p "$LOG_DIR"

LOGFILE="$LOG_DIR/ansible-$(basename "$PLAYBOOK" .yml)-$(date +%Y%m%d-%H%M%S).log"

if [ ! -f "$PROJECT_DIR/.vault_pass" ]; then
    echo "FATAL: .vault_pass not found — run: echo 'your-password' > .vault_pass && chmod 600 .vault_pass" >&2
    exit 1
fi

if [ ! -f "$ANSIBLE_DIR/playbooks/$PLAYBOOK" ]; then
    echo "FATAL: playbook not found: $ANSIBLE_DIR/playbooks/$PLAYBOOK" >&2
    exit 1
fi

echo "[$(date -Iseconds)] Starting $PLAYBOOK" | tee "$LOGFILE"

cd "$ANSIBLE_DIR"
ansible-playbook \
    -i inventory/hosts.ini \
    "playbooks/$PLAYBOOK" \
    "$@" \
    >> "$LOGFILE" 2>&1

STATUS=$?

if [ $STATUS -eq 0 ]; then
    echo "[$(date -Iseconds)] $PLAYBOOK completed OK" | tee -a "$LOGFILE"
else
    echo "[$(date -Iseconds)] $PLAYBOOK FAILED (exit $STATUS)" | tee -a "$LOGFILE" >&2
fi

# Nettoyage logs > 30 jours
find "$LOG_DIR" -name "ansible-*.log" -mtime +30 -delete 2>/dev/null || true

exit $STATUS
