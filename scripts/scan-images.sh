#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
# scan-images.sh — Trivy scan des images CMDB + push vers l'API CMDB
#
# Usage:
#   ./scripts/scan-images.sh                  # scan toutes les images
#   ./scripts/scan-images.sh --push-only      # re-push les rapports existants
#
# Variables d'environnement (ou depuis .env):
#   CMDB_URL            — URL de l'API CMDB (défaut: http://10.0.0.1:8000)
#   COLLECT_TOKEN       — Bearer token d'ingestion
#   HOSTNAME_REPORT     — hostname à déclarer dans le rapport (défaut: $(hostname))
#   TRIVY_CACHE_DIR     — répertoire cache Trivy (défaut: /tmp/trivy-cache)

set -euo pipefail

# Config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Charger .env si présent
if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$REPO_ROOT/.env"
    set +a
fi

CMDB_URL="${CMDB_URL:-http://10.0.0.1:8000}"
TOKEN="${COLLECT_TOKEN:-}"
HOSTNAME_REPORT="${HOSTNAME_REPORT:-$(hostname)}"
TRIVY_CACHE="${TRIVY_CACHE_DIR:-/tmp/trivy-cache}"
REPORTS_DIR="${TRIVY_REPORTS_DIR:-/tmp/trivy-reports-cmdb}"
PUSH_ONLY="${1:-}"

if [ -z "$TOKEN" ]; then
    echo "[ERROR] COLLECT_TOKEN is not set" >&2
    exit 1
fi

mkdir -p "$TRIVY_CACHE" "$REPORTS_DIR"

# Images à scanner — images publiques du compose + images buildées localement
# Récupère les images des containers actuellement en cours
RUNNING_IMAGES=()
while IFS= read -r img; do
    [ -n "$img" ] && RUNNING_IMAGES+=("$img")
done < <(docker ps --format '{{.Image}}' 2>/dev/null | grep -v "^$" | sort -u)

# Ajouter postgres depuis versions.env
POSTGRES_VERSION=$(grep POSTGRES_VERSION "$REPO_ROOT/versions.env" 2>/dev/null | cut -d= -f2 || echo "16-bookworm")
STATIC_IMAGES=("postgres:${POSTGRES_VERSION}")

# Fusion : running + static, dédupliqué
ALL_IMAGES=()
declare -A seen
for img in "${RUNNING_IMAGES[@]}" "${STATIC_IMAGES[@]}"; do
    if [[ -z "${seen[$img]:-}" ]]; then
        ALL_IMAGES+=("$img")
        seen[$img]=1
    fi
done

echo "[scan] Hostname: $HOSTNAME_REPORT"
echo "[scan] CMDB:     $CMDB_URL"
echo "[scan] Images:   ${#ALL_IMAGES[@]}"
echo ""

# Scan Trivy
if [ "$PUSH_ONLY" != "--push-only" ]; then
    echo "[scan] Updating Trivy DB..."
    docker run --rm \
        -v "$TRIVY_CACHE:/trivy-cache" \
        -e TRIVY_CACHE_DIR=/trivy-cache \
        aquasec/trivy:latest \
        image --download-db-only --cache-dir /trivy-cache
    echo "[scan] DB updated"
    echo ""

    for image in "${ALL_IMAGES[@]}"; do
        # Nom de fichier sûr
        safe_name=$(echo "$image" | tr '/: ' '---')
        out="$REPORTS_DIR/${safe_name}.json"

        echo "[scan] Scanning $image..."
        docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$TRIVY_CACHE:/trivy-cache" \
            -v "$REPORTS_DIR:/reports" \
            -e TRIVY_CACHE_DIR=/trivy-cache \
            aquasec/trivy:latest \
            image \
            --severity HIGH,CRITICAL \
            --ignore-unfixed \
            --exit-code 0 \
            --format json \
            --output "/reports/${safe_name}.json" \
            "$image" || true

        if [ -f "$out" ]; then
            count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$out" 2>/dev/null || echo 0)
            echo "  → $count vulnerabilities found"
        fi
    done
fi

# Push vers CMDB
echo ""
echo "[push] Pushing reports to CMDB..."
pushed=0
errors=0
skipped=0

for json_file in "$REPORTS_DIR"/*.json; do
    [ -f "$json_file" ] || continue

    image=$(jq -r '.ArtifactName // "unknown"' "$json_file" 2>/dev/null || echo "unknown")
    count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$json_file" 2>/dev/null || echo 0)

    if [ "$count" -eq 0 ]; then
        echo "[push] $image: no CVEs, skipping"
        skipped=$((skipped + 1))
        continue
    fi

    payload=$(jq -c \
        --arg h "$HOSTNAME_REPORT" \
        --arg img "$image" \
        '{hostname:$h,source:"trivy",target_type:"container",target_name:$img,image:$img,vulnerabilities:[.Results[]?.Vulnerabilities[]?]}' \
        "$json_file")

    if echo "$payload" | curl -sf -o /dev/null \
        -X POST "${CMDB_URL}/api/v1/cves/report" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d @- \
        --max-time 30; then
        echo "[push] $image: $count CVEs → CMDB"
        pushed=$((pushed + 1))
    else
        echo "[WARN] push failed: $image"
        errors=$((errors + 1))
    fi
done

echo ""
echo "[done] pushed=$pushed skipped=$skipped errors=$errors"
[ "$errors" -eq 0 ] || exit 1
