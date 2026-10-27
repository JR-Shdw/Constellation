# Operations

## Data Sources

### Ansible — hardware + software inventory

The `collect_inventory` role collects OS, packages, and containers via WireGuard.

| Data | Method |
|------|--------|
| Hardware | `inxi -Fxxx --output json` |
| OS | `/etc/os-release` + facts |
| Debian packages | `dpkg-query -W` |
| Arch packages | `pacman -Q` |
| RHEL/Rocky packages | `rpm -qa` |
| Containers | `docker inspect` (networks, ports, labels, digest) |
| Exposure | auto-classified: internet/wireguard/docker_internal/localhost |

```bash
# Manual collection
cd ansible && ansible-playbook -i inventory/hosts.ini playbooks/collect.yml

# Single host
ansible-playbook -i inventory/hosts.ini playbooks/collect.yml -l your-host

# Workstations (sudo)
ansible-playbook -i inventory/hosts.ini playbooks/collect_workstations.yml --ask-become-pass
```

### Trivy — CVE scans

```bash
# Install trivy on all hosts
ansible-playbook -i inventory/hosts.ini playbooks/install_trivy.yml

# Scan rootfs + Docker images
ansible-playbook -i inventory/hosts.ini playbooks/scan_trivy.yml

# Scan CMDB stack images
make scan-images

# Scan a single image
trivy image --format json --severity HIGH,CRITICAL nginx:latest | \
  curl -X POST http://localhost:8000/api/v1/cves/report \
    -H "Authorization: Bearer $COLLECT_TOKEN" \
    -H "Content-Type: application/json" --data-binary @-
```

### Trivy — misconfiguration scans

```bash
ansible-playbook -i inventory/hosts.ini playbooks/scan_misconf.yml
```

Recommended cron: weekly `0 4 * * 0`

### Wazuh — OS CVEs + SCA compliance

Synced via `sync-wazuh` container (6h cron):

```bash
docker exec cmdb_sync_wazuh python3 /app/sync_wazuh.py
docker exec cmdb_sync_wazuh python3 /app/sync_wazuh.py --agent-id 001
docker exec cmdb_sync_wazuh python3 /app/sync_wazuh.py --skip-sca
```

### OpenCVE — CVE monitoring + CISA KEV

| Script | Usage |
|--------|-------|
| `sync_opencve.py` | Hourly cron, last N hours |
| `sync_opencve_full.py` | Initial import, filters, resume |

```bash
make opencve-sync                                    # incremental (24h)
python3 tools/sync_opencve_full.py --limit 100000 --resume  # full import
python3 tools/sync_opencve_full.py --min-severity high --hours 1480  # high+critical, 60 days
```

| Option | Description |
|--------|-------------|
| `--min-severity` | Minimum threshold (high = high + critical) |
| `--hours N` | Time window (0 = all) |
| `--limit N` | Max CVEs to import |
| `--resume` | Skip already imported |
| `--workers N` | Parallel threads (default: 4) |

### Restic — backup monitoring

```bash
# Install wrapper
cp tools/restic-backup.sh /usr/local/bin/ && chmod +x /usr/local/bin/restic-backup.sh

# Usage: restic-backup.sh <repo_name> <sftp_host> <sftp_path> <sources...>
restic-backup.sh home sftp.example.com /backups/$(hostname)/home /home
```

Cron: `0 2 * * * root /usr/local/bin/restic-backup.sh ...`

Alerts: `tools/check_backup_alerts.sh` detects missing backups, failures, overdue (>25h).

---

## Makefile

```
# Stack
make up / down / build / restart / logs / ps
make api-logs              API logs only
make db-shell              psql shell
make db-backup             PostgreSQL dump

# Collection
make collect               Ansible inventory (all hosts)
make collect-trivy         Trivy CVE scan
make collect-misconf       Trivy misconfiguration scan
make collect-backup        Restic backup logs
make scan-images           Trivy scan CMDB images

# Sync
make opencve-sync          OpenCVE incremental (24h)
make opencve-full          OpenCVE full import
make wazuh-sync            Wazuh CVEs + SCA

# OpenCVE stack
make opencve-up / down / ps / logs / build
make opencve-admin         Create Django admin
make opencve-dag-start / stop / trigger / status

# Deploy
make deploy                Full deploy (sync + migrate + build + restart)
make sync                  Sync files only
make migrate               Apply SQL schema

# Dev
make lint                  Ruff check + format check
make lint-fix              Auto-fix
make test                  Pytest
make secrets               Generate .env secrets
make clean                 Remove volumes + orphans
```

## Migrations

The schema is idempotent (`CREATE TABLE IF NOT EXISTS`). Applied automatically at API startup with PostgreSQL advisory lock.

Legacy migrations in `migrations/` are kept for reference but no longer needed — `schema.sql` is the single source of truth.
