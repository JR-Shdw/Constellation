# Operations

## Sources de donnees

### Ansible — inventaire hardware + logiciel

Le role `collect_inventory` collecte OS, paquets et containers via WireGuard.

| Donnee | Methode |
|--------|---------|
| Hardware | `inxi -Fxxx --output json` |
| OS | `/etc/os-release` + facts |
| Paquets Debian | `dpkg-query -W` |
| Paquets Arch | `pacman -Q` |
| Paquets RHEL/Rocky | `rpm -qa` |
| Containers | `docker inspect` (networks, ports, labels, digest) |
| Exposure | auto-classifiee : internet/wireguard/docker_internal/localhost |

```bash
# Collecte manuelle
cd ansible && ansible-playbook -i inventory/hosts.ini playbooks/collect.yml

# Un host
ansible-playbook -i inventory/hosts.ini playbooks/collect.yml -l your-host

# Workstations (sudo)
ansible-playbook -i inventory/hosts.ini playbooks/collect_workstations.yml --ask-become-pass
```

### Trivy — scans CVE

```bash
# Installer trivy sur tous les hosts
ansible-playbook -i inventory/hosts.ini playbooks/install_trivy.yml

# Scanner rootfs + images Docker
ansible-playbook -i inventory/hosts.ini playbooks/scan_trivy.yml

# Scanner les images de la stack CMDB
make scan-images

# Scanner une image manuellement
trivy image --format json --severity HIGH,CRITICAL nginx:latest | \
  curl -X POST http://localhost:8000/api/v1/cves/report \
    -H "Authorization: Bearer $COLLECT_TOKEN" \
    -H "Content-Type: application/json" --data-binary @-
```

### Trivy — scans misconfiguration

```bash
ansible-playbook -i inventory/hosts.ini playbooks/scan_misconf.yml
```

Cron recommande : weekly `0 4 * * 0`

### Wazuh — CVE OS + SCA compliance

Synchro via le container `sync-wazuh` (cron 6h) :

```bash
docker exec cmdb_sync_wazuh python3 /app/sync_wazuh.py
docker exec cmdb_sync_wazuh python3 /app/sync_wazuh.py --agent-id 001
docker exec cmdb_sync_wazuh python3 /app/sync_wazuh.py --skip-sca
```

### OpenCVE — veille CVE + CISA KEV

| Script | Usage |
|--------|-------|
| `sync_opencve.py` | Cron horaire, dernieres N heures |
| `sync_opencve_full.py` | Import initial, filtres, resume |

```bash
make opencve-sync                                    # incremental (24h)
python3 tools/sync_opencve_full.py --limit 100000 --resume  # import complet
python3 tools/sync_opencve_full.py --min-severity high --hours 1480  # high+critical, 60 jours
```

| Option | Description |
|--------|-------------|
| `--min-severity` | Seuil minimum (high = high + critical) |
| `--hours N` | Fenetre temporelle (0 = tout) |
| `--limit N` | Max CVEs a importer |
| `--resume` | Skip les deja importees |
| `--workers N` | Threads paralleles (defaut: 4) |

### Restic — monitoring des backups

```bash
# Installer le wrapper
cp tools/restic-backup.sh /usr/local/bin/ && chmod +x /usr/local/bin/restic-backup.sh

# Usage : restic-backup.sh <repo_name> <sftp_host> <sftp_path> <sources...>
restic-backup.sh home sftp.example.com /backups/$(hostname)/home /home
```

Cron : `0 2 * * * root /usr/local/bin/restic-backup.sh ...`

Alertes : `tools/check_backup_alerts.sh` detecte backups manquants, echecs, retard (>25h).

---

## Makefile

```
# Stack
make up / down / build / restart / logs / ps
make api-logs              Logs API uniquement
make db-shell              Shell psql
make db-backup             Dump PostgreSQL

# Collecte
make collect               Inventaire Ansible (tous les hosts)
make collect-trivy         Scan Trivy CVE
make collect-misconf       Scan misconfigurations Trivy
make collect-backup        Logs backup Restic
make scan-images           Scan Trivy images CMDB

# Sync
make opencve-sync          OpenCVE incremental (24h)
make opencve-full          OpenCVE import complet
make wazuh-sync            Wazuh CVEs + SCA

# Stack OpenCVE
make opencve-up / down / ps / logs / build
make opencve-admin         Creer compte admin Django
make opencve-dag-start / stop / trigger / status

# Deploy
make deploy                Deploy complet (sync + migrate + build + restart)
make sync                  Sync fichiers uniquement
make migrate               Appliquer schema SQL

# Dev
make lint                  Ruff check + format check
make lint-fix              Auto-fix
make test                  Pytest
make secrets               Genere les secrets .env
make clean                 Supprime volumes + orphelins
```

## Migrations

Le schema est idempotent (`CREATE TABLE IF NOT EXISTS`). Applique automatiquement au demarrage de l'API avec advisory lock PostgreSQL.

Les anciennes migrations dans `migrations/` sont gardees comme reference mais ne sont plus necessaires — `schema.sql` est la source de verite unique.
