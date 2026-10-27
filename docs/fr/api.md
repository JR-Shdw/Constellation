# CMDB API Reference

Base URL: `https://cmdb.example.com/api/v1` (via Traefik + Authelia)
Internal: `http://10.0.1.1:8000/api/v1` (via WireGuard wg1)
Swagger: `https://cmdb.example.com/api/docs`

---

## Authentication

Deux modes selon l'endpoint :

### Bearer Token (collecte machine-to-machine)

Utilise par Ansible, restic-backup, sync scripts, Trivy.
Le token est le `COLLECT_TOKEN` defini dans `.env`.

```
Authorization: Bearer <COLLECT_TOKEN>
```

### Authelia / Bearer Token (lecture humain + scripts)

Les endpoints de lecture acceptent :
1. **Authelia** — headers `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups` injectes par forwardauth
2. **Bearer Token** — fallback avec le meme `COLLECT_TOKEN`

### Codes d'erreur

| Code | Signification |
|------|---------------|
| 200  | Succes |
| 401  | Token manquant ou invalide / pas authentifie Authelia |
| 422  | Validation Pydantic (champ manquant ou type incorrect) |
| 500  | Erreur interne |

---

## Endpoints de collecte (Bearer Token)

### `GET /api/v1/health`

Healthcheck public, aucune authentification requise.

**Response:**
```json
{"status": "ok"}
```

---

### `POST /api/v1/nodes/report`

Upsert d'un node + ses packages + ses containers. Utilise par le role Ansible `collect_inventory`.

**Request Body:**
```json
{
  "hostname": "vega",
  "type": "server",
  "os": "Arch Linux",
  "os_version": "rolling",
  "arch": "x86_64",
  "kernel": "6.6.126-1-MANJARO",
  "os_raw": "...",
  "hw_info": {"cpu": "...", "ram": "..."},
  "packages": [
    "openssh\t9.7p1-1\tx86_64",
    "nginx\t1.26.0-1\tx86_64"
  ],
  "containers": [
    {"name": "grafana", "image": "grafana/grafana:12.2.0", "status": "running"},
    {"name": "loki", "image": "grafana/loki:3.5.5", "status": "running"}
  ]
}
```

| Champ | Type | Requis | Description |
|-------|------|--------|-------------|
| hostname | string | oui | Nom d'hote unique |
| type | string | non | `server`, `vm`, `workstation` (default: `vm`) |
| os | string | non | Nom de l'OS |
| os_version | string | non | Version OS |
| arch | string | non | Architecture CPU |
| kernel | string | non | Version kernel |
| os_raw | string | non | Contenu brut `/etc/os-release` |
| hw_info | object/string | non | Info hardware (JSON libre) |
| packages | list[string] | non | Paquets `name\tversion[\tarch]` (tab-separated) |
| containers | list[object/string] | non | Containers Docker |

**Response:**
```json
{"status": "ok", "node_id": "uuid", "hostname": "vega"}
```

**Notes:**
- Les packages et containers sont remplaces (delete + insert) a chaque report
- `last_seen` est mis a jour automatiquement
- `is_active` est remis a `true`

---

### `POST /api/v1/cves/report`

Ingest de CVEs depuis Trivy (containers) ou Wazuh (packages OS).

**Request Body:**
```json
{
  "hostname": "vega",
  "source": "trivy",
  "target_type": "container",
  "target_name": "grafana/grafana:12.2.0",
  "image": "grafana/grafana:12.2.0",
  "vulnerabilities": [
    {
      "VulnerabilityID": "CVE-2024-1234",
      "Severity": "HIGH",
      "CVSS": {"nvd": {"V3Score": 7.5}},
      "PkgName": "libssl3",
      "PkgType": "debian",
      "InstalledVersion": "3.0.11-1",
      "FixedVersion": "3.0.13-1",
      "Description": "Buffer overflow in...",
      "Layer": {"Digest": "sha256:abc..."},
      "Target": "grafana/grafana:12.2.0 (debian 12.4)"
    }
  ]
}
```

| Champ | Type | Requis | Description |
|-------|------|--------|-------------|
| hostname | string | oui | Node source |
| source | string | non | `trivy` ou `wazuh` (default: `trivy`) |
| target_type | string | non | `container` ou `package` (default: `package`) |
| target_name | string | non | Nom de la cible (image ou hostname) |
| image | string | non | Nom complet de l'image Docker |
| vulnerabilities | list[dict] | non | Liste des CVEs |

**Champs vulnerabilite (Trivy format):**

| Champ | Fallback Wazuh | Description |
|-------|---------------|-------------|
| VulnerabilityID | cve_id | Identifiant CVE |
| Severity | severity | critical/high/medium/low |
| CVSS.*.V3Score | cvss_score | Score CVSS v3 |
| PkgName | pkg_name | Nom du paquet |
| PkgType | pkg_type | Type (debian, alpine, pip, npm...) |
| InstalledVersion | installed_ver | Version installee |
| FixedVersion | fixed_ver | Version corrigee |
| Description | description | Description CVE (tronquee 500 chars) |
| Layer.Digest | — | Digest du layer Docker |
| Target | target | Cible du scan |

**Response:**
```json
{"status": "ok", "node_id": "uuid", "cves_ingested": 42}
```

**Notes:**
- Si `target_type=container` -> table `cve_containers` (ON CONFLICT DO NOTHING)
- Si `target_type=package` -> table `cve_host_packages` (ON CONFLICT DO UPDATE)
- Declenche des notifications Matrix/mail selon le seuil de severite configure

---

### `POST /api/v1/backup/report`

Resultat d'un backup restic. Utilise par le wrapper `restic-backup.sh`.

**Request Body:**
```json
{
  "hostname": "altair",
  "repo_name": "alcor-altair",
  "repo_path": "sftp:backup@backup.example.com:/home/backup/altair",
  "sftp_host": "backup.example.com",
  "sftp_user": "backup",
  "status": "success",
  "files_new": 12,
  "files_changed": 45,
  "files_unmodified": 6789,
  "size_added": 1048576,
  "size_total": 10737418240,
  "snapshots_total": 42,
  "duration_secs": 120,
  "error_msg": null,
  "started_at": "2026-03-28T21:01:00Z",
  "source": "script",
  "raw": {"message_type": "summary", "files_new": 12, "...": "..."}
}
```

| Champ | Type | Requis | Description |
|-------|------|--------|-------------|
| hostname | string | oui | Node source |
| repo_name | string | non | Nom du repo (default: `default`) |
| repo_path | string | non | Chemin SFTP complet |
| sftp_host | string | non | Hote SFTP |
| sftp_user | string | non | User SFTP |
| status | string | non | `success`, `failure`, `partial`, `running` |
| files_new | int | non | Fichiers nouveaux |
| files_changed | int | non | Fichiers modifies |
| files_unmodified | int | non | Fichiers inchanges |
| size_added | int | non | Octets ajoutes |
| size_total | int | non | Taille totale du repo |
| snapshots_total | int | non | Nombre de snapshots |
| duration_secs | int | non | Duree en secondes |
| source | string | non | `script` (default) |
| error_msg | string | non | Message d'erreur si echec |
| started_at | string | non | Timestamp ISO debut |
| raw | object | non | Sortie JSON brute restic |

**Response:**
```json
{"status": "ok", "repo_id": "uuid"}
```

**Notes:**
- Upsert du repository + insert du run
- ON CONFLICT sur `(repo_id, started_at)` -> les doublons sont ignores
- Le node doit exister dans la table `nodes` (via `/nodes/report` d'abord)

---

### `POST /api/v1/sca/report`

Resultats SCA (Security Configuration Assessment) depuis Wazuh.

**Request Body:**
```json
{
  "hostname": "altair",
  "source": "wazuh",
  "policies": [
    {
      "policy_id": "cis_debian12",
      "policy_name": "CIS Debian 12 Benchmark",
      "score": 72,
      "total_checks": 150,
      "passed": 108,
      "failed": 42,
      "end_scan": "2026-03-28T10:00:00Z"
    }
  ]
}
```

| Champ | Type | Requis | Description |
|-------|------|--------|-------------|
| hostname | string | oui | Node source |
| source | string | non | `wazuh` (default) |
| policies | list[dict] | non | Resultats par policy |

**Champs policy:**

| Champ | Type | Description |
|-------|------|-------------|
| policy_id | string | Identifiant unique de la policy |
| policy_name | string | Nom lisible |
| score | int | Score de conformite (0-100) |
| total_checks | int | Nombre total de checks |
| passed | int | Checks passes |
| failed | int | Checks echoues |
| end_scan | string | Timestamp fin du scan |

**Response:**
```json
{"status": "ok", "node_id": "uuid", "policies_ingested": 3}
```

---

### `POST /api/v1/opencve/webhook`

Reception d'une alerte OpenCVE individuelle.

**Request Body:**
```json
{
  "cve_id": "CVE-2026-12345",
  "vendor": "nginx",
  "product": "nginx",
  "title": "Buffer overflow in ngx_http_parse_request_line",
  "description": "A buffer overflow vulnerability...",
  "cvss_v3": 8.1,
  "severity": "high",
  "cwe_ids": ["CWE-120"],
  "updated_at": "2026-03-28T12:00:00Z",
  "metrics": {}
}
```

| Champ | Type | Description |
|-------|------|-------------|
| cve_id | string | Identifiant CVE |
| vendor | string | Vendeur (optionnel) |
| product | string | Produit (optionnel) |
| title | string | Titre (tronque 200 chars) |
| description | string | Description (tronque 2000 chars) |
| cvss_v3 | float | Score CVSS v3 |
| severity | string | critical/high/medium/low/unknown |
| cwe_ids | list[string] | Liste de CWE |
| updated_at | string | Date de mise a jour |
| metrics | object | Metriques NVD brutes (extraction auto du CVSS) |

**Response:**
```json
{"status": "ok", "cve_id": "CVE-2026-12345"}
```

**Notes:**
- La severite est recalculee depuis `cvss_v3` si present
- Declenche une notification si le seuil est atteint
- ON CONFLICT sur `(cve_id, product)` -> update du score et de la severite

---

### `POST /api/v1/opencve/webhook/batch`

Import en lot d'alertes OpenCVE. Utilise par `sync_opencve.py`.

**Request Body:** (liste de dicts, meme format que `/webhook` individuel)
```json
[
  {"cve_id": "CVE-2026-001", "vendor": "nginx", "product": "nginx", "title": "...", "cvss_v3": 7.5, "severity": "high"},
  {"cve_id": "CVE-2026-002", "vendor": "linux", "product": "linux_kernel", "title": "...", "cvss_v3": 9.8, "severity": "critical"}
]
```

**Response:**
```json
{"status": "ok", "imported": 2}
```

---

## Endpoints de lecture (Authelia / Bearer Token)

Tous les endpoints paginables acceptent `?page=N&per_page=N` (default: page=1, per_page=50, max=200).

### `GET /api/v1/nodes`

Liste des nodes avec compteurs.

| Parametre | Type | Description |
|-----------|------|-------------|
| page | int | Page (default: 1) |
| per_page | int | Resultats par page (default: 50, max: 200) |
| type | string | Filtre par type (`server`, `vm`, `workstation`) — ILIKE |
| os | string | Filtre par OS exact |
| active | bool | Filtre par statut actif |

**Response:**
```json
{
  "items": [
    {
      "id": "uuid",
      "hostname": "vega",
      "type": "server",
      "os": "Arch Linux",
      "os_version": "rolling",
      "kernel": "6.6.126-1-MANJARO",
      "last_seen": "2026-03-28T10:00:00",
      "is_active": true,
      "package_count": 856,
      "container_count": 22,
      "cve_package_count": 12,
      "cve_container_count": 45,
      "cve_critical_count": 3
    }
  ],
  "total": 12,
  "page": 1,
  "per_page": 50
}
```

---

### `GET /api/v1/nodes/{node_id}`

Detail d'un node avec ses packages, containers et CVEs.

**Response:**
```json
{
  "node": {"id": "uuid", "hostname": "vega", "...": "..."},
  "packages": [
    {"name": "openssh", "version": "9.7p1-1", "arch": "x86_64"}
  ],
  "containers": [
    {"name": "grafana", "image": "grafana/grafana", "tag": "12.2.0", "status": "running"}
  ],
  "cves": [
    {"cve_id": "CVE-2024-1234", "severity": "critical", "cvss_score": 9.8, "...": "..."}
  ]
}
```

**Notes:** Les CVEs sont triees par score CVSS decroissant, limitees a 100.

---

### `GET /api/v1/packages`

Liste des packages (groupes par defaut).

| Parametre | Type | Description |
|-----------|------|-------------|
| name | string | Filtre par nom (ILIKE) |
| version | string | Filtre par version (ILIKE) |
| group | bool | Grouper par nom+version (default: true) |

**Response (group=true):**
```json
{
  "items": [
    {"name": "openssh", "version": "9.7p1-1", "arch": "x86_64", "host_count": 8, "hostnames": ["sirius", "altair", "vega"]}
  ],
  "total": 2345,
  "page": 1,
  "per_page": 50
}
```

---

### `GET /api/v1/packages/hosts?name=X`

Hotes ou un package specifique est installe.

| Parametre | Type | Requis | Description |
|-----------|------|--------|-------------|
| name | string | oui | Nom exact du package |

**Response:**
```json
{
  "items": [
    {"name": "openssh", "version": "9.7p1-1", "arch": "x86_64", "hostname": "vega", "node_id": "uuid"}
  ]
}
```

---

### `GET /api/v1/containers`

Liste des containers Docker (groupes par defaut).

| Parametre | Type | Description |
|-----------|------|-------------|
| image | string | Filtre par image (ILIKE) |
| tag | string | Filtre par tag (ILIKE) |
| group | bool | Grouper (default: true) |

---

### `GET /api/v1/containers/hosts?image=X`

Hotes qui font tourner une image Docker.

| Parametre | Type | Requis | Description |
|-----------|------|--------|-------------|
| image | string | oui | Nom exact de l'image |

---

### `GET /api/v1/cves`

Liste de toutes les CVEs (packages + containers via `v_all_cves`).

| Parametre | Type | Description |
|-----------|------|-------------|
| severity | string | Filtre : `critical`, `high`, `medium`, `low` |

**Response:**
```json
{
  "items": [
    {
      "cve_id": "CVE-2024-1234",
      "severity": "critical",
      "cvss_score": 9.8,
      "target": "grafana/grafana:12.2.0",
      "target_type": "container",
      "pkg_name": "libssl3",
      "hostname": "vega",
      "node_id": "uuid"
    }
  ],
  "total": 456
}
```

---

### `GET /api/v1/secrets`

Secrets detectes par Trivy dans les layers Docker.

**Response:**
```json
{
  "items": [
    {"file_path": "/app/.env", "secret_type": "aws-access-key", "severity": "critical", "hostname": "vega"}
  ]
}
```

---

### `GET /api/v1/search?q=X`

Recherche globale sur nodes, packages, containers, CVEs (ILIKE, min 2 chars).

| Parametre | Type | Requis | Description |
|-----------|------|--------|-------------|
| q | string | oui | Terme de recherche (min 2 chars) |

**Response:**
```json
{
  "nodes": [{"id": "uuid", "hostname": "vega", "type": "server", "os": "Arch Linux"}],
  "packages": [{"name": "openssh", "version": "9.7p1-1", "hostname": "vega"}],
  "containers": [{"name": "grafana", "image": "grafana/grafana", "hostname": "vega"}],
  "cves": [{"cve_id": "CVE-2024-1234", "severity": "critical", "cvss_score": 9.8}]
}
```

**Notes:** Chaque categorie est limitee a 10 resultats.

---

### `GET /api/v1/stats`

Statistiques globales du dashboard.

**Response:**
```json
{
  "nodes_total": 15,
  "nodes_active": 12,
  "packages_total": 8456,
  "containers_total": 45,
  "cves_critical": 3,
  "cves_high": 27,
  "cves_total": 456,
  "backups_ok": 10,
  "backups_failed": 1,
  "backups_overdue": 2
}
```

---

### `GET /api/v1/backup/summary`

Resume des backups avec stats 30 jours.

**Response:**
```json
{
  "items": [
    {
      "repo_id": "uuid",
      "hostname": "altair",
      "repo_name": "alcor-altair",
      "status": "success",
      "finished_at": "2026-03-28T21:05:00",
      "overdue": false,
      "total_runs": 90,
      "success_count": 88,
      "failure_count": 2,
      "avg_duration_secs": 120,
      "success_rate": 97.8,
      "total_added_30d": 5368709120
    }
  ]
}
```

---

### `GET /api/v1/backup/alerts`

Alertes backup : echecs, retards, nodes sans backup.

**Response:**
```json
{
  "items": [
    {"alert_type": "failure", "hostname": "castor", "repo_name": "riplay-castor", "...": "..."},
    {"alert_type": "overdue", "hostname": "deneb", "...": "..."},
    {"alert_type": "missing", "hostname": "lyra", "...": "..."}
  ]
}
```

---

### `GET /api/v1/backup/history/{repo_id}`

Historique des 90 derniers runs d'un repo.

---

### `GET /api/v1/opencve/alerts`

Alertes OpenCVE (veille CVE, paginable).

| Parametre | Type | Description |
|-----------|------|-------------|
| severity | string | Filtre par severite |

**Response:**
```json
{
  "items": [
    {"id": "uuid", "cve_id": "CVE-2026-12345", "vendor": "nginx", "product": "nginx", "title": "...", "cvss_v3": 8.1, "severity": "high", "created_at": "..."}
  ],
  "total": 234
}
```

---

### `GET /api/v1/opencve/impact`

Correlation : quels assets de l'infrastructure sont touches par les alertes OpenCVE.

| Parametre | Type | Description |
|-----------|------|-------------|
| cve_id | string | Filtre par CVE specifique (optionnel) |

**Response:**
```json
{
  "items": [
    {"cve_id": "CVE-2026-12345", "hostname": "vega", "pkg_name": "nginx", "installed_ver": "1.26.0", "...": "..."}
  ]
}
```

---

### `GET /api/v1/opencve/subscriptions`

Liste des vendors/products surveilles.

### `POST /api/v1/opencve/subscriptions`

Ajouter une souscription.

**Request Body:**
```json
{"vendor": "nginx", "product": "nginx"}
```

---

### `GET /api/v1/sca/`

Resultats SCA (filtrable par hostname, policy_id).

| Parametre | Type | Description |
|-----------|------|-------------|
| hostname | string | Filtre par hostname (ILIKE) |
| policy_id | string | Filtre par ID de policy |

---

### `GET /api/v1/sca/summary`

Score SCA moyen par node.

**Response:**
```json
{
  "global_avg_score": 68.5,
  "nodes": [
    {"hostname": "castor", "node_id": "uuid", "avg_score": 52.3, "total_passed": 245, "total_failed": 98, "policy_count": 3, "last_scan": "..."}
  ]
}
```

---

### `GET /api/v1/sca/{node_id}`

Detail SCA d'un node (toutes les policies).

---

### `GET /api/v1/settings/alerts`

Configuration actuelle des alertes.

**Response:**
```json
{
  "cve_severity_threshold": "high",
  "matrix_url": "https://matrix.example.com",
  "matrix_token": "...",
  "matrix_room_cve": "!...:matrix.example.com",
  "alert_email": "admin@example.com"
}
```

---

### `PUT /api/v1/settings/alerts`

Modifier la configuration des alertes.

**Cles autorisees :** `cve_severity_threshold`, `matrix_url`, `matrix_token`, `matrix_room_cve`, `matrix_room_security`, `alert_email`, `smtp_host`, `smtp_from`

**Request Body:**
```json
{"cve_severity_threshold": "critical", "alert_email": "admin@example.com"}
```

**Response:**
```json
{"status": "ok", "updated": 2}
```

---

## Sources de donnees et frequences

| Source | Script | Frequence | Endpoint CMDB |
|--------|--------|-----------|---------------|
| Ansible inventaire | `collect.yml` (bastion) | Cron 6h | POST /nodes/report |
| Restic backup | `restic-backup.sh` (chaque node) | Cron 21h01 UTC | POST /backup/report |
| Trivy containers | `sync_trivy.sh` (vega) | Cron 12h | POST /cves/report |
| Wazuh vulns | `sync_wazuh.py` (container) | Boucle 6h | POST /cves/report |
| Wazuh SCA | `sync_wazuh.py` (container) | Boucle 6h | POST /sca/report |
| OpenCVE veille | `sync_opencve.py` (container) | Boucle 1h | POST /opencve/webhook/batch |
| Backup alertes | `check_backup_alerts.sh` | Cron 8h | GET /backup/alerts |

## Reseau

```
Collecte machine-to-machine :  WG1 10.0.1.1:8000
Acces frontend interne :       WG0 10.0.0.1:3000
HTTPS public :                 cmdb.example.com (Traefik + Authelia)
Sync interne (Docker) :        cmdb_internal (api ↔ postgres)
Sync Wazuh/OpenCVE :           observability_net (172.20.0.x)
```
