# Fonctionnalites

## Gestion des CVE — cycle de vie

Chaque finding CVE porte :

| Champ | Valeurs | Description |
|-------|---------|-------------|
| `fix_status` | `fixed_available`, `unfixed`, `not_affected`, `under_investigation` | Auto-derive de `fixed_ver` a l'ingest |
| `status` | `open`, `mitigated`, `ignored`, `resolved` | Cycle de vie du finding |
| `exploited` | bool | `true` si dans CISA KEV (depuis OpenCVE) |
| `exploitability_context` | `likely_exploitable`, `requires_auth`, `requires_local_access`, `requires_user_interaction`, `unclear` | Contexte propre a l'infra |

### Score contextuel (0-100)

| Composant | Poids |
|-----------|-------|
| CVSS x 5 | 0-50 |
| Exploite (CISA KEV) | +25 |
| Exposition internet | +20 |
| Reseau prive | +10 |
| Fix disponible | +8 |
| `likely_exploitable` | +5 |
| `requires_auth` | -10 |
| `requires_local_access` | -15 |
| `requires_user_interaction` | -8 |

### Workflow CVE (par node)

`open` -> `acknowledged` -> `in_progress` -> `mitigated` / `false_positive` / `accepted_risk`

### Environnements

Chaque node porte un tag `environment` : `production`, `staging`, `development`, `lab`. Filtrable dans les vues CVE et Nodes.

---

## Misconfigurations

Trivy config scan detecte les problemes de configuration systeme (SSH, permissions, Docker, etc.). Filtrable par severite et statut.

---

## Compliance

Vue unifiee par node combinant :
- **SCA Score** — conformite Wazuh (CIS, PCI-DSS)
- **Misconfigurations** — problemes de config Trivy
- **CVEs ouvertes** — vulnerabilites non resolues

---

## Automation

Moteur a policies : les evenements sont matches contre des regles, first-match-wins par priorite (comme des regles firewall).

### Triggers

`cve_detected`, `update_available`, `image_update_available`, `backup_overdue`, `scan_stale`, `exposure_change`, `misconf_detected`, `pipeline_failure`, `worker_offline`, `deploy_requested`

### Actions

| Action | Auto-executable | Effet |
|--------|-----------------|-------|
| `notify` | Oui | Matrix + Email + webhooks |
| `create_deployment` | Oui | Cree une demande de deploiement |
| `pull_image` | Oui | Pull via Portainer |
| `ignore` | — | Logue comme ignore |
| `manual_validation` | — | Attente approbation dans l'UI |
| `auto_update` | — | Planifie |
| `rescan` | — | Planifie |

### Filtres

Tous optionnels (NULL = wildcard), logique AND entre filtres :

| Filtre | Type | Exemple |
|--------|------|---------|
| `match_hostname` | LIKE | `altair`, `%backup%` |
| `match_container` | LIKE | `traefik`, `%postgres%` |
| `match_image` | LIKE | `nginx:%` |
| `match_severity` | liste | `["critical", "high"]` |
| `match_environment` | liste | `["production"]` |
| `match_exposure` | liste | `["internet"]` |

---

## Repositories — suivi des versions

Suivi des images Docker deployees et des mises a jour disponibles depuis les registries (DockerHub, GHCR, GitLab, Harbor).

Chaque entree porte : `current_tag`, `latest_tag_available`, `update_available`, `listen` (exposition reseau), `auto_update_candidate`.

```bash
curl -X POST https://cmdb.example.com/api/v1/repositories/check-all
```

---

## Alertes

- **Seuil de severite** : configurable dans Settings (critical/high/medium/low)
- **Canaux** : Matrix (natif), Email (SMTP), N webhooks generiques (Mattermost, Rocket.Chat, Slack, Discord, ntfy, Gotify)
- **Deduplication** : une seule notification par CVE / host / canal — pas de flood sur rescan
- **Routage rooms** : CVE -> matrix_room_cve, CI/CD -> matrix_room_cicd, Backup -> matrix_room_backup, Security -> matrix_room_security
