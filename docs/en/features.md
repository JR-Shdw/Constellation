# Features

## CVE Management — lifecycle

Each CVE finding carries:

| Field | Values | Description |
|-------|--------|-------------|
| `fix_status` | `fixed_available`, `unfixed`, `not_affected`, `under_investigation` | Auto-derived from `fixed_ver` at ingest |
| `status` | `open`, `mitigated`, `ignored`, `resolved` | Finding lifecycle |
| `exploited` | bool | `true` if in CISA KEV (from OpenCVE) |
| `exploitability_context` | `likely_exploitable`, `requires_auth`, `requires_local_access`, `requires_user_interaction`, `unclear` | Infra-specific context |

### Contextual score (0-100)

| Component | Weight |
|-----------|--------|
| CVSS x 5 | 0-50 |
| Exploited (CISA KEV) | +25 |
| Internet exposure | +20 |
| Private network | +10 |
| Fix available | +8 |
| `likely_exploitable` | +5 |
| `requires_auth` | -10 |
| `requires_local_access` | -15 |
| `requires_user_interaction` | -8 |

### CVE workflow (per node)

`open` -> `acknowledged` -> `in_progress` -> `mitigated` / `false_positive` / `accepted_risk`

### Environments

Each node carries an `environment` tag: `production`, `staging`, `development`, `lab`. Filterable in CVE and Nodes views.

---

## Misconfigurations

Trivy config scan detects system issues (SSH, permissions, Docker, etc.). Filterable by severity and status.

---

## Compliance

Unified view per node combining:
- **SCA Score** — Wazuh compliance (CIS, PCI-DSS)
- **Misconfigurations** — Trivy config issues
- **Open CVEs** — unresolved vulnerabilities

---

## Automation

Policy-driven engine: events are matched against rules, first-match-wins by priority (like firewall rules).

### Triggers

`cve_detected`, `update_available`, `image_update_available`, `backup_overdue`, `scan_stale`, `exposure_change`, `misconf_detected`, `pipeline_failure`, `worker_offline`, `deploy_requested`

### Actions

| Action | Auto-executable | Effect |
|--------|-----------------|--------|
| `notify` | Yes | Matrix + Email + webhooks |
| `create_deployment` | Yes | Create deployment request |
| `pull_image` | Yes | Pull via Portainer |
| `ignore` | — | Log as ignored |
| `manual_validation` | — | Await approval in UI |
| `auto_update` | — | Planned |
| `rescan` | — | Planned |

### Filters

All optional (NULL = wildcard), AND logic between filters:

| Filter | Type | Example |
|--------|------|---------|
| `match_hostname` | LIKE | `altair`, `%backup%` |
| `match_container` | LIKE | `traefik`, `%postgres%` |
| `match_image` | LIKE | `nginx:%` |
| `match_severity` | list | `["critical", "high"]` |
| `match_environment` | list | `["production"]` |
| `match_exposure` | list | `["internet"]` |

---

## Repositories — version tracking

Tracks deployed Docker images and available updates from registries (DockerHub, GHCR, GitLab, Harbor).

Each entry carries: `current_tag`, `latest_tag_available`, `update_available`, `listen` (network exposure), `auto_update_candidate`.

```bash
curl -X POST https://cmdb.example.com/api/v1/repositories/check-all
```

---

## Alerts

- **Severity threshold**: configurable in Settings (critical/high/medium/low)
- **Channels**: Matrix (native), Email (SMTP), N generic webhooks (Mattermost, Rocket.Chat, Slack, Discord, ntfy, Gotify)
- **Deduplication**: one notification per CVE / host / channel — no flood on rescan
- **Room routing**: CVE -> matrix_room_cve, CI/CD -> matrix_room_cicd, Backup -> matrix_room_backup, Security -> matrix_room_security
