# Constellation — Infrastructure Security & Asset Management Platform

## Projet

Constellation : CAASM open-source — inventaire d'assets, gestion des vulnérabilités, visibilité de la surface d'attaque et automation pour infrastructure self-hosted.
FastAPI (Python 3.12) + PostgreSQL 18 + Frontend Vanilla JS + Traefik/Authelia.
Déployé sur **vega** (WG 10.0.0.1). ~30 600 LOC (21 928 Python + 8 696 JS).

## Stack technique

| Composant       | Techno                                       |
|-----------------|----------------------------------------------|
| Backend         | FastAPI, SQLAlchemy async, asyncpg, Pydantic |
| Frontend        | Vanilla JS (ES6 modules), Nginx Alpine       |
| Base de données | PostgreSQL 18-trixie                       |
| Auth            | SSO proxy requis (Authelia, Authentik, Keycloak) + Bearer tokens |
| Reverse proxy   | Traefik, Nginx, Caddy... (au choix)          |
| Scans           | Trivy (CVE + misconf + secrets), Wazuh (SCA + CVE) |
| CVE intel       | OpenCVE v2 (self-hosted)                     |
| Backup          | Restic (monitoring via API)                  |
| Forges          | Gitea, Forgejo, GitLab (connecteurs universels) |
| CI/CD           | Woodpecker, GitLab CI (connecteurs universels) |
| Registries      | DockerHub, GHCR, GitLab Registry, Harbor (connecteurs) |
| Messaging       | Matrix (natif) + webhooks génériques (Mattermost, Rocket.Chat, Slack, Discord, ntfy) |
| Deployment      | Portainer (image pull), Woodpecker/GitLab pipelines |
| Lint/Format     | ruff (check + format)                        |
| Tests           | pytest, pytest-asyncio, httpx (ASGI)         |

## Structure du projet

```
api/                  Backend FastAPI
  app/main.py         Point d'entrée, migration schema au démarrage (advisory lock)
  app/config.py       Settings Pydantic (env vars via pydantic-settings)
  app/auth.py         Double auth : Authelia header + Bearer token
  app/audit.py        Audit log + UUID validation
  app/notify.py       Notifications Matrix + email (CVE alerts + automation)
  app/database.py     Session async SQLAlchemy
  app/routes/         52 modules de routes — 25 top-level + 27 dans 3 sous-paquets (collect/, read/, cicd/) (voir section Routes)
  app/models/         Pydantic schemas (schemas.py)
  app/connectors/     Connecteurs universels : forge (Gitea, Forgejo, GitLab),
                      CI (Woodpecker, GitLab CI), registry (DockerHub, GHCR, GitLab, Harbor)
  app/utils/          portainer.py (client async httpx)
  Dockerfile          python:3.12-slim, uvicorn 4 workers

frontend/             SPA Vanilla JS (pas de build step)
  index.html          Point d'entrée HTML unique
  js/app.js           Router hash-based + imports ES6
  js/api.js           Helpers : api() avec cache stale-while-revalidate, esc(), timeAgo(), paginator()
  js/views/           19 vues (voir section Frontend)
  js/panels/          6 panneaux détail (node, cve, image, package, os, impact)
  css/style.css       CSS unique avec variables (--green, --red, --accent, --bg-card...)
  nginx.conf          SPA routing + security headers + gzip + proxy /api/ → api:8000

tools/                Scripts de synchronisation (Docker container)
  sync_opencve.py         OpenCVE → CMDB (toutes les 2h, incrémental)
  sync_opencve_full.py    Import complet OpenCVE avec resume
  sync_wazuh.py           Wazuh agents → CMDB (toutes les 6h)
  sync_woodpecker.py      Woodpecker repos/pipelines/workers + Gitea repos → CMDB
  sync_trivy.sh           Rapports Trivy → CMDB
  restic-backup.sh        Monitoring backup Restic
  mail_backup_parser.py   Parse emails alertes backup
  check_backup_alerts.sh  Monitoring pannes backup
  Dockerfile              python:3.12-slim-bookworm
  entrypoint.sh           Loop runner (SYNC_INTERVAL_SECONDS)

scripts/              Scripts opérationnels
  deploy.sh           Déploiement idempotent (sync + migrate + build + restart)
  scan-images.sh      Scan Trivy des images CMDB → push CVE reports
  publish-github.sh   Publication sanitisée vers GitHub (IPs, domaines, hostnames)

ansible/              Collecte d'inventaire
  playbooks/          collect, scan_trivy, scan_misconf, collect_backup_logs, check_api
  roles/              collect_inventory (OS, packages, containers → POST /nodes/report)
  inventory/          hosts.ini (production)
  woodpecker_ci/      Déploiement agents Woodpecker (sous-dossier)

opencve/              Stack OpenCVE v2 self-hosted (Airflow + PG + Redis)
tests/                pytest — 10 modules, 26+ tests
schema.sql            Schema PG complet (48 tables, 15 views, 125 indexes, idempotent)
```

## Routes API (52 modules, 207 endpoints)

| Module              | Préfixe                  | Rôle                                                    |
|---------------------|--------------------------|---------------------------------------------------------|
| `collect.py`        | `/api/v1`                | Ingestion nodes + CVEs + secrets (Ansible, collect_token)|
| `read.py`           | `/api/v1`                | Lecture : nodes, packages, containers, CVEs, stats, search |
| `backup.py`         | `/api/v1/backup`         | Rapports Restic, summary, alerts                        |
| `opencve.py`        | `/api/v1/opencve`        | Webhooks, alerts, impact, subscriptions                 |
| `sca.py`            | `/api/v1/sca`            | Wazuh SCA compliance                                    |
| `scan.py`           | `/api/v1/scan`           | Agrégats scan status                                    |
| `misconf.py`        | `/api/v1`                | Misconfigurations Trivy                                 |
| `repositories.py`   | `/api/v1/repositories`   | CRUD repos Docker, checks versions DockerHub/GHCR       |
| `pkg_repositories.py`| `/api/v1/pkg-repos`     | CRUD repos paquets OS (APT, DNF, Pacman) + seed officiel|
| `pkg_updates.py`    | `/api/v1/pkg-updates`    | Paquets vulnérables agrégés, summary, filtres           |
| `findings.py`       | `/api/v1/findings`       | Patch status CVE (host + container)                     |
| `automation.py`     | `/api/v1/automation`     | Policies CRUD, matching, execution engine, logs         |
| `cicd.py`           | `/api/v1/cicd`           | Repos, pipelines, workers (ingestion + lecture + trigger) |
| `deployments.py`    | `/api/v1/deployments`    | CRUD + preflight + state machine (draft→approved→running) |
| `managers.py`       | `/api/v1/managers`       | Portainer CRUD, test connexion, pull/list images        |
| `scheduler.py`      | `/api/v1/scheduler`      | Jobs CRUD, trigger, toggle, runs history, stats         |
| `settings.py`       | `/api/v1/settings`       | Seuils alertes, SSO/O.U., webhooks, features, config UI |
| `heartbeat.py`      | `/api/v1/heartbeat`      | Ping nodes, status, check address                       |

## Frontend (26 vues + 6 panneaux)

| Vue               | Page                                                      |
|-------------------|-----------------------------------------------------------|
| `dashboard.js`    | KPIs + vue d'ensemble                                     |
| `heartbeat.js`    | Uptime, trends (CVE mitigation, backup, automation), période 1d→1y |
| `nodes.js`        | Inventaire (bare metal, VM, containers, workstations)     |
| `packages.js`     | Paquets OS + versions                                     |
| `updates.js`      | Paquets vulnérables (CVE), fix status, severity, nodes    |
| `repositories.js` | Repos paquets OS (Debian, Ubuntu, RHEL, Rocky, Arch, AIX) |
| `containers.js`   | Containers Docker + classification exposition             |
| `crepositories.js`| Repos Docker (C.Repositories), checks versions            |
| `cves.js`         | CVEs avec workflow (open, mitigated, ignored, resolved)   |
| `exposure.js`     | Matrice exposition réseau (internet, WG, Docker, localhost) |
| `misconf.js`      | Misconfigurations Trivy + scoring compliance              |
| `compliance.js`   | Audit trail + dashboard conformité                        |
| `secrets.js`      | Secrets détectés (Trivy) — host + containers, masqués     |
| `backups.js`      | Monitoring Restic, alertes pannes                         |
| `opencve.js`      | Subscriptions CVE, propagation KEV                        |
| `versioning.js`   | Repos Git avec détection CI/CD, branches, pipeline status |
| `pipelines.js`    | Stats CI/CD, repos, runs récents Woodpecker               |
| `deployments.js`  | Déploiements : actifs, création, historique (3 onglets)   |
| `managers.js`     | Portainer : liste, ajout, images, pull (2 onglets)        |
| `automation.js`   | Policies automation + logs exécution (3 onglets)          |
| `scheduler.js`    | Jobs planifiés : liste, création, historique (2 onglets)  |
| `settings.js`     | Alertes, CVE, CI/CD, SSO/O.U., Features, Dev (6 onglets) |

**Pattern frontend** : chaque vue exporte `renderXxx(el)`. Les fonctions onclick sont exposées via `window.fn` dans `app.js`. Onglets via `window.xxxTab` + `loadView()`.

## Base de données (48 tables, 15 vues, 125 indexes)

### Tables principales
- `nodes` — Inventaire infra (hostname, type, OS, arch, environment)
- `packages` — Paquets OS par node
- `containers` — Containers Docker (image, tag, exposure, Traefik, Authelia, GeoIP)
- `cve_host_packages` — CVEs paquets OS (source: Wazuh/Trivy)
- `cve_containers` — CVEs containers (source: Trivy)
- `misconfigurations` — Règles misconf Trivy
- `cve_status` — Workflow CVE (open, mitigated, ignored, resolved)
- `backup_repositories` — Repos Restic
- `backup_runs` — Historique exécutions backup
- `secrets_detected` — Secrets Trivy (host + containers, match masqué, image, target_type)
- `repositories` — Repos Docker (DockerHub, GHCR, GitLab, Harbor)
- `opencve_subscriptions` — Produits CVE surveillés
- `opencve_alerts` — Alertes CVE (KEV, NVD, seuil sévérité)
- `sca_results` — Résultats SCA Wazuh

### Tables automation + CI/CD
- `automation_policies` — Règles (event + conditions → action)
- `automation_log` — Journal d'exécution policies
- `cicd_repositories` — Métadonnées repos (Gitea, Forgejo, GitLab — colonne `forge`)
- `cicd_pipelines` — Runs CI/CD (Woodpecker, GitLab — colonne `ci_system`)
- `cicd_workers` — Runners/agents CI (colonne `ci_system` + `external_id`)
- `cicd_servers` — Serveurs CI/CD enregistrés (woodpecker, gitea, gitlab, forgejo)
- `container_managers` — Endpoints Portainer (url, token, status)
- `deployments` — Demandes déploiement avec workflow
- `scheduler_jobs` — Jobs planifiés (cron, type, config, next_run_at)
- `scheduler_runs` — Historique d'exécution (status, duration, result)
- `notification_webhooks` — Webhooks génériques (Mattermost, Rocket.Chat, Slack, Discord, ntfy…)

### Tables système
- `alert_settings` — Configuration seuils (stocké en DB pour UI)
- `alert_sent` — Dédup alertes envoyées
- `audit_log` — Actions utilisateur + API

### Views (18+)
- `v_all_cves`, `v_node_summary`, `v_backup_status` — Agrégats principaux
- `v_cicd_latest` — Dernier pipeline par repo
- `v_cicd_stats_30d` — Taux succès + durée 30 jours
- `v_cicd_workers_status` — Workers + node info + pipelines running
- `v_deployment_summary` — Deployments + worker + manager info
- `v_scheduler_summary` — Jobs + dernière run + stats 30j + is_running
- Fonction `cve_score()` — Scoring contextuel (CVSS + exploitabilité + exposition)

### Conventions DB
- Schema **idempotent** : tout en `IF NOT EXISTS` / `CREATE OR REPLACE`
- Pattern **upsert** : `ON CONFLICT DO UPDATE` pour la collecte
- Paramètres nommés (`:param`) uniquement — jamais de f-string dans le SQL
- `CAST(:id AS uuid)` pour les UUID en paramètres
- Pas de migrations séparées — `schema.sql` est la source de vérité unique

## Conventions

### Code Python
- **ruff** pour lint + format (remplace black/flake8/isort)
- **Type hints** progressifs (pas obligatoire partout)
- **Pydantic** pour validation et config (`pydantic-settings` pour .env)
- **async/await** partout (SQLAlchemy async + asyncpg)
- Line length : 88 (`pyproject.toml`)
- Target : Python 3.12
- `ruff check` ET `ruff format --check` doivent passer
- Modèles séparés : `XxxCreate` (POST), `XxxPatch` (PUT, tous champs optionnels)

### Sécurité / Auth
- **Deux modes d'auth** :
  - `require_collect_token()` : Bearer token write-only (Ansible, scripts)
  - `require_permission(scope, mode)` : Granular guard pour tous les endpoints (13 scopes × r/w)
- **SSO Roles (O.U.)** : groupes SSO mappés vers rôles CMDB (admin, ops, viewer)
  - Builtins : `admin`, `admins`, `secops` → admin | `ops` → ops | `viewer` → viewer
  - Configurable via Settings → SSO / O.U. (stocké en DB `alert_settings.sso_group_mappings`)
  - Rechargé en mémoire au save + au démarrage de l'API
  - Supporte AD, LDAP, Authelia (Remote-Groups), Authentik (X-Auth-Groups), Keycloak (X-Forwarded-Groups)
  - Rôle le plus élevé gagne si l'utilisateur a plusieurs groupes (admin > ops > viewer)
  - SSO admin = full access, ops/viewer = read-only (mode `w` bloqué)
- **Privilege separation** : collect_token ne peut PAS lire, secret_key peut tout faire
- **Tokens DB** : HMAC-SHA512 (per-instance `TOKEN_HMAC_KEY`), affichés une seule fois à la création
- **13 scopes** : collect, read, backup, cicd, deployments, managers, automation, repositories, findings, misconf, settings, tokens, scheduler
- Trusted proxies : réseaux 172.16-20.x.x uniquement
- API collecte sur WG1 (10.0.1.x), frontend sur WG0 (10.0.0.x)
- `validate_uuid()` + `log_action()` pour tout audit
- Tokens masqués (hash tronqué 12 chars) dans les réponses API

### Modèle de sécurité réseau

> **⚠ Ne JAMAIS exposer un CMDB sur Internet.** Un CMDB contient la cartographie
> complète de l'infra (paquets, CVEs, exposition réseau, topologie containers,
> résultats de scans). C'est le plan d'attaque rêvé pour un attaquant.
> Accès uniquement via VPN (WireGuard) + SSO proxy (Authelia/Authentik/Keycloak).
>
> **Protections intégrées contre les menaces internes :**
> - **Anti brute-force offline** : tokens hachés HMAC-SHA512 avec clé per-instance —
>   un dump DB seul est inutile (impossible de calculer HMAC sans `TOKEN_HMAC_KEY`).
>   Même avec DB + clé, les tokens font 43 chars aléatoires (~10^57 combinaisons)
> - **Séparation des privilèges** : un token compromis a des droits limités (scope:mode)
> - **Révocation instantanée** : désactiver un token suspect sans toucher aux autres
> - **Audit log complet** : traçabilité de toutes les actions sensibles
> - **Anti header forgery** : `Remote-User` accepté uniquement depuis le réseau Docker
>   du reverse proxy (172.16-20.x) — forge impossible depuis un autre réseau
>
> L'exposition publique n'est **pas un cas d'usage supporté**.

### CORS Middleware
- Configuré dans `api/app/main.py` via `CORSMiddleware`
- Origins contrôlées par `ALLOWED_ORIGINS` dans `.env` (défaut: `[]` = aucune origin autorisée)
- Format : liste séparée par des virgules (ex: `https://cmdb.example.com,https://admin.example.com`)
- Parsé par `field_validator` dans `config.py`

### Docker
- Compose v2, images **debian-slim** préférées
- `versions.env` : versions d'images pinnées (commité dans git)
- `.env` : secrets et config locale (JAMAIS commité)
- Réseau interne `cmdb_internal` entre les services
- `traefik_proxy` pour le reverse proxy
- `observability_net` pour OpenCVE + Wazuh

### Git / CI
- Conventional commits (`feat:`, `fix:`, `style:`, `docs:`)
- Branche `main` pour les docs et hotfixes
- Feature branches pour les nouvelles fonctionnalités
- Merge humain uniquement après validation CI
- **Ne jamais `git add -A`** : toujours stager des fichiers spécifiques
- **Pas de tag Co-Authored-By Claude** dans les commits

### Tests
```bash
make test           # pytest complet (26+ tests, PG réel)
make lint           # ruff check + ruff format --check
make lint-fix       # auto-fix
```
- Tests async avec `pytest-asyncio` + `httpx` ASGITransport
- Base PG de test fraîche par pipeline (service `postgres-test` dans CI)
- `conftest.py` : applique schema.sql via `asyncpg` direct

## Pipelines Woodpecker

| Pipeline      | Trigger            | Rôle                                       |
|---------------|--------------------|---------------------------------------------|
| validate.yml  | push, PR           | lint + format + test + compose check + file check |
| deploy.yml    | push main          | build + deploy sur vega (label: host=vega) |
| scan.yml      | cron 3h, push main | Trivy CVE scan des images CMDB → push API   |

Note : `publish.yml` (GitHub) sur branche `publish-github` en attente de clé SSH.

## Makefile (cibles principales)

```bash
# Stack
make up / down / build / restart    # Stack CMDB
make logs / ps / db-shell           # Diagnostic
make db-backup                      # Backup base PG

# Collecte
make collect                        # Ansible collecte inventaire (tous hosts)
make collect-trivy                  # Scan Trivy nodes
make collect-misconf                # Scan misconfigurations
make collect-backup                 # Collecte logs Restic

# Sync
make opencve-sync                   # Sync incrémentale OpenCVE (24h)
make opencve-full                   # Import complet OpenCVE
make wazuh-sync                     # Sync agents Wazuh
make scan-images                    # Scan images CMDB + push CVE

# Dev/CI
make lint                           # ruff check + format check
make lint-fix                       # auto-fix
make test                           # pytest complet
make deploy                         # Déploiement complet (sync + migrate + build + restart)
make secrets                        # Générer .env avec clés aléatoires
```

## Services Docker (docker-compose.yml)

| Service       | Image                    | Rôle                      | Réseau                     |
|---------------|--------------------------|---------------------------|----------------------------|
| postgres      | postgres:18-trixie     | Base de données           | cmdb_internal              |
| api           | python:3.12-slim (build) | Backend FastAPI            | cmdb_internal + traefik    |
| frontend      | nginx:stable-alpine      | SPA + reverse proxy        | cmdb_internal + traefik    |
| sync-opencve  | python:3.12-slim (build) | Sync OpenCVE (toutes 2h)  | cmdb_internal + observability |
| sync-wazuh    | python:3.12-slim (build) | Sync Wazuh (toutes 6h)    | cmdb_internal + observability |

## Variables d'environnement clés

Voir `env.example` pour la liste complète. Les essentiels :
- `POSTGRES_PASSWORD` : mot de passe PG
- `API_SECRET_KEY` : clé admin API (lecture + écriture)
- `COLLECT_TOKEN` : token de collecte (Ansible/scripts, écriture seule)
- `ALLOWED_ORIGINS` : CORS origins (virgule-séparées, défaut vide)
- `WG1_IP` / `WG_IP` : IPs WireGuard (10.0.1.1 / 10.0.0.1)
- `CMDB_DOMAIN` : domaine public (Traefik)
- `WOODPECKER_URL` / `WOODPECKER_TOKEN` : API Woodpecker (optionnel)
- `GITEA_URL` / `GITEA_TOKEN` : API Gitea (optionnel)
- `VAULT_URL` / `VAULT_TOKEN` : rhorizon secrets vault (optionnel)
- `OPENCVE_*` : Connexion OpenCVE
- `WAZUH_*` : Connexion Wazuh + OpenSearch

## Intégration rhorizon (Phase 3)

### Principe

Le CMDB utilise rhorizon comme source de secrets au lieu des variables d'environnement `.env`.
Au démarrage, `_load_vault_secrets()` récupère les secrets depuis le vault via Bearer token.
Si le vault n'est pas configuré, le CMDB fonctionne en mode legacy (`.env`).

### Guard vault sealed

Quand le vault est configuré, **toute exécution est bloquée si le vault est sealed** :
- **Scheduler** : jobs échouent avec `Vault sealed — execution blocked`
- **CI/CD trigger** : `POST /cicd/pipelines/trigger` → HTTP 503
- **Deployments** : `POST /deployments/{id}/execute` → HTTP 503
- **Automation** : `_execute_action()` bloquée (sauf `notify` qui n'utilise pas de secrets CI)
- **Preflight** : check `vault_unsealed` ajouté aux vérifications pré-vol

### Secrets mappés (vault → config)

| Secret vault           | Setting CMDB         |
|------------------------|----------------------|
| `cmdb-secret-key`      | `secret_key`         |
| `cmdb-collect-token`   | `collect_token`      |
| `cmdb-token-hmac-key`  | `token_hmac_key`     |
| `cmdb-woodpecker-token`| `woodpecker_token`   |
| `cmdb-gitea-token`     | `gitea_token`        |
| `cmdb-gitlab-token`    | `gitlab_token`       |
| `cmdb-forgejo-token`   | `forgejo_token`      |
| `cmdb-opencve-password`| `opencve_password`   |

### Fichiers impliqués

| Fichier | Rôle |
|---|---|
| `api/app/connectors/vault.py` | Client vault (status cache TTL 15s, guard, VaultSealedError) |
| `api/app/main.py` | `_load_vault_secrets()` au startup (lifespan) |
| `api/app/routes/settings.py` | `GET /vault/status` + `POST /vault-check` |
| `api/app/routes/scheduler.py` | Guard avant trigger manuel |
| `api/app/routes/cicd.py` | Guard avant trigger pipeline |
| `api/app/routes/deployments.py` | Guard avant execute + preflight check |
| `api/app/routes/automation.py` | Guard avant _execute_action (sauf notify) |
| `api/app/scheduler.py` | Guard avant execute_job (boucle background) |

### Configuration

Deux options pour configurer vault URL/token :
1. **Variables d'environnement** : `VAULT_URL` et `VAULT_TOKEN` dans `.env`
2. **UI Settings** : onglet CI/CD → section rhorizon (stocké en DB, chiffré)

Le token vault doit avoir le scope `{"secrets": "r", "namespaces": ["cmdb"]}`.

## Moteur d'automation

Le moteur d'automation évalue les événements contre les policies configurées (first-match-wins par `priority DESC`) et exécute les actions automatiquement si `auto_execute=true`.

### Flux : événement → policy → action

```
Ingestion endpoint (collect, backup, cicd, repos, misconf, scan)
    → run_evaluation(event, db)
        → charge toutes les policies enabled
        → matche event contre filtres (AND entre tous)
        → première policy matchée → log + exécute action
```

### Triggers (10 événements câblés)

| Trigger | Source endpoint | Condition de déclenchement |
|---|---|---|
| `cve_detected` | `POST /cves/report` | CVE severity critical ou high |
| `backup_overdue` | `POST /backup/report` | Status error, warning ou failed |
| `worker_offline` | `POST /cicd/workers/report` | Worker status offline |
| `pipeline_failure` | `POST /cicd/pipelines/report` | Pipeline status failure |
| `image_update_available` | `POST /repositories/{id}/check` + `/check-all` | Nouvelle version détectée |
| `misconf_detected` | `POST /misconfigurations/report` | Misconfiguration critical ou high |
| `exposure_change` | `POST /nodes/report` | Container change d'exposition réseau |
| `deploy_requested` | `POST /deployments/{id}/submit` | Deployment soumis (draft→pending) |
| `scan_stale` | `GET /scan/status` | Node non scanné depuis 7+ jours |
| `update_available` | — | Alias de `image_update_available` (packages: futur) |

### Filtres (conditions de match)

Tous optionnels. Vide = match tout. Logique **AND** entre filtres.

| Filtre | Type | Syntaxe | Exemple |
|---|---|---|---|
| `match_hostname` | texte | LIKE avec `%` wildcard | `altair`, `%backup%` |
| `match_container` | texte | LIKE avec `%` wildcard | `traefik`, `%postgres%` |
| `match_image` | texte | LIKE avec `%` wildcard | `nginx:%`, `%/cmdb-%` |
| `match_package` | texte | LIKE avec `%` wildcard | `openssl`, `linux-headers%` |
| `match_cve_id` | texte | LIKE avec `%` wildcard | `CVE-2024-%`, `CVE-2024-3094` |
| `match_severity` | liste | valeurs exactes | `["critical"]`, `["critical","high"]` |
| `match_environment` | liste | valeurs exactes | `["production"]`, `["production","staging"]` |
| `match_exposure` | liste | valeurs exactes | `["internet"]`, `["internet","private_network"]` |

Valeurs possibles : severity (`critical`, `high`, `medium`, `low`), environment (`production`, `staging`, `development`, `lab`), exposure (`internet`, `private_network`, `localhost`, `docker_internal`).

### Actions (7 définies, 4 exécutées automatiquement)

| Action | auto_execute=true | Effet |
|---|---|---|
| `notify` | ✓ | Envoi Matrix + email, room routée par trigger type |
| `create_deployment` | ✓ | INSERT deployment status=pending + notification |
| `pull_image` | ✓ | Appel Portainer API (premier manager connecté) + notification |
| `ignore` | — | Log en status `ignored`, rien d'autre |
| `manual_validation` | — | Log en `pending`, attente approve/skip dans l'UI |
| `auto_update` | — | *Défini, pas encore implémenté* |
| `rescan` | — | *Défini, pas encore implémenté* |

### Routage Matrix automatique

| Trigger | Room DB setting |
|---|---|
| `cve_detected`, `update_available`, `image_update_available` | `matrix_room_cve` |
| Tous les autres | `matrix_room_security` |

Override possible par policy via le champ `notify_room`.

### Champs policy

| Champ | Requis | Description |
|---|---|---|
| `name` | oui | Nom unique |
| `trigger_type` | oui | Un des 10 triggers |
| `action` | oui | Une des 7 actions |
| `priority` | non | Entier, plus haut = évalué en premier (défaut: 0) |
| `enabled` | non | true/false (défaut: true) |
| `auto_execute` | non | true = exécution immédiate (défaut: false) |
| `notify_room` | non | Room Matrix override |
| `config` | non | JSON libre pour `create_deployment` : `{"deploy_type":"...","repo_name":"...","branch":"..."}` |
| `match_*` | non | 8 filtres optionnels (voir tableau) |

### Fichiers impliqués

| Fichier | Rôle |
|---|---|
| `api/app/routes/automation.py` | Matcher, CRUD policies, `run_evaluation()`, `_execute_action()` |
| `api/app/notify.py` | `notify_cve()` (CVE spécifique) + `send_automation_notification()` (générique) |
| `api/app/routes/collect.py` | Fire `cve_detected` + `exposure_change` |
| `api/app/routes/backup.py` | Fire `backup_overdue` |
| `api/app/routes/cicd.py` | Fire `worker_offline` + `pipeline_failure` |
| `api/app/routes/repositories.py` | Fire `image_update_available` |
| `api/app/routes/misconf.py` | Fire `misconf_detected` |
| `api/app/routes/deployments.py` | Fire `deploy_requested` |
| `api/app/routes/scan.py` | Fire `scan_stale` |

### Exemples de policies

```json
// Notifier toute CVE critique en production
{
  "name": "cve-critical-prod",
  "trigger_type": "cve_detected",
  "action": "notify",
  "match_severity": ["critical"],
  "match_environment": ["production"],
  "auto_execute": true,
  "priority": 100
}

// Ignorer les CVE medium en lab (priorité haute = évalué avant)
{
  "name": "ignore-medium-lab",
  "trigger_type": "cve_detected",
  "action": "ignore",
  "match_severity": ["medium"],
  "match_environment": ["lab"],
  "priority": 200
}

// Auto-pull image quand update dispo sur containers internet
{
  "name": "auto-pull-internet",
  "trigger_type": "image_update_available",
  "action": "pull_image",
  "match_exposure": ["internet"],
  "auto_execute": true,
  "priority": 80
}

// Notifier quand un backup échoue sur les serveurs backup
{
  "name": "backup-alert",
  "trigger_type": "backup_overdue",
  "action": "notify",
  "match_hostname": "%backup%",
  "auto_execute": true,
  "priority": 90
}
```

## Performance et cache

### Backend — cache in-memory TTL
Cache Python `dict` avec `time.monotonic()` dans `read.py` et `cicd.py`.
Évite de re-exécuter les requêtes PG lourdes (vues, agrégats) à chaque chargement de page.

| Clé           | TTL  | Endpoint         | Contenu                          |
|---------------|------|------------------|----------------------------------|
| `stats`       | 30s  | `GET /stats`     | Dashboard KPIs (6 CTEs)          |
| `nodes_list`  | 60s  | `GET /nodes/list`| Dropdown nodes (hostname, id)    |
| `exposure`    | 45s  | `GET /exposure`  | Matrice exposition réseau        |
| `compliance`  | 45s  | `GET /compliance`| Scores compliance agrégés        |
| `cicd_stats`  | 30s  | `GET /cicd/stats`| Stats pipelines 30j + repos      |

Le cache est invalidé naturellement par expiration TTL. Pas d'invalidation explicite — acceptable car les données changent au rythme des syncs (heures).

### Frontend — stale-while-revalidate
`api()` dans `api.js` cache les réponses JSON en mémoire (Map).
- Si données < TTL : retour immédiat, pas de fetch
- Si données > TTL (stale) : retour immédiat + refetch en background silencieux
- Si pas de cache : fetch normal
- Endpoints non cachés (listes paginées, recherche) : fetch direct

| Path prefix     | TTL   |
|-----------------|-------|
| `/stats`        | 20s   |
| `/nodes/list`   | 60s   |
| `/cicd/stats`   | 25s   |
| `/scan/status`  | 30s   |

### PostgreSQL — tuning mémoire (vega : 16 GB RAM, ~1 GB libre)

Paramètres dans `docker-compose.yml` via `command:` flags :

| Paramètre | Valeur | Rôle |
|---|---|---|
| `shared_buffers` | 384 MB | Cache pages PG en RAM (alloc réelle) |
| `effective_cache_size` | 1536 MB | Hint planner (OS + PG cache, pas d'alloc) |
| `work_mem` | 16 MB | Mémoire par sort/hash (× connexions) |
| `maintenance_work_mem` | 128 MB | VACUUM, CREATE INDEX (temporaire) |
| `wal_buffers` | 12 MB | Buffer WAL écriture |
| `random_page_cost` | 1.1 | Optimisé SSD |

Conservateur car vega héberge beaucoup de containers (~15 GB utilisés).

### Nginx — compression gzip
Activé dans `nginx.conf` pour JSON, CSS, JS, texte. `gzip_min_length 256` pour éviter l'overhead sur les petites réponses. Compression typique 70-80% sur les réponses JSON.

## Connecteurs universels

Architecture en couches d'abstraction avec factories (`get_forge()`, `get_ci()`, `get_registry()`).

```
┌─────────────────────────────────────────────────────────┐
│              Remédiation / Deployment logic              │
│         (automation.py, deployments.py, scheduler.py)    │
├──────────────────────┬──────────────────────────────────┤
│   Forge Connector    │       CI/CD Connector            │
│   (repos, branches)  │   (pipelines, runners, trigger)  │
├──────────────────────┼──────────────────────────────────┤
│ GiteaForge           │ WoodpeckerCI                     │
│ ForgejoForge         │ GitLabCI                         │
│ GitLabForge          │                                  │
└──────────────────────┴──────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  Notification Channels                    │
├──────────┬──────────┬───────────────────────────────────┤
│  Matrix  │  Email   │  Webhook (N instances en DB)      │
│ (natif)  │  (SMTP)  │  Mattermost, Rocket.Chat, Slack…  │
└──────────┴──────────┴───────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│               Registry Connector                         │
├──────────┬──────────┬──────────┬────────────────────────┤
│DockerHub │   GHCR   │  GitLab  │       Harbor           │
└──────────┴──────────┴──────────┴────────────────────────┘
```

| Fichier | Rôle |
|---|---|
| `api/app/connectors/__init__.py` | Factories : `get_forge()`, `get_ci()`, `get_registry()` |
| `api/app/connectors/forge.py` | ABC `ForgeConnector` |
| `api/app/connectors/ci.py` | ABC `CIConnector` |
| `api/app/connectors/registry.py` | ABC `RegistryConnector` + 4 implémentations |
| `api/app/connectors/gitea.py` | `GiteaForge` (API v1) |
| `api/app/connectors/forgejo.py` | `ForgejoForge` (hérite GiteaForge) |
| `api/app/connectors/gitlab.py` | `GitLabForge` (API v4) |
| `api/app/connectors/woodpecker.py` | `WoodpeckerCI` (agents, pipelines, trigger) |
| `api/app/connectors/gitlab_ci.py` | `GitLabCI` (runners, pipelines, trigger) |

## Architecture décisionnelle

1. **Pas de build step frontend** — Vanilla JS ES6 modules, déployé tel quel via Nginx
2. **Schema unique idempotent** — `schema.sql` appliqué au démarrage avec advisory lock PG
3. **Ansible push model** — Pas de daemon sur les nodes, collecte via playbooks
4. **Tokens fixes** — Pas de JWT, Bearer tokens dans .env (simple et auditable)
5. **Clients API optionnels** — Si Woodpecker/Gitea/Portainer pas configurés, les endpoints lecture marchent, seuls trigger/execute renvoient 503
6. **Deployment state machine** — draft → pending → approved → running → success/failure, approbation humaine par défaut
7. **Preflight checks** — Vérification pré-vol avant exécution (worker, repo, manager)
8. **Policy-driven** — Automation par match first-match-wins (comme les règles firewall)
9. **Réseau isolé** — VPN WireGuard requis, pas d'exposition Internet directe
10. **Self-hosted** — OpenCVE, Gitea, Woodpecker, Matrix — zéro dépendance SaaS
11. **Cache à deux niveaux** — Backend TTL (Python dict) + Frontend stale-while-revalidate (JS Map), pas de Redis/Memcached nécessaire
12. **Scheduler intégré** — Boucle asyncio dans le process API, jobs en DB avec cron expressions, `FOR UPDATE SKIP LOCKED` pour multi-worker safety, exécution via Woodpecker/GitLab (pipelines) ou HTTP (API calls)

## Workflow CVE — Cycle de vie des vulnérabilités

### Principe

La décision humaine prime sur le scan automatique. Une CVE marquée "resolved" ou "mitigated" par un opérateur ne revient jamais en "open" même si Wazuh/Trivy la réimporte.

### Tables impliquées

| Table | Rôle |
|---|---|
| `cve_host_packages` | CVEs détectées sur les paquets OS (source: Trivy/Wazuh) |
| `cve_containers` | CVEs détectées sur les containers (source: Trivy) |
| `cve_status` | Décisions workflow par (node_id, cve_id) — table séparée |

### Statuts workflow (`cve_status.status`)

| Statut | Signification |
|---|---|
| `open` | Vulnérabilité active, non traitée |
| `acknowledged` | Prise en compte, en cours d'analyse |
| `in_progress` | Remédiation en cours |
| `mitigated` | Mesure compensatoire appliquée (pas de fix direct) |
| `resolved` | Paquet mis à jour ou supprimé — CVE corrigée |
| `false_positive` | Faux positif confirmé (nécessite justification) |
| `accepted_risk` | Risque accepté volontairement (nécessite justification) |

### Flux d'ingestion avec persistance des décisions

```
Trivy/Wazuh scan
    ↓
POST /cves/report
    ↓
Upsert cve_host_packages / cve_containers
(status non touché par ON CONFLICT — préservé)
    ↓
Sync workflow : UPDATE ... SET status = cve_status.status
WHERE cve_status.status != 'open'
(les décisions utilisateur sont réappliquées)
    ↓
Cleanup stale : DELETE WHERE status = 'open' AND scanned_at < 5min
(seules les CVEs open non re-scannées sont supprimées)
```

### Règles de persistance

1. **Upsert** : `ON CONFLICT DO UPDATE` met à jour severity/cvss/fix_status mais **jamais** `status`
2. **Sync workflow** : après chaque upsert, les décisions de `cve_status` sont appliquées aux CVEs open
3. **Cleanup stale** : ne supprime que les CVEs avec `status = 'open'` — les resolved/mitigated/ignored sont préservées
4. **Réouverture** : seul un changement manuel dans l'UI peut remettre une CVE en "open"

### Chaîne de détection multi-couche

```
Trivy rootfs scan (host) ──→ cve_host_packages
Trivy image scan (container) ──→ cve_containers
Wazuh agent scan ──→ cve_host_packages (source='wazuh')
OpenCVE subscriptions ──→ opencve_alerts (alertes indépendantes)
```

OpenCVE fonctionne en parallèle : même si une CVE est "resolved" dans la CMDB, OpenCVE continue de surveiller le produit. Si le paquet vulnérable est réinstallé par erreur, OpenCVE émet une alerte indépendante.

### Fichiers impliqués

| Fichier | Rôle |
|---|---|
| `api/app/routes/collect.py` | Ingestion CVE + sync workflow + cleanup stale |
| `api/app/routes/read.py` | `PUT /cves/{id}/workflow` — set statut + justification |
| `api/app/routes/findings.py` | `PATCH /findings/host/{id}` — patch direct status/fix_status |
| `frontend/js/panels/cve.js` | UI workflow select + `setCveWorkflow()` |
| `frontend/js/views/cves.js` | Liste CVEs avec filtres workflow |

## Scheduler — Config JSON par type de job

### `woodpecker_pipeline`
Déclenche un pipeline Woodpecker. Le `repo_name` doit matcher le `full_name` dans Woodpecker.
```json
{"repo_name": "youruser/cmdb", "branch": "main", "variables": {"PLAYBOOK": "collect"}}
```

### `gitlab_pipeline`
Déclenche un pipeline GitLab CI. Le `repo_name` est le path du projet (ex: `group/project`).
```json
{"repo_name": "shdw/infra", "branch": "main", "variables": {"ENVIRONMENT": "prod"}}
```

### `http_request`
Appelle un endpoint HTTP. Les URLs relatives (`/api/...`) sont résolues vers `http://localhost:8000` avec auth Bearer secret_key automatique.
```json
{"method": "POST", "url": "/api/v1/cicd/workers/sync", "expected_status": [200]}
```
```json
{"method": "GET", "url": "https://external.api/health", "headers": {"X-Token": "abc"}, "expected_status": [200, 204]}
```
