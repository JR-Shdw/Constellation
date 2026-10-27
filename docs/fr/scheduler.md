# Scheduler

Scheduler integre fonctionnant en boucle asyncio dans le process API. Utilise des expressions cron et PostgreSQL `FOR UPDATE SKIP LOCKED` pour la securite multi-worker.

## Types de jobs

### `woodpecker_pipeline`

Declenche un pipeline Woodpecker CI. Le `repo_name` doit matcher le `full_name` dans Woodpecker.

```json
{
  "repo_name": "youruser/cmdb",
  "branch": "main",
  "variables": {"PLAYBOOK": "collect"}
}
```

Le scheduler appelle l'API Woodpecker — les etapes du pipeline sont definies dans `.woodpecker/` du repo.

### `gitlab_pipeline`

Declenche un pipeline GitLab CI. Le `repo_name` est le path du projet (ex: `group/project`).

```json
{
  "repo_name": "shdw/infra",
  "branch": "main",
  "variables": {"ENVIRONMENT": "prod"}
}
```

### `http_request`

Appelle un endpoint HTTP. Les URLs relatives (`/api/...`) sont resolues vers `http://localhost:8000` avec auth Bearer automatique via `secret_key`.

```json
{
  "method": "POST",
  "url": "/api/v1/cicd/workers/sync",
  "expected_status": [200]
}
```

URL externe avec headers personnalises :

```json
{
  "method": "GET",
  "url": "https://external.api/health",
  "headers": {"X-Token": "abc"},
  "expected_status": [200, 204]
}
```

## Jobs predefinis

6 jobs crees par defaut (desactives, activer via l'UI) :

| Job | Type | Cron | Description |
|-----|------|------|-------------|
| `ansible-collect` | woodpecker_pipeline | `0 2 * * *` | Inventaire Ansible quotidien |
| `trivy-scan-nodes` | woodpecker_pipeline | `0 3 * * *` | Scan CVE nodes quotidien |
| `trivy-scan-images` | woodpecker_pipeline | `0 4 * * *` | Scan CVE images quotidien |
| `woodpecker-sync` | http_request | `0 */4 * * *` | Sync workers Woodpecker |
| `backup-check` | http_request | `0 */6 * * *` | Check alertes backup |
| `cve-auto-resolve` | http_request | `0 6 * * 1` | Auto-resolve CVEs hebdomadaire |

## Fonctionnalites

- **Expressions cron** : format standard 5 champs (`min hour dom mon dow`)
- **Timeout** : configurable par job (defaut 300s)
- **Retries** : nombre max configurable avec delai entre tentatives
- **Protection overlap** : optionnelle, empeche de lancer un job si le precedent tourne encore
- **Notifications** : Matrix/email/webhooks sur echec final ou timeout
- **Trigger manuel** : lancer n'importe quel job a la demande depuis l'UI
- **Historique** : log complet avec statut, duree, erreurs, liens pipelines

## Endpoints API

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/scheduler/jobs` | Liste des jobs avec stats |
| POST | `/api/v1/scheduler/jobs` | Creer un job |
| GET | `/api/v1/scheduler/jobs/{id}` | Detail job + runs recents |
| PUT | `/api/v1/scheduler/jobs/{id}` | Modifier un job |
| DELETE | `/api/v1/scheduler/jobs/{id}` | Supprimer un job |
| POST | `/api/v1/scheduler/jobs/{id}/toggle` | Activer/desactiver |
| POST | `/api/v1/scheduler/jobs/{id}/trigger` | Trigger manuel |
| GET | `/api/v1/scheduler/runs` | Historique des runs (pagine) |
| GET | `/api/v1/scheduler/stats` | Stats agregees |
