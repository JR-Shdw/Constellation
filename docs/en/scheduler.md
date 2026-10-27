# Scheduler

Built-in job scheduler running as an asyncio background loop in the API process. Uses cron expressions and PostgreSQL `FOR UPDATE SKIP LOCKED` for multi-worker safety.

## Job types

### `woodpecker_pipeline`

Triggers a Woodpecker CI pipeline. The `repo_name` must match the `full_name` in Woodpecker.

```json
{
  "repo_name": "youruser/cmdb",
  "branch": "main",
  "variables": {"PLAYBOOK": "collect"}
}
```

The scheduler calls the Woodpecker API — the pipeline steps are defined in `.woodpecker/` in the repo.

### `gitlab_pipeline`

Triggers a GitLab CI pipeline. The `repo_name` is the project path (e.g. `group/project`).

```json
{
  "repo_name": "shdw/infra",
  "branch": "main",
  "variables": {"ENVIRONMENT": "prod"}
}
```

### `http_request`

Calls any HTTP endpoint. Relative URLs (`/api/...`) are resolved to `http://localhost:8000` with automatic Bearer auth using `secret_key`.

```json
{
  "method": "POST",
  "url": "/api/v1/cicd/workers/sync",
  "expected_status": [200]
}
```

External URL with custom headers:

```json
{
  "method": "GET",
  "url": "https://external.api/health",
  "headers": {"X-Token": "abc"},
  "expected_status": [200, 204]
}
```

## Preset jobs

6 jobs are created by default (disabled, enable via UI):

| Job | Type | Cron | Description |
|-----|------|------|-------------|
| `ansible-collect` | woodpecker_pipeline | `0 2 * * *` | Daily Ansible inventory |
| `trivy-scan-nodes` | woodpecker_pipeline | `0 3 * * *` | Daily node CVE scan |
| `trivy-scan-images` | woodpecker_pipeline | `0 4 * * *` | Daily image CVE scan |
| `woodpecker-sync` | http_request | `0 */4 * * *` | Sync Woodpecker workers |
| `backup-check` | http_request | `0 */6 * * *` | Check backup alerts |
| `cve-auto-resolve` | http_request | `0 6 * * 1` | Weekly auto-resolve CVEs |

## Features

- **Cron expressions**: standard 5-field format (`min hour dom mon dow`)
- **Timeout**: per-job configurable (default 300s)
- **Retries**: configurable max retries with delay between attempts
- **Overlap protection**: optional, prevents running a job if previous run is still active
- **Notifications**: Matrix/email/webhooks on final failure or timeout
- **Manual trigger**: run any job on demand from the UI
- **History**: full run log with status, duration, error messages, pipeline links

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/scheduler/jobs` | List all jobs with stats |
| POST | `/api/v1/scheduler/jobs` | Create a job |
| GET | `/api/v1/scheduler/jobs/{id}` | Job detail + recent runs |
| PUT | `/api/v1/scheduler/jobs/{id}` | Update a job |
| DELETE | `/api/v1/scheduler/jobs/{id}` | Delete a job |
| POST | `/api/v1/scheduler/jobs/{id}/toggle` | Enable/disable |
| POST | `/api/v1/scheduler/jobs/{id}/trigger` | Manual trigger |
| GET | `/api/v1/scheduler/runs` | Run history (paginated) |
| GET | `/api/v1/scheduler/stats` | Aggregated stats |
