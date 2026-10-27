# Connectors

Universal connector architecture with abstract interfaces and factory functions.

```
           Remediation / Deployment logic
      (automation.py, deployments.py, scheduler.py)
    ┌──────────────────┬──────────────────────────┐
    │  Forge Connector │    CI/CD Connector        │
    │  (repos, branches)│   (pipelines, runners)   │
    ├──────────────────┼──────────────────────────┤
    │ GiteaForge       │ WoodpeckerCI             │
    │ ForgejoForge     │ GitLabCI                 │
    │ GitLabForge      │                          │
    └──────────────────┴──────────────────────────┘

    ┌─────────────────────────────────────────────┐
    │            Registry Connector                │
    ├──────────┬────────┬──────────┬──────────────┤
    │DockerHub │  GHCR  │  GitLab  │   Harbor     │
    └──────────┴────────┴──────────┴──────────────┘

    ┌─────────────────────────────────────────────┐
    │          Notification Channels               │
    ├──────────┬────────┬─────────────────────────┤
    │  Matrix  │ Email  │ Webhooks (N instances)  │
    │ (native) │ (SMTP) │ Mattermost, Rocket.Chat │
    │          │        │ Slack, Discord, ntfy    │
    └──────────┴────────┴─────────────────────────┘
```

## Token setup

### Gitea / Forgejo

1. Go to **Settings > Applications > Manage Access Tokens**
2. Create a token with these scopes:

| Scope | Permission | Usage |
|-------|------------|-------|
| **repository** | **Read** | List repos, branches, file contents |

No other scope needed. The token is read-only.

3. Add the token to CMDB: **Settings > CI/CD > Gitea Token** or `GITEA_TOKEN` in `.env`

### Woodpecker

1. Open the Woodpecker UI (`ci.example.com`)
2. Click on your avatar > **Settings**
3. Section **Personal API tokens** > generate a token

Or via CLI if you have server access:
```bash
woodpecker-cli token
```

Personal tokens have full access to everything the user can do (no granular scopes). To limit permissions, create a dedicated user (e.g., `cmdb-bot`) with access only to the required repos.

4. Add the token to CMDB: **Settings > CI/CD > Woodpecker Token** or `WOODPECKER_TOKEN` in `.env`

### GitLab

1. Go to **Settings > Access Tokens** (project or group level)
2. Create a token with these scopes:

| Scope | Usage |
|-------|-------|
| `read_api` | List projects, pipelines, runners |
| `read_repository` | Branches, CI config files |

To trigger pipelines (scheduler, deployments), add the `api` scope (read+write).

3. Add the token to CMDB via the UI: **Pipelines > Servers > Add Server**

### Access matrix per connector

| Connector | List repos | Branches | CI detection | Sync pipelines | Trigger pipeline |
|-----------|:---:|:---:|:---:|:---:|:---:|
| Gitea (repository:read) | x | x | x | — | — |
| Woodpecker (personal token) | x | — | — | x | x |
| GitLab (read_api) | x | x | x | x | — |
| GitLab (api) | x | x | x | x | x |

> **Note**: Gitea provides repos and branches, Woodpecker provides pipelines and agents. Both tokens are complementary.

## Forge connectors

Abstract interface `ForgeConnector` with methods: `test_connection()`, `list_repos()`, `get_branches()`, `has_ci_config()`.

| Connector | API | Auth | CI config detection |
|-----------|-----|------|---------------------|
| `GiteaForge` | Gitea v1 | `token` header | `.woodpecker/` |
| `ForgejoForge` | Gitea v1 (compatible) | `token` header | `.woodpecker/`, `.forgejo/workflows/` |
| `GitLabForge` | GitLab v4 | `PRIVATE-TOKEN` header | `.gitlab-ci.yml` |

### Add a forge server

In the UI: **Pipelines > Servers > Add Server**, or via API:

```bash
curl -X POST /api/v1/cicd/servers \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "my-gitlab", "server_type": "gitlab", "url": "https://gitlab.example.com", "token": "glpat-xxx"}'
```

## CI/CD connectors

Abstract interface `CIConnector` with methods: `test_connection()`, `list_pipelines()`, `list_runners()`, `trigger_pipeline()`.

| Connector | API | Auth | Runner type |
|-----------|-----|------|-------------|
| `WoodpeckerCI` | Woodpecker REST | Bearer token | Agents |
| `GitLabCI` | GitLab v4 | `PRIVATE-TOKEN` | Runners |

### Sync workers

```bash
# Sync from Woodpecker (default)
curl -X POST /api/v1/cicd/workers/sync

# Sync from GitLab
curl -X POST /api/v1/cicd/workers/sync?ci_system=gitlab
```

### Trigger a pipeline

```bash
curl -X POST /api/v1/cicd/pipelines/trigger \
  -d '{"ci_system": "woodpecker", "repo_name": "youruser/cmdb", "branch": "main"}'

curl -X POST /api/v1/cicd/pipelines/trigger \
  -d '{"ci_system": "gitlab", "repo_name": "group/project", "branch": "main"}'
```

## Registry connectors

Abstract interface `RegistryConnector` with methods: `resolve_latest()`, `list_tags()`.

| Connector | Registry | Auth |
|-----------|----------|------|
| `DockerHubRegistry` | Docker Hub | Anonymous |
| `GHCRRegistry` | GitHub Container Registry | Anonymous token |
| `GitLabRegistry` | GitLab Container Registry | Bearer token |
| `HarborRegistry` | Harbor v2 | Basic auth |

Used by the **Repositories** view to check for available updates.

## Notification webhooks

Generic webhooks stored in the `notification_webhooks` table. Each webhook has:
- **Platform**: `mattermost`, `rocketchat`, `slack`, `discord`, `ntfy`, `gotify`, `generic`
- **Route filters**: enable/disable per category (CVE, security, CI/CD, backup)
- **Channel override**: per-category channel/room

### Configure in UI

**Settings > Notification Webhooks > Add Webhook**

### Payload format by platform

| Platform | Payload |
|----------|---------|
| Mattermost, Rocket.Chat, Slack, generic | `{"text": "message", "channel": "#room"}` |
| Discord | `{"content": "message"}` |
| ntfy | `{"topic": "channel", "message": "message"}` |

### Sync scripts

| Script | Source | Data |
|--------|--------|------|
| `tools/sync_woodpecker.py` | Gitea + Woodpecker | Repos, pipelines, agents |
| `tools/sync_gitlab.py` | GitLab | Projects, pipelines, runners |
| `tools/sync_forgejo.py` | Forgejo | Repos (no CI) |

Each script runs in a Docker container with env vars (`GITLAB_URL`, `GITLAB_TOKEN`, etc.) and pushes to the CMDB API.
