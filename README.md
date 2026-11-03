<!--
-----------------------------------------------------------------------------
Constellation - (c) 2024-2026 shdw <contact@resurgamus.com> - Apache-2.0
Self-hosted CAASM/CMDB platform
Source: https://github.com/JR-Shdw/Constellation
-----------------------------------------------------------------------------
-->

# Constellation — CMDB / CAASM

> **License**
> - Licensed under **Apache-2.0** ([LICENSE](LICENSE)). Permissive: you may use, modify and redistribute, including in closed-source and commercial products, provided you keep the notices required by sections 4(b) and 4(d).
> - **No warranty and no guaranteed support.** Provided "AS IS" — see Apache-2.0 sections 7 and 8.
> - **Donation funded.** Every release and every security fix goes to everyone at the same time; nothing is gated behind sponsorship. Deployment assistance is a separate service — see [SUPPORT.md](SUPPORT.md).
> - **"Constellation"** is a project name; Apache-2.0 section 6 grants no trademark rights.

Asset inventory + vulnerability tracking + exposure map + automation for a
small self-hosted infrastructure. FastAPI + PostgreSQL backend, Vanilla JS
SPA, Ansible-based collection, Trivy/Wazuh/OpenCVE for CVE data.

Status: working, deployed on my own stack. Not meant as a SaaS replacement —
this is a solo-maintained tool that does what I need and is documented well
enough that someone else can run it.

Docs: [English](docs/en/) · [Francais](docs/fr/)

## Architecture

```
               Collection (push to CMDB)
    Ansible ──────┐
    Trivy ────────┤     ┌─────────────────────────────────┐
    Wazuh ────────┼────>│  FastAPI + PostgreSQL            │
    OpenCVE ──────┤     │  19 views, 76+ API endpoints    │
    Restic ───────┘     │  Scheduler, Automation engine   │
                        └──────────┬──────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │         Universal Connectors                      │
         ├──────────┬──────────┬──────────┬─────────────────┤
         │  Forges  │  CI/CD   │ Registry │   Messaging     │
         │  Gitea   │ Woodpeck │ DockerHub│  Matrix (native)│
         │  Forgejo │ GitLabCI │ GHCR     │  N webhooks:    │
         │  GitLab  │          │ GitLab   │  Mattermost     │
         │          │          │ Harbor   │  Rocket.Chat    │
         │          │          │          │  Slack, Discord  │
         │          │          │          │  ntfy, Gotify   │
         └──────────┴──────────┴──────────┴─────────────────┘
```

## Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.12 / FastAPI / asyncpg / PostgreSQL 17 |
| Frontend | Vanilla JS (ES modules), no build step |
| Collection | Ansible, Trivy, Wazuh, OpenCVE, Restic |
| Forges | Gitea, Forgejo, GitLab (universal connectors) |
| CI/CD | Woodpecker, GitLab CI (universal connectors) |
| Registries | DockerHub, GHCR, GitLab Registry, Harbor |
| Messaging | Matrix + webhooks (Mattermost, Rocket.Chat, Slack, Discord, ntfy) |
| Managed nodes | Debian, Ubuntu, Arch Linux, Rocky Linux 9/10, RHEL 9+ |
| Infra | Docker Compose v2, Traefik, Authelia |

## Quickstart

```bash
make secrets          # generate .env with random secrets
vim .env              # set your domain and middleware
make up               # launch the stack
curl localhost:8000/api/v1/health
```

> See [Installation guide](docs/en/install.md) for full setup instructions.

## Documentation

| Document | Description |
|----------|-------------|
| [Installation](docs/en/install.md) | Requirements, env vars, quickstart, security, Authelia, firewall |
| [Operations](docs/en/operations.md) | Data sources, syncs, Makefile, migrations |
| [Features](docs/en/features.md) | CVEs, misconf, compliance, automation, repos, alerts |
| [Scheduler](docs/en/scheduler.md) | Scheduled jobs, config JSON, cron expressions |
| [Connectors](docs/en/connectors.md) | Forges, CI/CD, registries, webhooks |
| [API Reference](docs/en/api.md) | All endpoints, auth, examples |

## License

[Apache-2.0](LICENSE) — Free to use, modify, deploy and redistribute, including commercially. Keep the copyright, patent, trademark and attribution notices (section 4(b)) and reproduce the NOTICE file in derivative works (section 4(d)).

No warranty and no guaranteed support: the software is provided "AS IS"
(sections 7 and 8).

The project is funded by donations. Releases and security fixes are never
restricted to donors or sponsors. Deployment assistance, where offered, is a
separate service and not part of this license — see [SUPPORT.md](SUPPORT.md).
