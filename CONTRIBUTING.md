<!--
-----------------------------------------------------------------------------
Constellation - (c) 2024-2026 shdw <contact@resurgamus.com> - Apache-2.0
Self-hosted CAASM/CMDB platform
Contributions accepted under DCO (Signed-off-by:) - see section below
-----------------------------------------------------------------------------
-->

# Contributing

Thanks for your interest in contributing to CMDB Constellation.

## Getting started

```bash
# Clone
git clone https://github.com/YOUR_USER/cmdb.git
cd cmdb

# Generate secrets
make secrets

# Edit .env — set your domain and middleware
vim .env

# Launch (standalone, no Traefik needed)
docker compose -f docker-compose.yml -f docker-compose.standalone.yml up -d

# Verify
curl http://localhost:8000/api/v1/health
```

## Development

### Stack

- **Backend**: Python 3.12 / FastAPI / SQLAlchemy (raw SQL) / asyncpg / PostgreSQL 16
- **Frontend**: Vanilla JS (ES modules), no build step, no framework
- **Infra**: Docker Compose v2, Ansible, Woodpecker CI

### Code style

- **Python**: ruff (linter + formatter, replaces black/flake8/isort)
- **SQL**: raw SQL via `text()` bindings — no ORM, no string interpolation
- **Frontend**: no build tools, no npm — pure HTML/CSS/JS modules

```bash
# Lint
make lint

# Auto-fix
make lint-fix

# Tests (requires running postgres-test container)
make test
```

### Tests

Integration tests run against a real PostgreSQL instance (no mocks).

```bash
# Start test DB
docker compose -f docker-compose.test.yml up -d

# Run tests
pytest tests/ -v

# Stop test DB
docker compose -f docker-compose.test.yml down
```

### Pre-commit checks

Three checks must pass before every commit (CI enforces the same):

1. `ruff check` — lint on staged Python files
2. `ruff format --check` — formatting on staged Python files
3. `detect-secrets` vs `.secrets.baseline` — no new secrets

Pick the option that suits your workflow — both run the same checks:

**Option A — `pre-commit` framework (standard ecosystem)**

```bash
pip install pre-commit           # in your venv, system, or via Ansible
pre-commit install
```

Per-hook skip: `SKIP=ruff git commit -m "..."`.

**Option B — shell + Docker fallback (zero install required)**

```bash
make hooks-install
# = git config core.hooksPath scripts/git-hooks
```

The shell hook auto-detects available tooling:
`ruff`/`detect-secrets` in `$PATH` → fast local run; else `.venv/bin/*` → fast venv
run; else `docker`/`podman` → containerized run (slower first time). See
[scripts/git-hooks/README.md](scripts/git-hooks/README.md) for details.

Bypass either with `git commit --no-verify` (use sparingly — CI will still catch).

**If you add a hook**: update both `.pre-commit-config.yaml` and
`scripts/git-hooks/pre-commit` so both options stay in sync. Tool versions are
pinned in `versions.env` (`RUFF_VERSION`, `DETECT_SECRETS_VERSION`) and reused
by both options + CI.

**False-positive secret**:

```bash
make secrets-baseline                    # rescan against current tree
detect-secrets audit .secrets.baseline   # interactive review of new findings
git add .secrets.baseline && git commit  # commit the audited baseline
```

## Developer Certificate of Origin (DCO)

All commits must be signed off (`git commit -s`) to certify that you wrote the
patch or have the right to submit it under this project's license. The signoff
is your assertion of the [Developer Certificate of Origin](https://developercertificate.org/) —
no CLA, no copyright assignment.

```bash
git commit -s -m "feat: add new collector"
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer to the
commit message. Set `user.name` and `user.email` in your git config first.

> **Note for automated tooling**: if you are an automated agent (LLM-driven
> coding assistant, code-generation pipeline, etc.) submitting changes on
> behalf of a human contributor, the human is responsible for the DCO
> signoff and must verify the patch before submission.

## Submitting changes

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run `make lint` and `make test`
5. Commit with `-s` (DCO signoff) and a descriptive message (conventional commits preferred):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation only
   - `refactor:` code change that neither fixes a bug nor adds a feature
   - `test:` adding or updating tests
6. Push to your fork and open a Pull Request

## Architecture overview

```
ansible/          Inventory collection playbooks
api/              FastAPI backend (routes, auth, config)
frontend/         Vanilla JS frontend (ES modules, no build)
  js/views/       View modules (one per page)
  js/panels/      Detail panel modules
  css/            Styles
migrations/       SQL migrations (applied automatically)
opencve/          OpenCVE v2 deployment (optional)
scripts/          Deploy and scan scripts
tools/            Sync scripts (OpenCVE, Wazuh) + Dockerfile
tests/            Integration tests (pytest + real PostgreSQL)
schema.sql        Database schema (idempotent, self-contained)
docker-compose.yml  Production stack
```

## Data flow

```
Collection (Ansible, Trivy, Wazuh, Restic, OpenCVE)
    → POST /api/v1/*/report (Bearer token)
    → PostgreSQL
    → Frontend reads via GET /api/v1/* (Authelia SSO or Bearer)
```

## Security

- All dynamic values in frontend are escaped via `esc()` — maintain this for any new view
- All SQL parameters use `:param` bindings — never interpolate user input
- Remote-User header is only trusted from Docker proxy network
- API rejects startup with default tokens ("change-me")

If you find a security issue, please report it privately rather than opening a public issue.

## What we're looking for

- New data source integrations (Nessus, Qualys, cloud providers...)
- Dashboard improvements
- Better mobile responsiveness
- Notification channels (Slack, Telegram, PagerDuty...)
- Performance improvements on large datasets
- Documentation and translations
