# Installation

## Requirements

| Requirement | Details |
|-------------|---------|
| Docker | Docker Engine 24+ with Compose v2 |
| OS (CMDB host) | Debian 12+, Arch Linux, Rocky Linux 9+ |
| OS (managed nodes) | Debian, Ubuntu, Arch Linux, Rocky Linux 9/10, RHEL 9+ |
| SSO proxy | **Required** — Authelia, Authentik, or Keycloak |
| Private network | **Required** — WireGuard, Tailscale, or equivalent VPN |

> **NEVER expose a CMDB on the public internet.** A CMDB contains the complete map of your infrastructure. It must only be accessible through a private network (VPN) behind an SSO proxy.

## Environment variables

See [`env.example`](../../env.example) for all variables. At minimum:

| Variable | Purpose |
|----------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `API_SECRET_KEY` | Admin API key (read/write) |
| `COLLECT_TOKEN` | Collection token (Ansible, Trivy, scripts) |
| `CMDB_DOMAIN` | Public domain for HTTPS (Traefik) |

Optional: `OPENCVE_*`, `WAZUH_*`, `WOODPECKER_*`, `GITEA_*`, `GITLAB_*`, `FORGEJO_*`

Generate all secrets: `make secrets`

## Quickstart

```bash
# 1. Generate secrets
make secrets

# 2. Edit .env
vim .env

# 3. Start
make up

# 4. Verify
curl localhost:8000/api/v1/health

# 5. First collection
cd ansible && ansible-playbook -i inventory/hosts.ini playbooks/collect.yml
```

## Authentication

The frontend has no built-in authentication. An SSO reverse proxy is required.

| Method | How it works | Use case |
|--------|-------------|----------|
| **SSO header** (`Remote-User`) | Set by reverse proxy after login | Browser access |
| **Bearer token** | `Authorization: Bearer <token>` | Scripts, Ansible, Trivy, curl |

`Remote-User` is only trusted from Docker proxy network (172.16-20.x).

### Token levels

| Token | Source | Permissions |
|-------|--------|-------------|
| **Collect token** | `.env` `COLLECT_TOKEN` | Write-only: collection endpoints |
| **Admin key** | `.env` `API_SECRET_KEY` | Full access |
| **DB tokens** | API `/api/v1/tokens` | Granular (12 scopes x r/w/rw) |

DB tokens are hashed with HMAC-SHA512 (per-instance `TOKEN_HMAC_KEY`). Shown once at creation.

**12 scopes:** `collect`, `read`, `backup`, `cicd`, `deployments`, `managers`, `automation`, `repositories`, `findings`, `misconf`, `settings`, `tokens`

## Security

| Layer | Protection |
|-------|-----------|
| XSS | All values escaped via `esc()` |
| SQL injection | All parameters bound (`:param`) |
| CSP | `Content-Security-Policy` on nginx |
| PostgreSQL | Internal Docker network, no exposed port |
| Startup | API refuses default `change-me` tokens |
| Header trust | `Remote-User` only from Docker proxy network |
| HMAC tokens | DB dump useless without `TOKEN_HMAC_KEY` |
| Audit log | All sensitive actions logged with actor |

## Authelia

```yaml
access_control:
  rules:
    - domain: ['cmdb.example.com']
      networks: ['10.0.0.0/24']
      policy: 'one_factor'
    - domain: ['cmdb.example.com']
      policy: 'two_factor'
```

## Resurgamus Horizon (optional)

The CMDB can load its secrets from an rhorizon instance instead of `.env`.
On startup, if `VAULT_URL` and `VAULT_TOKEN` are set, the API attempts to fetch each secret. If the vault is sealed or a secret is missing, the `.env` value is kept.

### Configuration

```bash
# .env — only two secrets needed
VAULT_URL=http://vault:8200
VAULT_TOKEN=rh_xxx...    # scope: secrets:r, namespace: cmdb
```

### Secrets to create in the vault

| Vault secret | CMDB setting | Role | Required |
|---|---|---|---|
| `cmdb-secret-key` | `secret_key` | Admin API key (read + write) | yes |
| `cmdb-collect-token` | `collect_token` | Collect token (Ansible, scripts) | yes |
| `cmdb-token-hmac-key` | `token_hmac_key` | HMAC key for hashing DB tokens | yes |
| `cmdb-woodpecker-token` | `woodpecker_token` | Woodpecker API token | if CI/CD |
| `cmdb-gitea-token` | `gitea_token` | Gitea API token (repository:read) | if forge |
| `cmdb-gitlab-token` | `gitlab_token` | GitLab API token (read_api) | if GitLab |
| `cmdb-forgejo-token` | `forgejo_token` | Forgejo API token | if Forgejo |
| `cmdb-opencve-password` | `opencve_password` | OpenCVE password | if CVE intel |

### Create secrets in rhorizon

```bash
# Example with curl
for secret in cmdb-secret-key cmdb-collect-token cmdb-token-hmac-key; do
  curl -X POST "$VAULT_URL/api/v1/vault/secrets" \
    -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$secret\", \"value\": \"$(openssl rand -base64 32)\", \"namespace\": \"cmdb\"}"
done
```

### Vault sealed guard

When the vault is configured, certain operations are blocked if the vault is sealed:

| Operation | Behavior |
|---|---|
| Scheduler trigger | HTTP 503 with explicit message |
| Pipeline trigger | HTTP 503 |
| Deployment execute | HTTP 503 |
| Automation execute | Blocked (except `notify`) |

The error message includes the vault URL and how to disable the guard (remove `VAULT_URL`/`VAULT_TOKEN`).

### Minimum vault token

The vault token used by the CMDB needs:
```json
{"secrets": "r", "namespaces": ["cmdb"]}
```
Read-only on the `cmdb` namespace. No write or admin access needed.

## Firewall

```bash
# nftables — port 8000 from wg0 and wg1
nft add rule inet filter input ip saddr 10.0.0.0/24 tcp dport 8000 accept
nft add rule inet filter input ip saddr 10.0.1.0/24 tcp dport 8000 accept
nft list ruleset > /etc/nftables.conf
```
