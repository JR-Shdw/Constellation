# Installation

## Pre-requis

| Requis | Details |
|--------|---------|
| Docker | Docker Engine 24+ avec Compose v2 |
| OS (hote CMDB) | Debian 12+, Arch Linux, Rocky Linux 9+ |
| OS (nodes geres) | Debian, Ubuntu, Arch Linux, Rocky Linux 9/10, RHEL 9+ |
| Proxy SSO | **Requis** — Authelia, Authentik, ou Keycloak |
| Reseau prive | **Requis** — WireGuard, Tailscale, ou VPN equivalent |

> **Ne JAMAIS exposer un CMDB sur Internet public.** Un CMDB contient la cartographie complete de votre infrastructure. Il ne doit etre accessible que via un reseau prive (VPN) derriere un proxy SSO.

## Variables d'environnement

Voir [`env.example`](../../env.example) pour toutes les variables. Au minimum :

| Variable | Role |
|----------|------|
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL |
| `API_SECRET_KEY` | Cle admin API (lecture + ecriture) |
| `COLLECT_TOKEN` | Token de collecte (Ansible, Trivy, scripts) |
| `CMDB_DOMAIN` | Domaine public pour HTTPS (Traefik) |

Optionnel : `OPENCVE_*`, `WAZUH_*`, `WOODPECKER_*`, `GITEA_*`, `GITLAB_*`, `FORGEJO_*`

Generer tous les secrets : `make secrets`

## Quickstart

```bash
# 1. Generer les secrets
make secrets

# 2. Editer .env
vim .env

# 3. Demarrer
make up

# 4. Verifier
curl localhost:8000/api/v1/health

# 5. Premiere collecte
cd ansible && ansible-playbook -i inventory/hosts.ini playbooks/collect.yml
```

## Authentification

Le frontend n'a pas d'authentification integree. Un reverse proxy SSO est requis.

| Methode | Fonctionnement | Cas d'usage |
|---------|---------------|-------------|
| **Header SSO** (`Remote-User`) | Injecte par le reverse proxy apres login | Acces navigateur |
| **Bearer token** | `Authorization: Bearer <token>` | Scripts, Ansible, Trivy, curl |

`Remote-User` n'est accepte que depuis le reseau Docker du proxy (172.16-20.x).

### Niveaux de tokens

| Token | Source | Permissions |
|-------|--------|-------------|
| **Token collecte** | `.env` `COLLECT_TOKEN` | Ecriture seule : endpoints de collecte |
| **Cle admin** | `.env` `API_SECRET_KEY` | Acces complet |
| **Tokens DB** | API `/api/v1/tokens` | Granulaire (12 scopes x r/w/rw) |

Tokens DB haches HMAC-SHA512 (cle per-instance `TOKEN_HMAC_KEY`). Affiches une seule fois a la creation.

**12 scopes** : `collect`, `read`, `backup`, `cicd`, `deployments`, `managers`, `automation`, `repositories`, `findings`, `misconf`, `settings`, `tokens`

## Securite

| Couche | Protection |
|--------|-----------|
| XSS | Valeurs echappees via `esc()` |
| Injection SQL | Parametres bindes (`:param`) |
| CSP | `Content-Security-Policy` sur nginx |
| PostgreSQL | Reseau Docker interne, aucun port expose |
| Demarrage | L'API refuse les tokens `change-me` par defaut |
| Trust header | `Remote-User` uniquement depuis le reseau Docker du proxy |
| HMAC tokens | Dump DB inutile sans `TOKEN_HMAC_KEY` |
| Audit log | Actions sensibles loguees avec acteur |

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

## Resurgamus Horizon (optionnel)

Le CMDB peut charger ses secrets depuis un vault rhorizon au lieu du `.env`.
Au demarrage, si `VAULT_URL` et `VAULT_TOKEN` sont definis, l'API tente de recuperer chaque secret. Si le vault est sealed ou un secret absent, la valeur `.env` est conservee.

### Configuration

```bash
# .env — seuls secrets necessaires
VAULT_URL=http://vault:8200
VAULT_TOKEN=rh_xxx...    # scope: secrets:r, namespace: cmdb
```

### Secrets a creer dans le vault

| Secret vault | Setting CMDB | Role | Requis |
|---|---|---|---|
| `cmdb-secret-key` | `secret_key` | Cle admin API (lecture + ecriture) | oui |
| `cmdb-collect-token` | `collect_token` | Token de collecte (Ansible, scripts) | oui |
| `cmdb-token-hmac-key` | `token_hmac_key` | Cle HMAC pour hacher les tokens DB | oui |
| `cmdb-woodpecker-token` | `woodpecker_token` | Token API Woodpecker | si CI/CD |
| `cmdb-gitea-token` | `gitea_token` | Token API Gitea (repository:read) | si forge |
| `cmdb-gitlab-token` | `gitlab_token` | Token API GitLab (read_api) | si GitLab |
| `cmdb-forgejo-token` | `forgejo_token` | Token API Forgejo | si Forgejo |
| `cmdb-opencve-password` | `opencve_password` | Mot de passe OpenCVE | si CVE intel |

### Creer les secrets dans rhorizon

```bash
# Exemple avec curl
for secret in cmdb-secret-key cmdb-collect-token cmdb-token-hmac-key; do
  curl -X POST "$VAULT_URL/api/v1/vault/secrets" \
    -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$secret\", \"value\": \"$(openssl rand -base64 32)\", \"namespace\": \"cmdb\"}"
done
```

### Vault sealed guard

Quand le vault est configure, certaines operations sont bloquees si le vault est sealed :

| Operation | Comportement |
|---|---|
| Scheduler trigger | HTTP 503 avec message explicite |
| Pipeline trigger | HTTP 503 |
| Deployment execute | HTTP 503 |
| Automation execute | Bloquee (sauf `notify`) |

Le message d'erreur indique l'URL du vault et comment desactiver le guard (retirer `VAULT_URL`/`VAULT_TOKEN`).

### Token vault minimal

Le token vault utilise par le CMDB a besoin de :
```json
{"secrets": "r", "namespaces": ["cmdb"]}
```
Lecture seule sur le namespace `cmdb`. Pas besoin d'ecriture ni d'admin.

## Firewall

```bash
# nftables — port 8000 depuis wg0 et wg1
nft add rule inet filter input ip saddr 10.0.0.0/24 tcp dport 8000 accept
nft add rule inet filter input ip saddr 10.0.1.0/24 tcp dport 8000 accept
nft list ruleset > /etc/nftables.conf
```
