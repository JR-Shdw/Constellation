# Resurgamus Horizon — Spécification technique

## Résumé

Vault de secrets self-hosted, minimaliste, conçu pour l'automation infrastructure.
Remplace les secrets `.env` en clair par un stockage chiffré avec seal/unseal,
tokens HMAC, et support YubiKey.

**Philosophie** : utiliser des primitives cryptographiques éprouvées (libsodium),
ne rien inventer, garder le code auditable (~2000 LOC).

## Cas d'usage

```
Ansible playbook → demande un token collect au vault → utilise le token → l'oublie
CMDB scheduler   → demande les credentials OpenCVE   → sync → les oublie
Script backup    → demande la passphrase Restic       → backup → l'oublie
CI/CD pipeline   → demande un deploy token            → déploie → l'oublie
```

Aucun secret n'est jamais écrit en clair sur disque (ni `.env`, ni fichier temp).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          rhorizon                                 │
│                                                                  │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────────────┐    │
│  │ hkkeygen │   │  libsodium   │   │    FastAPI (Python)   │    │
│  │   (C)    │   │     (C)      │   │                       │    │
│  │          │   │              │   │  /unseal              │    │
│  │ Génère:  │   │ Chiffre:     │   │  /seal                │    │
│  │ - tokens │   │ - XChaCha20  │   │  /secret/{name}       │    │
│  │ - DEK    │   │ - AES-256    │   │  /secret (CRUD)       │    │
│  │ - nonces │   │              │   │  /token (CRUD)        │    │
│  │          │   │ Dérive:      │   │  /audit               │    │
│  │ Source:  │   │ - Argon2id   │   │  /health              │    │
│  │ urandom  │   │ - HKDF-SHA512│   │  /status (sealed?)    │    │
│  │          │   │              │   │                       │    │
│  │          │   │ Protège:     │   │  Auth:                │    │
│  │          │   │ - mlock()    │   │  - HMAC-SHA512 tokens │    │
│  │          │   │ - memzero()  │   │  - scope/mode (r/w)   │    │
│  │          │   │ - memcmp()   │   │                       │    │
│  └──────────┘   └──────────────┘   └──────────────────────┘    │
│                         │                                        │
│                         ▼                                        │
│              ┌──────────────────┐                               │
│              │   PostgreSQL     │                               │
│              │                  │                               │
│              │  secrets (blob)  │  ← XChaCha20-Poly1305 (DEK)  │
│              │  dek_store (blob)│  ← AES-256-GCM (master_key)  │
│              │  vault_tokens    │  ← HMAC-SHA512 hash           │
│              │  audit_log       │  ← signé HMAC                 │
│              │  config          │  ← paramètres non-secrets      │
│              └──────────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

## Cryptographie — couches

### Couche 1 : Unseal (humain → master key)

```
master_password (humain, clavier)
  + YubiKey HMAC-SHA256(challenge aléatoire 32 bytes)
  → concaténation
  → Argon2id(memory=256MB, iterations=3, parallelism=4)
  → master_key (256 bits)
  → mlock(master_key) — non swappable
```

**Argon2id paramètres** :
- `m_cost = 262144` (256 MB) — mémoire-dur, anti-GPU/ASIC
- `t_cost = 3` — 3 itérations
- `p_cost = 4` — 4 threads parallèles
- `hashlen = 32` — 256 bits en sortie
- Salt : stocké en DB (généré au premier unseal)

**YubiKey** :
- Slot 2, HMAC-SHA256 challenge-response
- Challenge = 32 bytes aléatoires (changé à chaque unseal)
- Multi-YubiKey : plusieurs clés enregistrées (backup)
- Sans YubiKey : mode dégradé possible (password seul, configurable)

### Couche 2 : Dérivation (master key → clés spécialisées)

```
master_key
  → HKDF-SHA512(info="hmac-tokens")  → hmac_key    (auth vault tokens)
  → HKDF-SHA512(info="dek-encrypt")  → dek_key     (chiffre les DEK)
  → HKDF-SHA512(info="audit-sign")   → audit_key   (signe les logs)
```

**HKDF** (RFC 5869) : dérivation déterministe, chaque clé est indépendante.
Compromis d'une clé dérivée ≠ compromis des autres.

### Couche 3 : Chiffrement des secrets (double enveloppe)

```
Secret "opencve-password"
  → DEK aléatoire (256 bits, hkkeygen/urandom)
  → XChaCha20-Poly1305(secret, DEK, nonce_192bits)
  → ciphertext stocké en DB (table secrets)

DEK
  → AES-256-GCM(DEK, dek_key, nonce_96bits)
  → encrypted_dek stocké en DB (table dek_store)
```

**Pourquoi double enveloppe** :
1. Rotation de master key → re-chiffrer les DEK (~dizaines), pas les secrets (~centaines)
2. Chaque secret a sa propre DEK → compromis d'un secret ≠ compromis des autres
3. Deux algorithmes différents → si XChaCha20 est cassé dans 20 ans, AES-256 protège encore

**Nonces** :
- XChaCha20 : 192 bits aléatoires (collision impossible même sans compteur)
- AES-256-GCM : 96 bits aléatoires (suffisant pour le nombre de DEK)

### Couche 4 : Authentification (vault tokens)

```
vault_token = "rh_" + random_urlsafe(32)   ← hkkeygen/urandom
token_hash  = HMAC-SHA512(hmac_key, vault_token)
```

Même pattern que la CMDB. `hmac_key` est dérivée du master key → jamais sur disque.

## Schema PostgreSQL

```sql
-- Métadonnées vault (non secret)
CREATE TABLE IF NOT EXISTS vault_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Stocke: argon2_salt, yubikey_ids, version, auto_seal_minutes

-- Secrets chiffrés
CREATE TABLE IF NOT EXISTS vault_secrets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    namespace   TEXT NOT NULL DEFAULT 'default',
    ciphertext  BYTEA NOT NULL,           -- XChaCha20-Poly1305(secret, DEK)
    nonce       BYTEA NOT NULL,           -- 24 bytes (192 bits)
    dek_id      UUID NOT NULL REFERENCES vault_dek(id),
    metadata    JSONB DEFAULT '{}',       -- labels, rotation_policy, etc.
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,              -- auto-suppression (optionnel)
    created_by  TEXT NOT NULL
);

-- Data Encryption Keys (chiffrées par master key)
CREATE TABLE IF NOT EXISTS vault_dek (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    encrypted_key   BYTEA NOT NULL,       -- AES-256-GCM(DEK, dek_key)
    nonce           BYTEA NOT NULL,       -- 12 bytes (96 bits)
    active          BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Tokens d'accès au vault
CREATE TABLE IF NOT EXISTS vault_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT NOT NULL UNIQUE,     -- HMAC-SHA512
    permissions JSONB NOT NULL DEFAULT '{}',
    active      BOOLEAN DEFAULT true,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ
);

-- Audit trail signé
CREATE TABLE IF NOT EXISTS vault_audit (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ DEFAULT NOW(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,                     -- secret name (jamais la valeur)
    detail      JSONB DEFAULT '{}',
    ip_address  TEXT,
    signature   TEXT NOT NULL             -- HMAC-SHA512(audit_key, payload)
);

CREATE INDEX IF NOT EXISTS idx_vault_secrets_name ON vault_secrets (name);
CREATE INDEX IF NOT EXISTS idx_vault_secrets_ns ON vault_secrets (namespace);
CREATE INDEX IF NOT EXISTS idx_vault_tokens_hash ON vault_tokens (token_hash) WHERE active;
CREATE INDEX IF NOT EXISTS idx_vault_audit_ts ON vault_audit (timestamp DESC);
```

## API REST

### Seal / Unseal

```
POST /api/v1/vault/unseal
  Body: { "password": "...", "yubikey_response": "..." }
  → 200: { "status": "unsealed", "expires_in": null }
  → 401: { "error": "invalid credentials" }

POST /api/v1/vault/seal
  Auth: vault admin token
  → 200: { "status": "sealed" }
  → sodium_memzero(master_key, hmac_key, dek_key, audit_key)

GET /api/v1/vault/status
  No auth required
  → 200: { "sealed": true/false, "uptime": "4h32m", "version": "0.1.0" }
```

### Secrets CRUD

```
POST /api/v1/vault/secrets
  Auth: vault token (scope: secrets, mode: w)
  Body: { "name": "cmdb-collect-token", "value": "cmdb_xxx...",
          "namespace": "cmdb", "metadata": {"node": "vega"},
          "expires_at": "2026-04-07T00:00:00Z" }
  → 201: { "id": "...", "name": "...", "version": 1 }
  Note: value n'apparaît jamais dans la réponse ni dans les logs

GET /api/v1/vault/secrets/{name}
  Auth: vault token (scope: secrets, mode: r)
  → 200: { "name": "...", "value": "cmdb_xxx...", "version": 1 }
  → 403: sealed / insufficient permissions
  Audit: logged avec actor, IP, timestamp (pas la valeur)

GET /api/v1/vault/secrets
  Auth: vault token (scope: secrets, mode: r)
  Query: ?namespace=cmdb
  → 200: { "items": [{ "name": "...", "namespace": "...", "version": 1 }] }
  Note: liste les noms, jamais les valeurs

PUT /api/v1/vault/secrets/{name}
  Auth: vault token (scope: secrets, mode: w)
  Body: { "value": "new_value" }
  → 200: { "version": 2 }
  Note: ancien ciphertext écrasé, nouvelle DEK, version incrémentée

DELETE /api/v1/vault/secrets/{name}
  Auth: vault token (scope: secrets, mode: w)
  → 200: { "status": "deleted" }
  Note: suppression définitive, audit logged
```

### Tokens CRUD

```
POST /api/v1/vault/tokens
  Auth: vault admin
  Body: { "name": "cmdb-scheduler", "permissions": {"secrets": "r"} }
  → 201: { "token": "rh_xxx..." }  ← affiché une seule fois

POST /api/v1/vault/tokens/{id}/revoke
DELETE /api/v1/vault/tokens/{id}
POST /api/v1/vault/tokens/bulk/revoke
  Body: { "prefix": "ansible-" }
```

### Audit

```
GET /api/v1/vault/audit
  Auth: vault token (scope: audit, mode: r)
  Query: ?actor=cmdb&action=read_secret&limit=100
  → 200: { "items": [...], "verified": true }
  Note: chaque entrée est vérifiée via HMAC (signature intègre)
```

### Utilitaires

```
POST /api/v1/vault/generate
  Auth: vault token (scope: generate, mode: r)
  Body: { "length": 43, "charset": "urlsafe" }
  → 200: { "value": "xK9m..." }
  Note: utilise hkkeygen, le secret n'est PAS stocké (juste généré)

POST /api/v1/vault/rotate-master
  Auth: vault admin + password + YubiKey
  → Re-chiffre toutes les DEK avec la nouvelle master key
  → Ancien master invalidé
```

## Scopes et permissions

| Scope | r | w | Usage |
|---|---|---|---|
| `secrets` | Lire un secret | Créer/modifier/supprimer | Ansible, CMDB, scripts |
| `generate` | Générer un secret | — | Scripts, CI/CD |
| `tokens` | Lister les tokens | Créer/révoquer | Admin |
| `audit` | Lire les logs | — | Monitoring |
| `admin` | Tout | Tout + seal/unseal/rotate | Opérateur |

## Seal / Unseal — cycle de vie

```
                    ┌──────────┐
          reboot →  │  SEALED  │ ← seal explicite
                    └────┬─────┘
                         │ POST /unseal
                         │ (password + YubiKey)
                         ▼
                    ┌──────────┐
                    │ UNSEALED │ ← tâches automatisées OK
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         auto-seal   shutdown    seal API
         (timer)     (SIGTERM)   (manuel)
              │          │          │
              └──────────┼──────────┘
                         ▼
                    ┌──────────┐
                    │  SEALED  │
                    └──────────┘
                    sodium_memzero()
```

### Auto-seal (configurable)

| Mode | Comportement | Usage |
|---|---|---|
| `never` | Reste unsealed jusqu'au reboot/seal | Production (automation 24/7) |
| `inactivity` | Seal après N minutes sans requête | Environnement sensible |
| `timer` | Seal toutes les N heures | Re-unseal quotidien |

**Recommandation** : `never` pour commencer (les tâches cron tournent toutes les 2-6h).

## Protection mémoire — détails C

```c
#include <sodium.h>
#include <sys/mman.h>
#include <sys/prctl.h>

// Au démarrage
sodium_init();
prctl(PR_SET_DUMPABLE, 0);     // Pas de core dump
prctl(PR_SET_PTRACER, 0);      // Pas de ptrace/gdb attach

// Allocation sécurisée
void *master_key = sodium_malloc(32);  // Guard pages avant/après
sodium_mlock(master_key, 32);          // Non swappable

// Dérivation
crypto_pwhash(master_key, 32,
    combined_password, combined_len,
    salt,
    3,                                  // t_cost
    268435456,                          // m_cost (256 MB)
    crypto_pwhash_ALG_ARGON2ID13);

// Utilisation — timing-safe comparison
if (sodium_memcmp(computed_hmac, stored_hmac, 64) != 0)
    return DENIED;

// Nettoyage
sodium_memzero(master_key, 32);        // Écrase la mémoire
sodium_free(master_key);               // Libère avec guard pages
```

`sodium_malloc` place des **guard pages** (pages mémoire inaccessibles) avant et après
le buffer. Tout débordement → SIGSEGV immédiat, pas de fuite silencieuse.

## Intégration CMDB

### Phase 1 : vault comme source de secrets CMDB

```yaml
# docker-compose.yml — CMDB
services:
  api:
    environment:
      VAULT_URL: "http://vault:8200"
      VAULT_TOKEN: "${VAULT_TOKEN}"  # seul secret dans .env
```

```python
# api/app/config.py — au démarrage
async def load_secrets_from_vault():
    """Remplace les secrets .env par des secrets vault."""
    if settings.vault_url:
        async with httpx.AsyncClient() as client:
            for key in ("secret_key", "collect_token", "token_hmac_key"):
                r = await client.get(
                    f"{settings.vault_url}/api/v1/vault/secrets/cmdb-{key}",
                    headers={"Authorization": f"Bearer {settings.vault_token}"},
                )
                if r.status_code == 200:
                    setattr(settings, key, r.json()["value"])
```

### Phase 2 : Ansible utilise le vault

```yaml
# Playbook — pre_task fetch secret
- name: Get collect token from vault
  ansible.builtin.uri:
    url: "{{ vault_url }}/api/v1/vault/secrets/node-{{ inventory_hostname }}"
    headers:
      Authorization: "Bearer {{ vault_token }}"
    return_content: true
  register: vault_secret
  delegate_to: localhost

- name: Set token fact
  ansible.builtin.set_fact:
    cmdb_api_token: "{{ vault_secret.json.value }}"
```

### Phase 3 : rhorizon comme service indépendant

```
~/dev/tools/rhorizon/
  core/               C — libsodium, hkkeygen intégré
    crypto.c           Chiffrement/déchiffrement/HMAC
    memory.c           mlock, memzero, guard pages
    keygen.c           Génération secrets (hkkeygen adapté)
    yubikey.c          Challenge-response YubiKey
    shamir.c           Secret sharing (upscale)
  api/                 Python — FastAPI
    app/main.py        Seal/unseal state machine
    app/routes/secrets.py
    app/routes/tokens.py
    app/routes/audit.py
  schema.sql           Tables vault
  Dockerfile           debian-slim + libsodium-dev
  docker-compose.yml
  tests/
```

## Dépendances

| Paquet | Rôle | Taille | Maintenance |
|---|---|---|---|
| `libsodium` | Crypto (XChaCha20, AES-256, Argon2id, HKDF) | ~3 MB | djb/Frank Denis, très actif |
| `pynacl` | Binding Python pour libsodium | ~200 KB | PyCA, actif |
| `fastapi` | API REST | déjà dans la stack | actif |
| `asyncpg` | PostgreSQL async | déjà dans la stack | actif |
| `python-yubico` | YubiKey HMAC challenge-response | ~50 KB | Yubico, actif |
| `postgresql` | Stockage | déjà dans la stack | actif |

**Total nouvelles dépendances** : libsodium + pynacl + python-yubico. Zéro Node.js, zéro Redis.

## Modèle de menace

| Scénario | Protection | Résultat |
|---|---|---|
| Vol du serveur (disque) | Vault scellé, master key pas sur disque | Secrets inaccessibles |
| Dump de la DB | Secrets chiffrés XChaCha20 + DEK chiffrées AES-256 | Inutilisable |
| Dump DB + `.env` | `.env` ne contient qu'un vault token (pas la master key) | Token seul = accès limité par scope, vault doit être unsealed |
| Attaquant root (process running, vault unsealed) | mlock + no-dump + no-ptrace | Compliqué mais possible (module kernel) |
| Attaquant root (vault sealed) | Master key pas en mémoire | Secrets inaccessibles |
| Vault token volé | Scope limité (ex: secrets:r pour un namespace) | Impact limité, révoquer immédiatement |
| Brute-force master password | Argon2id 256MB + YubiKey requis | Impraticable |
| YubiKey volée seule | Password toujours requis | Inutile sans le password |
| Password intercepté seul | YubiKey toujours requise | Inutile sans la YubiKey |
| Cold boot (RAM freeze) | Risque résiduel si accès physique | Mitigation : auto-seal, pas de bare metal en datacenter tiers |

## Estimation

| Composant | LOC | Langage | Priorité |
|---|---|---|---|
| Crypto core (chiffrement, HMAC, mlock) | ~500 | C | P0 |
| hkkeygen intégré | ~300 | C (existant, adapter) | P0 |
| YubiKey challenge-response | ~150 | C | P1 |
| Shamir secret sharing | ~200 | C | P2 (upscale) |
| API seal/unseal | ~200 | Python | P0 |
| API secrets CRUD | ~300 | Python | P0 |
| API tokens + audit | ~300 | Python | P0 |
| Schema SQL | ~80 | SQL | P0 |
| Tests | ~400 | Python | P0 |
| **Total** | **~2400** | C + Python | |

## Roadmap

```
Phase 0 : Spec (ce document)                      ← fait
Phase 1 : Core crypto + API secrets + seal/unseal  ← MVP
Phase 2 : YubiKey + audit signé                    ← sécurité complète
Phase 3 : Intégration CMDB (load_secrets_from_vault)
Phase 4 : Intégration Ansible (pre_task fetch)
Phase 5 : Shamir + multi-YubiKey (upscale équipe)
Phase 6 : Namespaces + rotation automatique
```
