# Modèle de menace STRIDE — Constellation CMDB

Modélisation formelle des menaces selon **STRIDE** (Microsoft, 1999).
Complète l'audit statique `security-audit.md` en offrant une vue par **catégorie de menace** plutôt que par **primitive technique**.

- Périmètre : `api/app/**`, `frontend/js/**`, `frontend/nginx.conf`, `schema.sql`, `docker-compose.yml`
- Hypothèse de déploiement : **VPN WireGuard obligatoire + SSO proxy (Authelia/Authentik/Keycloak)**. Expo Internet directe = **non supporté**.
- Version évaluée : post-commit `0aeba83` (rotation secrets) + hardening container du 2026-04-21.

---

## Diagramme de confiance (Data Flow Diagram)

```
┌──────────────────────────────────────────────────────────────────────┐
│                         ZONE PUBLIQUE (interdite)                     │
│                                                                       │
│   Attaquants Internet ──X──► bloqué (pas d'expo publique)            │
└──────────────────────────────────────────────────────────────────────┘
                                │
                                │ WireGuard (wg0 / wg1)
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│                       ZONE PRIVÉE VPN (semi-trust)                    │
│                                                                       │
│   ┌──────────┐   SSO     ┌──────────┐     ┌──────────────────────┐  │
│   │ Admin UI │──────────►│ Traefik  │────►│ Authelia/Authentik   │  │
│   │ (navig.) │ cookie    │ + TLS    │     │ (Remote-User header) │  │
│   └──────────┘           └──────────┘     └──────────────────────┘  │
│                                │                                      │
│                                │ Remote-User: alice                   │
│                                ▼                                      │
│   ┌──────────┐  Bearer   ┌────────────────────────────────────────┐  │
│   │ Ansible  │──────────►│       CMDB API (FastAPI, uvicorn)       │  │
│   │ Trivy    │ collect   │  ┌──────────────────────────────────┐  │  │
│   │ Scripts  │ token     │  │ SecurityMiddleware (rate + BF)   │  │  │
│   └──────────┘           │  │ require_permission(scope, mode)  │  │  │
│                          │  │ validate_uuid() + log_action()   │  │  │
│                          │  └──────────────────────────────────┘  │  │
│                          └─────────────┬──────────────────────────┘  │
│                                        │                              │
│                       ┌────────────────┼──────────────────────┐      │
│                       ▼                ▼                      ▼      │
│                  ┌─────────┐     ┌──────────┐         ┌──────────┐  │
│                  │ PG 17   │     │ rhorizon │         │ Matrix   │  │
│                  │ (volume)│     │ (vault)  │         │ (notify) │  │
│                  └─────────┘     └──────────┘         └──────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

**Frontières de confiance** :
1. **Internet → VPN** : WireGuard auth crypto. Hors scope CMDB.
2. **VPN → Traefik** : TLS + SSO forward-auth.
3. **Traefik → API** : réseau Docker `traefik_proxy`, IP source dans `172.16-20.x.` = trusted proxy.
4. **API → PG** : réseau Docker interne `cmdb_internal`, pas de port exposé.
5. **API → rhorizon** : Bearer token vault (scope `secrets:r` namespace `cmdb`).

---

## STRIDE — Matrice complète

### S — Spoofing (usurpation d'identité)

| # | Menace | Vecteur | Mitigation en place | Résiduel |
|---|---|---|---|---|
| S1 | Forge du header `Remote-User` | Requête avec `Remote-User: admin` depuis le VPN | `_is_trusted_proxy()` rejette le header si IP ∉ `172.16-20.x.` (préfixe avec point terminal, pas de bypass `172.160.x`) | **Très faible** |
| S2 | Usurpation token Bearer | Brute-force ou fuite | Tokens 43 chars random (~10⁵⁷ combinaisons) + HMAC-SHA512 hashés en DB avec clé per-instance (`TOKEN_HMAC_KEY`). Dump DB seul = inutile. | **Négligeable** |
| S3 | Replay de session SSO | Cookie Authelia volé | Hors périmètre CMDB — cookie géré par Authelia (session TTL + SameSite=Strict) | Dépend d'Authelia |
| S4 | Impersonation sur l'audit log | Token admin volé → actions attribuées à la victime | Rotation 330d/365d + révocation instantanée + `last_used_at` traçable | **Faible** |
| S5 | DNS hijack sur webhook outbound | Webhook Matrix/Mattermost redirigé vers C2 | Validation URL à la création (`validate_url`) mais DNS résolu à la requête (rebinding possible) | **Faible** (admin compromis requis) |

**Sévérité catégorie : FAIBLE** — toutes les mitigations structurelles sont en place.

---

### T — Tampering (altération)

| # | Menace | Vecteur | Mitigation en place | Résiduel |
|---|---|---|---|---|
| T1 | Injection SQL | Payload dans hostname/cve_id/query param | 100% paramètres nommés (`:param`). F-strings uniquement sur identifiants whitelisted (`_SORT_MAP`, `_TRIGGER_ROUTE_FIELD`). `validate_uuid()` avant query. | **Négligeable** |
| T2 | Altération de l'audit log | DELETE / UPDATE direct en DB | Pas de route DELETE/PATCH sur `audit_log`. Accès PG uniquement via uid=1500 (non-root). | **Très faible** |
| T3 | Modification de payload ingestion | Ansible collecte falsifiée via MITM | WireGuard chiffre tout. `collect_token` Bearer (scope write-only, ne peut pas lire). | **Négligeable** |
| T4 | CSV formula injection | Hostname `=HYPERLINK(...)` → ouvert dans Excel | `_sanitize_csv_cell()` dans `export.py:31` préfixe `'` sur caractères dangereux (`=`, `+`, `-`, `@`, `\t`, `\r`) + 6 tests | **Négligeable** |
| T5 | Schema tampering via migration race | Deux workers appliquent `schema.sql` en parallèle | `pg_try_advisory_lock(42)` au startup — un seul worker migre | **Négligeable** |
| T6 | Altération du container (filesystem) | RCE dans un container → persistance | `read_only: true` + `cap_drop: ALL` + `no-new-privileges` + tmpfs `/tmp` uniquement en écriture | **Très faible** |
| T7 | Altération des dépendances Python | Compromise PyPI / typosquat | Versions pinnées dans `requirements.txt` + `pip-audit` fail on fixable CVE en CI | **Faible** |

**Sévérité catégorie : FAIBLE**.

---

### R — Repudiation (déni d'action)

| # | Menace | Vecteur | Mitigation en place | Résiduel |
|---|---|---|---|---|
| R1 | Admin nie avoir fermé un incident | Pas de trace | `audit_log` append-only pour toute action sensible (incident patch, CVE workflow, token create/delete, settings update) | **Négligeable** |
| R2 | Opérateur nie avoir déclenché une rotation | Log tronqué | Pattern `log_action(db, actor, action, target_type, target_id, detail)` sur chaque mutation. `detail JSONB` pour le diff. | **Négligeable** |
| R3 | Ambiguïté sur l'acteur | Token partagé entre scripts | Recommandation : un token par collecteur (Ansible ≠ Trivy ≠ Wazuh). `last_used_at` par token | **Faible** (dépend de l'ops) |
| R4 | Suppression de l'export audit | CSV altéré hors-ligne | Export signé ? Non. Intégrité garantie uniquement côté DB. | **Faible** — à documenter pour la gouvernance |

**Sévérité catégorie : FAIBLE**.

---

### I — Information Disclosure (divulgation)

| # | Menace | Vecteur | Mitigation en place | Résiduel |
|---|---|---|---|---|
| I1 | Dump de la base de données volé | Backup mal protégé | Tokens hashés HMAC-SHA512 avec `TOKEN_HMAC_KEY` per-instance (hors DB). Secrets sensibles (matrix_token, smtp_password…) chiffrés Fernet. | **Très faible** |
| I2 | Leak via logs | Token dans URL ou message d'erreur | Tokens jamais loggés. Swagger désactivé par défaut (`ENABLE_SWAGGER=false`). Logs uvicorn = access only. | **Négligeable** |
| I3 | Leak via CORS | Origin attaquante lit la réponse | `ALLOWED_ORIGINS=[]` par défaut → CORS refuse tout sauf opt-in explicite | **Négligeable** |
| I4 | SSRF sortant vers méta-données cloud | Webhook `http://169.254.169.254/latest/meta-data/` | `validate_url(url, allow_private=False)` bloque link-local/loopback/RFC1918 sauf opt-in `webhooks` (self-hosted Matrix) | **Faible** |
| I5 | Timing attack sur comparaison token | Mesure de latence par byte différent | `hmac.compare_digest()` (constant-time) sur toutes les comparaisons `.env` tokens. `_const_eq()` dans `auth.py`. | **Négligeable** |
| I6 | Leak via réponse API en liste | Énumération des tokens en clair | Listing tokens → hash tronqué 12 chars seulement, valeur affichée une seule fois à la création | **Négligeable** |
| I7 | Headers sensibles leaked vers fetch upstream | Authorization forwardé à rhorizon par erreur | httpx avec headers explicites uniquement, pas de forward automatique | **Négligeable** |
| I8 | XSS reflected/stored | Injection via hostname/cve_title/note | CSP `default-src 'none'; frame-ancestors 'none'; base-uri 'none'`. `esc()` escape 5 chars HTML sur chaque sortie. `test_csp_compliance.py` garantit 0 inline handler. | **Faible** |
| I9 | Leak via messages d'erreur frontend | `innerHTML = e.message` | Remplacé par `textContent` via `_setStatus()` dans versioning.js + `_setCheckStatus()` dans repositories.js | **Négligeable** |
| I10 | Fuite via cache frontend stale-while-revalidate | Données sensibles cachées après déconnexion | Cache in-memory uniquement (perdu au refresh), pas de localStorage/sessionStorage pour les données | **Faible** |

**Sévérité catégorie : FAIBLE**.

---

### D — Denial of Service

| # | Menace | Vecteur | Mitigation en place | Résiduel |
|---|---|---|---|---|
| D1 | Flood HTTP depuis le VPN | 10k req/s | `SecurityMiddleware` : rate limit 2000 req/60s par IP (in-memory, sliding window) | **Faible** |
| D2 | Brute-force auth | Répétition de Bearer invalides | Ban 30 fails/5min → 5min ban par IP | **Très faible** |
| D3 | Upload volumineux | POST 1 GB → OOM | `client_max_body_size 20m` dans nginx. Payload JSON parsé en streaming par Pydantic. | **Faible** |
| D4 | Requête SQL lourde | Pagination désactivée via `per_page=99999` | `Query(..., le=200)` sur tous les endpoints list. Exports plafonnés à 50 rows pour les CVEs risqués. | **Faible** |
| D5 | Fork bomb dans un container | RCE + fork() en boucle | `pids_limit` non configuré — **gap identifié**. À ajouter dans le prochain lot hardening. | **Moyen** |
| D6 | OOM via SQL join cartésien | Vue mal filtrée | Index couverts + toutes les vues agrégées sont testées par pytest sur PG réel | **Faible** |
| D7 | Scheduler boucle infinie | Job `http_request` en loop | `pytest-timeout=60` + timeout httpx 10s dans les connecteurs. `FOR UPDATE SKIP LOCKED` évite double-run. | **Très faible** |
| D8 | Expansion XML entity | XXE (N/A — pas de XML parsing user-facing) | Pas d'ingestion XML acceptée (Trivy/Wazuh envoient du JSON) | **Négligeable** |
| D9 | Regex catastrophic backtracking | Hostname `a+a+a+…!` | Patterns simples dans l'app (pas de regex récursive). À auditer si nouvelles regex ajoutées. | **Très faible** |
| D10 | Vault sealed → API bloquée | Attaquant seal rhorizon | `notify` + `create_incident` restent autorisés (pas besoin de secrets CI). Scheduler loggue l'état. | **Faible** |

**Sévérité catégorie : FAIBLE** — une amélioration recommandée : `pids_limit` + `mem_limit`.

---

### E — Elevation of Privilege

| # | Menace | Vecteur | Mitigation en place | Résiduel |
|---|---|---|---|---|
| E1 | Escalade depuis `collect_token` → lecture admin | Scope `collect:w` utilisé sur `GET /nodes` | `require_permission` factory vérifie scope ET mode séparément. Collect-token ne peut PAS lire. | **Négligeable** |
| E2 | Escalade SSO viewer → admin | Groupe SSO mappé à admin par erreur | `_resolve_sso_role()` — rôle le plus élevé gagne, fallback `viewer` (least privilege) | **Faible** |
| E3 | Escalade root dans container API | RCE → pivot host | `cap_drop: ALL`, uid=1500 non-root, `no-new-privileges` bloque setuid, `read_only` bloque `/etc/sudoers` write | **Très faible** |
| E4 | Escalade via volume mount | Volume `sync_triggers` partagé | Volume propre au projet, uid 1500 cohérent entre api/sync-*. Pas de bind mount de `/` ou `/etc`. | **Négligeable** |
| E5 | Escalade via API settings | Modif d'un setting sensible sans droit | `settings:w` requis pour mutations. SSO admin only, collect-token bloqué. | **Négligeable** |
| E6 | Docker socket abuse | Container peut créer d'autres containers | Pas de `/var/run/docker.sock` monté dans les containers CMDB. Portainer géré via API HTTP, pas socket. | **Négligeable** |
| E7 | PostgreSQL superuser via ingestion | Injection SQL → DROP TABLE | SQL paramétré (T1). User PG `cmdb` = owner DB, pas `SUPERUSER`. | **Très faible** |
| E8 | Vault token scope escalation | Token rhorizon modifié pour scope `admin` | Token vault lu depuis config, jamais muté par l'API. Scope fixé par rhorizon lui-même. | **Négligeable** |

**Sévérité catégorie : NÉGLIGEABLE**.

---

## Synthèse quantitative

| Catégorie | Menaces examinées | Résiduel **Moyen** | Résiduel **Faible** | Résiduel **Très faible / Négligeable** |
|---|---:|---:|---:|---:|
| **S** Spoofing | 5 | 0 | 2 | 3 |
| **T** Tampering | 7 | 0 | 2 | 5 |
| **R** Repudiation | 4 | 0 | 2 | 2 |
| **I** Information Disclosure | 10 | 0 | 4 | 6 |
| **D** Denial of Service | 10 | **1** | 6 | 3 |
| **E** Elevation of Privilege | 8 | 0 | 1 | 7 |
| **Total** | **44** | **1** | **17** | **26** |

### Scoring

- **0** menace critique ou élevée
- **1** menace moyenne résiduelle (D5 — pids_limit / mem_limit manquants)
- **17** menaces faibles (acceptables compte tenu du modèle de déploiement VPN+SSO)

---

## Plan de traitement

| Priorité | Action | Menace traitée | Effort | Sprint |
|---|---|---|---|---|
| **1** | Ajouter `pids_limit: 200` + `mem_limit: 2g` sur chaque service dans `docker-compose.yml` | D5 | 5 LOC | Prochain |
| 2 | Documenter la policy de rotation des `collect_token` (1 par collecteur) | R3 | Doc | Idle |
| 3 | Signer les exports CSV audit (HMAC-SHA256 footer) pour la non-répudiation externe | R4 | ~20 LOC | Backlog |
| 4 | DNS rebinding mitigation (transport httpx custom résolvant l'IP avant request) | S5 / I4 | ~50 LOC complexes | Backlog |
| 5 | Retirer `style-src 'unsafe-inline'` après migration CSS classes | I8 (hardening) | ~1000 inline styles à migrer | Multi-sprint |

---

## Hypothèses

Ce modèle repose sur les hypothèses suivantes. Si une hypothèse tombe, le modèle doit être ré-évalué :

1. **Déploiement sur VPN privé** — WireGuard entre tous les nodes, pas d'expo publique.
2. **SSO proxy de confiance** — Authelia/Authentik/Keycloak sur le même host que Traefik, réseau Docker partagé.
3. **PostgreSQL non exposé** — port 5432 uniquement sur `cmdb_internal` (réseau Docker interne).
4. **rhorizon disponible** — vault sealed = CMDB restreinte mais pas compromise (notify-only).
5. **Images de base officielles** — `python:3.12-slim`, `postgres:18-trixie`, `nginx:stable-alpine` depuis Docker Hub.
6. **Opérateur unique ou petite équipe** — audit log suffit, pas de SIEM central requis.

---

## Références

- **STRIDE** — Microsoft SDL Threat Modeling, Loren Kohnfelder & Praerit Garg (1999)
- **OWASP Top 10 2021** — voir `security-audit.md`
- **MITRE ATT&CK** — tactiques mappées dans `security-audit.md`
- **NIST SP 800-154** — Guide to Data-Centric System Threat Modeling

Date du modèle : 2026-04-22. À réviser à chaque ajout de composant majeur (nouvelle route externe, nouveau connecteur, nouveau proxy).
