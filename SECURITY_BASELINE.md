# Security Baseline — Constellation (CMDB)

> **Purpose** — Defines the non-negotiable security baseline for the Constellation
> codebase. Any code change touching authentication, data storage, user input,
> output rendering, secrets, or external resources MUST be reviewed against this
> document. This file is also intentionally written to prime AI-assisted review
> sessions toward strict-security mode: keep it at the repo root and reference
> it explicitly in review prompts.
>
> Companion baseline: this file mirrors the chronolion baseline so the same
> review checklist applies across Resurgamus projects. Differences from
> chronolion are documented inline (Constellation has no password storage —
> auth is fully delegated to the SSO proxy).

---

## 0. Status

| Field | Value |
|---|---|
| Project | Constellation (CMDB / CAASM) |
| Owner | shdw / Resurgamus |
| Phase | **alpha / dev** — refactor agressif autorisé, DB recréable from scratch |
| Network model | **WireGuard only** — exposition Internet directe non supportée |
| Auth model | SSO proxy (Authelia / Authentik / Keycloak) + Bearer tokens DB |
| Secrets backend | rhorizon (Resurgamus Horizon) — fallback `.env` legacy |
| Target assurance | OWASP ASVS v4 Level 2 at v0.1 cutover |
| Last reviewed | 2026-05-10 |

---

## 1. Reference Frameworks

| Framework | Version | Use |
|---|---|---|
| OWASP Top 10 | latest at owasp.org/Top10 | Risk taxonomy |
| OWASP ASVS | v4.0.3 (verify latest) | Verification checklist (target L2) |
| OWASP Cheat Sheet Series | rolling | Concrete patterns |
| MITRE ATT&CK | Enterprise current | Adversary TTP mapping |
| MITRE CWE | Top 25 current | Weakness identifiers |
| NIST SP 800-63B | rev 4 | Authenticator assurance levels (AAL2 target) |
| RFC 9106 | — | Argon2 parameters (N/A — no password storage, see §2.5) |

---

## 2. Critical Classes — Mandatory Mitigations

### 2.1 Injection — CWE-89 / 77 / 78 / 94 / 943 — **DONE**

**Surfaces**: SQL, OS command, template, header injection.

In place:
- SQLAlchemy async + asyncpg with **named parameters only** (`:param`).
  CLAUDE.md mandate : « Paramètres nommés (`:param`) uniquement — jamais de
  f-string dans le SQL ». UUID params via `CAST(:id AS uuid)`.
- ORM bind variables via `text(...)` + dict — every raw SQL reviewed in PR.
- Pydantic v2 validation on every request body / query / path.
- No `shell=True`, no `eval`, no `exec` on user-derived strings anywhere in
  `api/` or `tools/`. Subprocess calls use argv arrays (validated via Bandit).
- FastAPI / Pydantic handle header injection on responses; no raw header
  echo from user input.

Verification:
- CI : `bandit -r api/` blocks on HIGH severity (validate.yml).
- CI : `ruff check` blocks on lint errors (S-rules planned, see §7).
- Manual review of every raw `text(...)` call at PR time.

---

### 2.2 Cross-Site Scripting — CWE-79 — **DONE (custom escape stack)**

**Surfaces**: stored XSS in CVE titles, hostnames, package names, Trivy
descriptions, container labels — every field that bubbles up from external
sources (Wazuh, Trivy, Gitea, Woodpecker, OpenCVE).

In place:
- All untrusted strings passed through `esc()` / `_h()` (frontend/js/api.js).
- `_h()` is a template-literal tag : every interpolation is escaped by
  default; raw HTML requires explicit `raw(…)` opt-in (auditable).
- **XSS-ratchet test** (`tests/test_innerhtml_safety.py`) : grep over
  `frontend/js/` for `innerHTML = \`…${var}…\`` patterns that bypass `_h()`.
  Block merge if a new bypass appears.
- CI gate (validate.yml `check-security`) : grep for `onclick=`, `onchange=`,
  `oninput=`, `onsubmit=` in `frontend/js/views|panels|index.html` — fails
  the build if any inline event handler is committed.

Forbidden (enforced by review + ratchet test):
- `innerHTML = userInput` without `_h()` wrapping.
- `outerHTML`, `document.write`, `eval`, `Function()`, `setTimeout(string)`.
- `dangerouslySetInnerHTML` (no React in this stack — irrelevant but listed).
- `|safe`-style bypasses.

Deviation from chronolion : **no DOMPurify dependency**. The `_h()` template
tag plus the ratchet test give us auditable XSS protection without adding a
runtime library. Documented as a deliberate choice.

Verification:
- CI grep audit on every PR (validate.yml `check-security`).
- CSP `report-uri` planned (see §7).

---

### 2.3 Content Security Policy — CWE-1021 — **DONE (without nonces)**

**Frontend (nginx.conf)** — JSON SPA, no inline scripts allowed:

```
Content-Security-Policy:
  default-src 'self';
  script-src  'self';
  style-src   'self';
  font-src    'self';
  img-src     'self' data:;
  frame-ancestors 'none';
  base-uri    'self';
  form-action 'self';
```

**API (api/app/main.py)** — JSON-only, locked down:

```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'
```

**Companion headers (in place)** :

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY (api) / SAMEORIGIN (frontend)
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store (api responses)
```

CI enforcement (validate.yml `check-security`) :
- script-src must NOT contain `unsafe-inline` or `unsafe-eval`.
- style-src must NOT contain `unsafe-eval`.
- API CSP must keep `default-src 'none'`.
- nginx must serve `X-Frame-Options` and `X-Content-Type-Options`.

Deviation from chronolion :
- **No nonce** : `script-src 'self'` is sufficient because the SPA loads
  zero inline scripts (enforced by the CI gate above). Nonce would be
  defense-in-depth without changing the threat model.
- **No COOP / CORP / Permissions-Policy report-to** yet — see §7.

Verification target : observatory.mozilla.org A grade
(A+ requires nonces — accepted as §7 debt).

---

### 2.4 Memory Safety / Overflow — CWE-120 / 787 / 125 — **N/A**

The CMDB is Python 3.12 + JS only. No C / C++ / FFI surface in our code.
Native dependencies (asyncpg, cryptography, etc.) are tracked by `pip-audit`
in CI ; CVEs there are flagged as fixable and block the build.

If a parser-on-untrusted-bytes component is added later (e.g. custom binary
protocol), §2.4 of chronolion baseline applies as-is.

---

### 2.5 Password Storage — CWE-916 / 522 — **N/A (no password storage)**

Constellation **never stores user passwords**. User authentication is fully
delegated to the SSO proxy (Authelia / Authentik / Keycloak / LDAP),
mapped to roles (admin / ops / viewer) via group headers (see §2.7).

What we *do* store : **API tokens** for service-to-service auth (Ansible
collect, Trivy scan, scheduler triggers). These are **not** human passwords :

| Property | Value |
|---|---|
| Token format | 43 random chars (`secrets.token_urlsafe(32)`), ≥256 bits entropy |
| At rest | HMAC-SHA512 (per-instance `TOKEN_HMAC_KEY`), 128-char hex digest |
| Display | First 12 chars of hash only — raw token shown ONCE at creation |
| Comparison | `hmac.compare_digest` (constant-time) |

Why HMAC-SHA512 and not Argon2id : Argon2 is designed to slow brute-force
of low-entropy human-chosen passwords. Random 256-bit tokens have ~10^77
combinations — brute-force is mathematically infeasible regardless of hash
function. HMAC keyed with a per-instance secret adds a hard wall against
offline DB-dump attacks (attacker without `TOKEN_HMAC_KEY` cannot test
token candidates). Trade-off: documented and accepted.

**File**: `api/app/auth.py:hash_token()`

---

### 2.6 Data-at-Rest Encryption — **DONE (secrets) / DOCUMENTED (asset data)**

In place :
- **Secrets in DB settings** : `alert_settings` rows whose key is in
  `_SECRET_KEYS` (vault tokens, Gitea/Woodpecker tokens, SMTP creds, etc.)
  are encrypted with Fernet via `api/app/crypto.py:encrypt_setting()`.
- **API tokens** : stored as HMAC-SHA512 hash, not plaintext (§2.5).
- **rhorizon (Horizon)** : canonical source for high-value secrets
  (`cmdb-secret-key`, `cmdb-collect-token`, `cmdb-token-hmac-key`,
  forge tokens, OpenCVE creds). Loaded at API startup via Bearer token,
  cached in `settings`. See CLAUDE.md §"Intégration rhorizon (Phase 3)".
- **Vault sealed guard** : when rhorizon is configured, every privileged
  execution path (scheduler, CI/CD trigger, deployments, automation)
  refuses to run if the vault is sealed.

Deliberately not encrypted at field level :
- CVE rows, package inventory, container metadata, scan results — these
  are the asset graph itself. Encrypting them at field level breaks every
  query (filter, sort, aggregate) and adds zero protection inside our
  threat model (attacker with DB read = attacker with API admin =
  game over either way).

Host-level :
- vega FS encryption status : **TODO** — verify and document
  (LUKS at OS install, or accept as residual risk for alpha phase).
- Backups : Restic with repo password in rhorizon. Restore drill cadence
  documented in observability stack runbook.

Verification : quarterly restore test from encrypted backup, on isolated
host (currently best-effort, see §7).

---

### 2.7 Authentication — RFC 4422 / NIST 800-63B AAL2 — **DONE**

User auth (delegated) :
- SSO proxy required (Authelia / Authentik / Keycloak / LDAP).
- Group headers (`Remote-Groups`, `X-Auth-Groups`, `X-Forwarded-Groups`)
  trusted **only** when source IP is in `_TRUSTED_PROXIES`
  (172.16-20.x — Docker reverse-proxy networks).
  Forge from any other network = ignored.
- 2FA / WebAuthn / passkeys : **responsibility of the SSO proxy**, not the
  CMDB. Authelia and Authentik both support WebAuthn natively.
- Role mapping : DB-backed (`alert_settings.sso_group_mappings`),
  highest role wins (admin > ops > viewer). SSO ops/viewer = read-only,
  mode `w` is rejected for those roles regardless of scope.

Service-to-service auth :
- Bearer tokens (≥256 bits, opaque, server-validated).
- Two privilege-separated legacy tokens : `COLLECT_TOKEN` (write-only on
  collect endpoints) and `SECRET_KEY` (admin). Both deprecated in favor
  of granular DB tokens.
- DB tokens : 13 scopes × {r, w} permissions, expiry, last-used tracking.
- All token validation via `hmac.compare_digest` (timing-safe).

Brute-force / rate limiting (`api/app/security.py`) :
- In-memory rate limiter per IP : 2000 req / 60s default (configurable).
- Brute-force tracker on 401/403 with `Authorization: Bearer …` →
  IP banned after `bf_max_failures` failures within `bf_window_seconds`,
  for `bf_ban_seconds`.
- Loopback (127.0.0.1) bypassed (scheduler / internal).
- Goal stated in code : « catch a misbehaving script, not harden against
  internet bots » — because the CMDB is on WG only.

Honey tokens (`api/app/honey.py`) :
- Tokens flagged `is_honey=TRUE` in DB authenticate normally (no signal
  to attacker) but fire a Matrix alert on every use. Convention :
  realistic-looking names like `portainer-readonly`.

Cookies : N/A — no cookie-based session in the CMDB API. SSO proxy owns
session cookies (Secure / HttpOnly / SameSite enforced upstream).

Verification : ASVS V2 + V3 chapter checklist before v0.1 cutover.

---

### 2.8 Credential Leak — Detection & Remediation (Horizon-integrated) — **PARTIAL**

**Prevention** :
- CI (validate.yml `lint-and-sast`) : `detect-secrets` scan on every PR,
  excluding `.git/`, `env.example`, `.env`, `tests/`. Flagged secrets
  printed to log for review (currently report-only — should block, see §7).
- `pip-audit -r api/requirements.txt` blocks merge on any **fixable** CVE.
- `bandit -r api/` blocks merge on HIGH severity findings.
- `.gitignore` covers `.env`, `*.pem`, `*.key`. `env.example` only.
- Production secrets resolved from rhorizon at startup ; `.env` legacy
  fallback kept for dev only.

**Runbook on detected leak** :
1. Mark credential compromised in rhorizon (UI or CLI).
2. rhorizon rotates the secret and propagates to consumers.
3. For CMDB tokens : `UPDATE api_tokens SET active=FALSE WHERE id=…`,
   force-rotate `TOKEN_HMAC_KEY` if the leak is the master HMAC key
   itself (invalidates all DB tokens — accepted, requires re-issue).
4. Audit log entry : who, when, where, propagation latency.
5. Post-mortem : how it leaked, add detection rule (regex / entropy
   threshold) so the same shape is caught next time.
6. If leaked publicly (GitHub, paste site) : file takedown request,
   assume third-party scrape, treat as fully compromised regardless.

Drill cadence : **TODO** — quarterly tabletop, annual live rotation drill
in staging. Currently not scheduled (see §7).

---

## 3. MITRE ATT&CK — Relevant Techniques

| Tactic | Technique | Primary mitigation in CMDB |
|---|---|---|
| Initial Access | T1190 Exploit Public-Facing App | WG-only network, no public exposure ; pip-audit + Trivy in CI |
| Initial Access | T1078 Valid Accounts | SSO MFA upstream ; brute-force tracker ; honey tokens |
| Execution | T1059 Command/Scripting Interp. | No `shell=True`, argv arrays, Bandit gate |
| Persistence | T1098 Account Manipulation | `audit_log` table, RBAC review at PR time |
| Credential Access | T1110 Brute Force | `security.py` IP ban, SSO MFA, 256-bit tokens |
| Credential Access | T1552 Unsecured Credentials | rhorizon, `detect-secrets`, settings encryption |
| Defense Evasion | T1070 Indicator Removal | `audit_log` (TODO append-only role, see §7) |
| Collection | T1213 Data from Repositories | Granular permission scopes, `validate_uuid()` everywhere |
| Exfiltration | T1041 Exfil over C2 Channel | SSRF guard (`security.validate_url`) blocks RFC1918 + loopback |

---

## 4. CI/CD Tooling — Required Gates

State of the actual pipelines under `.woodpecker/` :

| Stage | Tool | Status | Blocking on |
|---|---|---|---|
| pre-commit | gitleaks / trufflehog / ruff | **TODO** (§7) | — |
| PR | ruff (lint + format) | DONE (`validate.yml`) | any error |
| PR | bandit (SAST) | DONE | HIGH severity |
| PR | pip-audit | DONE | any **fixable** CVE |
| PR | detect-secrets | DONE (report-only) | nothing — should block, §7 |
| PR | pytest + coverage ≥80% | DONE | tests / coverage |
| PR | docker compose config | DONE | invalid config |
| PR | CSP / inline-handler grep | DONE (`check-security`) | any inline handler |
| build / cron | Trivy image scan (HIGH/CRITICAL) | DONE (`scan.yml`) | report-only → CMDB |
| build / cron | Nuclei DAST | DONE | report-only |
| pre-deploy | OWASP ZAP baseline | **N/A** — Nuclei covers DAST role |
| post-deploy | continuous deps watch | DONE — pipelines re-run on schedule + push to main |

Equivalence note : chronolion uses semgrep + ZAP, Constellation uses
bandit + Nuclei. Both cover the SAST + DAST roles ; we don't run both
to keep the pipeline fast.

---

## 5. Out of Scope (alpha) — Deferred to Hardening Phase

- [ ] Full ASVS L2 walkthrough with sign-off
- [ ] Internal pentest (Resurgamus) or external pentest
- [ ] Bug bounty / responsible disclosure policy (the project is Apache-2.0 —
      open issues on Gitea or contact@resurgamus.com is the current
      reporting path)
- [ ] Formal threat model (STRIDE per component)
- [ ] SOC2-aligned audit log retention (currently best-effort — `audit_log`
      table grows unbounded, archival loop exists in `main.py` but
      retention policy not yet formalized)

---

## 6. Phase Markers

- [x] **alpha phase** — fast iteration, conscious security debt tracked
      in §7. Refactor agressif et schema recreation autorisés.
- [ ] **v0.1 cutover** — when this checkbox flips, change §0 status to
      "STRICT" and require paranoid review on every change touching the
      surfaces in §2.

---

## 7. Known Debt — Remediate Before v0.1 Cutover

> One ticket per item. Update this list whenever new debt is added or resolved.

**High priority (security gaps that change the threat model)** :
- [ ] `detect-secrets` in CI is report-only — **must block merge on any
      finding** that is not in the baseline allowlist.
- [ ] No pre-commit hooks (`gitleaks`, `trufflehog`, `ruff`, `bandit`).
      CI catches everything but pre-commit shortens the feedback loop and
      prevents secret commits from ever reaching the remote.
- [ ] vega host FS encryption (LUKS) status — verify and document.
- [ ] `audit_log` writable by the application role — should be append-only
      (separate Postgres role with `INSERT` only, no `UPDATE` / `DELETE`),
      with archival via a privileged reaper job.
- [ ] Quarterly leak-remediation drill not yet scheduled (rotation of a
      throwaway rhorizon secret in staging, end-to-end).

**Medium priority (defense-in-depth)** :
- [ ] CSP `report-uri` / `report-to` to catch missed XSS sinks in prod.
- [ ] CSP nonce-based `script-src` (defense-in-depth on top of the
      existing `'self'` + zero-inline-handler enforcement).
- [ ] `Cross-Origin-Opener-Policy: same-origin` and
      `Cross-Origin-Resource-Policy: same-origin` headers.
- [ ] Trusted Types API on the frontend (browsers that support it).
- [ ] HSTS `preload` flag + submission to hstspreload.org once domain is
      stable.
- [ ] ruff `S` (bandit-equivalent) and `B` (bugbear) rule sets in
      `pyproject.toml` for stricter inline checks at edit time.

**Low priority (process / documentation)** :
- [ ] Add ASVS V2 + V3 sign-off checklist to v0.1 cutover ticket.
- [ ] Document the `_h()` / XSS-ratchet decision so future reviewers don't
      ask "why no DOMPurify".
- [ ] Threat model session — STRIDE per route module.

---

## 8. Review Cadence

- **Weekly (alpha)** : triage scan results from `scan.yml` cron, update §7
  if new debt discovered, close items as they ship.
- **Pre-cutover** : full §2 + §4 walkthrough, sign-off required.
- **Post-cutover** : monthly drift check (compare nginx headers, CSP, CI
  gates against this file), quarterly leak-remediation drill.

---

*Maintained by shdw — Resurgamus Informatique*
*Mirrors the chronolion baseline. Diff intentional where Constellation
has no password storage and runs on a closed network only.*
