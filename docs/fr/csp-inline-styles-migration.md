# Migration CSS classes — retrait `style-src 'unsafe-inline'`

Plan multi-sprints pour retirer `'unsafe-inline'` de la directive `style-src` dans
`frontend/nginx.conf` et le middleware `security_headers` de `api/app/main.py`.

## Pourquoi pas maintenant

- **1 043** occurrences de `style="..."` dans 33 fichiers
- **420** strings CSS uniques — dont certaines dynamiques avec interpolation JS
- Patterns non-migrables directement : `style="color:var(--${color})"`, `style="${_iStyle}"`, `style="${_btnStyle('var(--red)')}"`
- Testing UI nécessaire par vue -> plusieurs heures minimum

L'effort de migration > bénéfice immédiat compte tenu de la CSP déjà stricte sur `script-src`.

## Risque résiduel actuel

**Très faible**. `'unsafe-inline'` sur `style-src` seulement (pas `script-src`) n'autorise PAS l'exécution de JS — seulement des styles. Les seuls vecteurs d'attaque possibles :
- CSS exfiltration par attribute-selectors (marginal sans `script-src` ouvert)
- UI redressing (atténué par `X-Frame-Options: DENY` + `frame-ancestors 'none'`)

Priorité = **basse** dans le backlog sécurité.

## Plan d'exécution (par sprints)

### Sprint 1 — Utilities CSS (~30 min)

Ajouter dans `frontend/css/style.css` :

```css
/* Typography */
.t-red    { color: var(--red); }
.t-green  { color: var(--green); }
.t-orange { color: var(--orange); }
.t-accent { color: var(--accent); }
.t-dim    { color: var(--text-dim); }
.t-xs     { font-size: 10px; }
.t-sm     { font-size: 11px; }
.t-md     { font-size: 12px; }
.t-bold   { font-weight: 600; }
.t-bolder { font-weight: 700; }
.t-mono   { font-family: monospace; }
.t-center { text-align: center; }
.t-up     { text-transform: uppercase; letter-spacing: 1px; }
.nowrap   { white-space: nowrap; }
.hidden   { display: none; }

/* Spacing */
.mb-4  { margin-bottom: 4px; }
.mb-8  { margin-bottom: 8px; }
.mb-12 { margin-bottom: 12px; }
.mb-16 { margin-bottom: 16px; }
.mt-4  { margin-top: 4px; }
.mt-8  { margin-top: 8px; }
.mt-10 { margin-top: 10px; }
.mt-12 { margin-top: 12px; }
.mt-16 { margin-top: 16px; }
.mt-24 { margin-top: 24px; }

/* Form elements */
.f-input  { background: var(--bg-card); border: 1px solid var(--border); color: var(--text);
            padding: 6px 10px; font-family: inherit; font-size: 12px; border-radius: 3px; }
.f-accent { accent-color: var(--accent); width: 14px; height: 14px; }

/* Row highlights (replaces conditional bg) */
.row-kev      { background: rgba(224, 64, 80, 0.1); }
.row-overdue  { background: rgba(224, 64, 80, 0.08); }

/* Section headers */
.section-h { color: var(--text-dim); margin: 12px 0 8px; font-size: 11px;
             text-transform: uppercase; letter-spacing: 1px; }
```

Couvre ~**800 occurrences** sur 1043.

### Sprint 2 — Refactor JS helpers (~1 h)

Dans `frontend/js/api.js`, ajouter des helpers qui **retournent une classe** plutôt qu'un style :

```js
// AVANT
export const STYLE_BTN_PRIMARY = 'background:var(--accent);color:#000;...';

// APRÈS
export const BTN_PRIMARY = 'btn btn-primary';
export const BTN_DANGER  = 'btn btn-danger';

// AVANT
const _btnStyle = (bg) => `background:${bg};color:#fff;padding:6px 12px;...`;

// APRÈS — approche sémantique (pas de couleur libre)
const _btnClass = (variant) => `btn btn-${variant}`;
// variants: primary, danger, success, warning, neutral, dim
```

Nécessite de refacto les usages `style="${_btnStyle('var(--red)')}"` -> `class="${_btnClass('danger')}"`.

### Sprint 3 — Migration par vue (6-8 h, vue par vue)

**Ordre suggéré (du moins risqué au plus complexe)** :

| Vue | Inline styles | Difficulté |
|---|---:|---|
| `secrets.js` | 7 | Trivial |
| `compliance.js` | 6 | Trivial |
| `opencve.js` | 7 | Trivial |
| `misconf.js` | 8 | Facile |
| `packages.js` | 8 | Facile |
| `containers.js` | 1 | Trivial |
| `exposure.js` | 13 | Facile |
| `backups.js` | 13 | Moyen |
| `history.js` | 22 | Moyen |
| `updates.js` | 18 | Moyen |
| `nodes.js` | 13 | Moyen |
| `heartbeat.js` | 32 | Moyen |
| `dashboard.js` | 23 | Moyen |
| `tokens.js` | 35 | Plus long |
| `managers.js` | 24 | Plus long |
| `repositories.js` | 34 | Plus long |
| `pipelines.js` | 43 | Plus long |
| `deployments.js` | 23 | Plus long |
| `crepositories.js` | 35 | Plus long |
| `scheduler.js` | 44 | Plus long |
| `incidents.js` | 48 | Plus long |
| `automation.js` | 64 | Plus long |
| `cves.js` | 99 | **Difficile** (interpolations dynamiques) |
| `settings.js` | 274 | **Le plus dur** (forms + preview inline) |

Tester chaque vue après migration (golden path + edge cases). Commit par vue.

### Sprint 4 — Cas dynamiques restants (~2 h)

Les patterns comme `style="color:var(--${color})"` doivent devenir :

```js
// AVANT
`<span style="color:var(--${color})">${value}</span>`

// APRÈS
const COLOR_CLASSES = { red: 't-red', green: 't-green', orange: 't-orange' };
`<span class="${COLOR_CLASSES[color] || 't-dim'}">${value}</span>`
```

### Sprint 5 — Retrait `'unsafe-inline'` (~15 min)

1. Dans `frontend/nginx.conf` :
   ```
   # AVANT
   add_header Content-Security-Policy "... style-src 'self' 'unsafe-inline'; ...";
   # APRÈS
   add_header Content-Security-Policy "... style-src 'self'; ...";
   ```
2. Dans `api/app/main.py` — `security_headers()` middleware, même traitement.
3. Mettre à jour `.woodpecker/validate.yml` check-security : vérifier que `'unsafe-inline'` est absent aussi de `style-src`.
4. Tester manuellement chaque vue (pas de style cassé en console DevTools).

### Sprint 6 — Hardening CSP final (~15 min)

Ajouter la directive `require-trusted-types-for 'script'` pour forcer l'usage de Trusted Types API quand on écrit du HTML dynamique :

```
Content-Security-Policy: default-src 'none';
                         script-src 'self';
                         style-src 'self';
                         img-src 'self' data:;
                         connect-src 'self';
                         frame-ancestors 'none';
                         base-uri 'none';
                         require-trusted-types-for 'script';
```

Nécessite de passer les `innerHTML = html` par `trustedTypes.createPolicy()`.

## Métriques de succès

- `grep -rn 'style="' frontend/ | wc -l` retourne **0**
- `grep -rn "style-src 'self'" frontend/nginx.conf api/app/main.py` confirme plus de `'unsafe-inline'`
- Toutes les vues testées manuellement sans erreur console
- `test_csp_compliance.py` passe avec le check `'unsafe-inline'` absent de `style-src`

## Alternative si migration abandonnée

Si la migration n'est pas faite, documenter formellement dans `security-audit.md` :
- Pourquoi `'unsafe-inline'` est conservé
- Mitigation compensatoire : CSP strict sur `script-src` (qui reste le vecteur critique XSS)
- Revue annuelle à la date anniversaire du déploiement

Date de création du plan : 2026-04-22
