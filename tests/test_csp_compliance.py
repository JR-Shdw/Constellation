"""CSP compliance — verify frontend JS has no inline event handlers.

These tests enforce Content-Security-Policy readiness:
- No onclick/onchange/oninput/onsubmit in JS template literals
- All interactive elements use data-action (click) or data-change (change)
- Every data-action value maps to a registered handler in app.js
- No orphan handlers (registered but never used in any view)

Runs without a browser — pure static analysis of JS source files.
"""

import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "js"
VIEWS_DIR = FRONTEND / "views"
PANELS_DIR = FRONTEND / "panels"
APP_JS = FRONTEND / "app.js"
INDEX_HTML = FRONTEND.parent / "index.html"

# Files to scan for inline handlers
_JS_FILES = sorted(
    list(VIEWS_DIR.glob("*.js")) + list(PANELS_DIR.glob("*.js")) + [APP_JS]
)
_ALL_FILES = _JS_FILES + [INDEX_HTML]

# Inline event handler attributes that violate CSP script-src 'self'
# Matches onclick="..." in HTML, NOT el.onclick = fn (JS assign)
_INLINE_RE = re.compile(
    r"\bon(click|change|input|submit|keydown|keyup|mousedown|mouseup|focus|blur)"
    r'\s*=\s*"',
    re.IGNORECASE,
)

# data-action="xxx" and data-change="xxx" in templates
_DATA_ACTION_RE = re.compile(r'data-action="([^"]+)"')
_DATA_CHANGE_RE = re.compile(r'data-change="([^"]+)"')

# Handler registrations in app.js: _actions = { name, } or _changes = { name: ..., }


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _extract_registry_keys(block_text: str) -> set[str]:
    """Extract handler names from a JS object literal block (shorthand + explicit).

    Only matches top-level properties (2-space indent within block).
    Nested arrow function bodies (4+ spaces) are skipped.
    """
    keys = set()
    for line in block_text.splitlines():
        # Only top-level object properties (2 spaces indent inside block)
        if not re.match(r"^  \w", line):
            continue
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        # Explicit key: "name: value"
        m = re.match(r"(\w+)\s*:", stripped)
        if m:
            keys.add(m.group(1))
            continue
        # Shorthand entries: "name, name, name,"
        for m in re.finditer(r"(\w+)\s*[,}]", stripped):
            keys.add(m.group(1))
    return keys


def _find_inline_handlers(text: str, filepath: str) -> list[str]:
    """Return list of 'file:line — match' for every inline handler found."""
    violations = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in _INLINE_RE.finditer(line):
            snippet = line.strip()[:120]
            violations.append(f"{filepath}:{i} — {snippet}")
    return violations


# Tests


def test_no_inline_onclick():
    """No onclick= in any JS view, panel, or app.js."""
    violations = []
    for f in _ALL_FILES:
        if not f.exists():
            continue
        text = _read(f)
        for v in _find_inline_handlers(text, f.name):
            if "onclick=" in v.lower():
                violations.append(v)
    assert not violations, (
        f"{len(violations)} inline onclick= found (CSP violation):\n"
        + "\n".join(violations[:30])
    )


def test_no_inline_onchange():
    """No onchange= in any JS view, panel, or app.js."""
    violations = []
    for f in _ALL_FILES:
        if not f.exists():
            continue
        text = _read(f)
        for v in _find_inline_handlers(text, f.name):
            if "onchange=" in v.lower():
                violations.append(v)
    assert not violations, (
        f"{len(violations)} inline onchange= found (CSP violation):\n"
        + "\n".join(violations[:30])
    )


def test_no_inline_handlers_any():
    """No inline event handlers of any kind."""
    violations = []
    for f in _ALL_FILES:
        if not f.exists():
            continue
        violations.extend(_find_inline_handlers(_read(f), f.name))
    assert not violations, (
        f"{len(violations)} inline handlers found (CSP violation):\n"
        + "\n".join(violations[:30])
    )


def test_data_actions_have_handlers():
    """Every data-action used in views/panels has a handler in _actions."""
    if not APP_JS.exists():
        return
    app_text = _read(APP_JS)

    # Extract registered action names from _actions = { ... }
    # Find the _actions block
    m = re.search(r"const _actions\s*=\s*\{(.+?)\n\};", app_text, re.DOTALL)
    if not m:
        # _actions not yet created — skip
        return
    registered = _extract_registry_keys(m.group(1))

    # Collect all data-action values used in views + panels
    used = set()
    for f in _JS_FILES + [INDEX_HTML]:
        if not f.exists():
            continue
        for action in _DATA_ACTION_RE.findall(_read(f)):
            used.add(action)

    # Built-in actions handled directly in the click dispatcher
    builtins = {
        "setTab",
        "goPage",
        "hideEl",
        "closeDetail",
        "toggleFullscreen",
        "toggleSidebar",
        "toggleMobileMenu",
        "toggleMobileNavMode",
        "toggleNavGroup",
    }
    missing = used - registered - builtins
    assert not missing, "data-action values without handler in _actions:\n" + "\n".join(
        sorted(missing)
    )


def test_data_changes_have_handlers():
    """Every data-change used in views/panels has a handler in _changes."""
    if not APP_JS.exists():
        return
    app_text = _read(APP_JS)

    m = re.search(r"const _changes\s*=\s*\{(.+?)\n\};", app_text, re.DOTALL)
    if not m:
        return
    registered = _extract_registry_keys(m.group(1))

    used = set()
    for f in _JS_FILES + [INDEX_HTML]:
        if not f.exists():
            continue
        for change in _DATA_CHANGE_RE.findall(_read(f)):
            used.add(change)

    missing = used - registered
    assert not missing, "data-change values without handler in _changes:\n" + "\n".join(
        sorted(missing)
    )


def test_no_orphan_actions():
    """No registered handler that is never used in any template."""
    if not APP_JS.exists():
        return
    app_text = _read(APP_JS)

    m = re.search(r"const _actions\s*=\s*\{(.+?)\n\};", app_text, re.DOTALL)
    if not m:
        return
    registered = _extract_registry_keys(m.group(1))

    used = set()
    for f in _JS_FILES + [INDEX_HTML]:
        if not f.exists():
            continue
        for action in _DATA_ACTION_RE.findall(_read(f)):
            used.add(action)

    orphans = registered - used
    # Allow some actions that might be called programmatically
    orphans -= {"closeDetail", "toggleFullscreen", "toggleSidebar"}
    assert not orphans, (
        "Registered _actions handlers never used in templates:\n"
        + "\n".join(sorted(orphans))
    )


def test_no_window_fn_assignments():
    """app.js should not expose functions via window.fn = fn (use delegation)."""
    if not APP_JS.exists():
        return
    text = _read(APP_JS)
    # Match window.fnName = fnName; (the old pattern)
    # Exclude state/framework vars: currentView, currentPage, loadView, etc.
    # which are state/framework, not onclick handlers
    allowed = {
        "currentView",
        "currentPage",
        "loadView",
        "refreshView",
        "getFilterType",
        "getFilterSeverity",
        "getFilterNode",
        "getFilterPackage",
        "getFilterTable",
        "getFilterHostname",
        "navigate",
    }
    pattern = re.compile(r"^window\.(\w+)\s*=", re.MULTILINE)
    assignments = []
    for m in pattern.finditer(text):
        name = m.group(1)
        if name not in allowed and not name.startswith("_"):
            assignments.append(f"  window.{name}")
    assert not assignments, (
        "window.fn assignments found (use event delegation instead):\n"
        + "\n".join(assignments[:30])
    )


# CSP / inline style hardening

# Ratchet: count of inline style="..." across frontend files.
# This number MUST ONLY decrease. Lower it when you migrate more styles to CSS classes.
# When it reaches 0, drop 'unsafe-inline' from style-src in nginx.conf + api/main.py.
_INLINE_STYLE_BUDGET = 0

_STYLE_ATTR_RE = re.compile(r'style="[^"]*"')


def test_inline_styles_not_regressing():
    """Inline style="..." count must stay <= budget (ratchet)."""
    count = 0
    for f in _ALL_FILES:
        if not f.exists():
            continue
        count += len(_STYLE_ATTR_RE.findall(_read(f)))
    assert count <= _INLINE_STYLE_BUDGET, (
        f"Inline styles regressed: {count} > budget {_INLINE_STYLE_BUDGET}. "
        f"Migrate new inline styles to CSS classes in frontend/css/style.css."
    )
    if count < _INLINE_STYLE_BUDGET:
        print(
            f"\n[info] Inline style budget can be lowered: "
            f"{_INLINE_STYLE_BUDGET} → {count} in tests/test_csp_compliance.py"
        )


def test_csp_nginx_style_src_no_unsafe_eval():
    """nginx CSP style-src must be 'self' only — no unsafe-*."""
    nginx = Path(__file__).resolve().parent.parent / "frontend" / "nginx.conf"
    if not nginx.exists():
        return
    text = nginx.read_text(encoding="utf-8")
    m = re.search(r"style-src[^;]*", text)
    assert m, "nginx.conf has no style-src directive in CSP"
    directive = m.group(0)
    assert "'self'" in directive, f"style-src missing 'self': {directive}"
    assert "'unsafe-eval'" not in directive, (
        f"style-src must never include 'unsafe-eval': {directive}"
    )
    assert "'unsafe-inline'" not in directive, (
        f"style-src must never include 'unsafe-inline': {directive}"
    )


def test_csp_nginx_script_src_hardened():
    """nginx CSP script-src must never loosen beyond 'self'."""
    nginx = Path(__file__).resolve().parent.parent / "frontend" / "nginx.conf"
    if not nginx.exists():
        return
    text = nginx.read_text(encoding="utf-8")
    m = re.search(r"script-src[^;]*", text)
    assert m, "nginx.conf has no script-src directive"
    directive = m.group(0)
    assert "'self'" in directive, f"script-src missing 'self': {directive}"
    assert "'unsafe-inline'" not in directive, (
        f"script-src must never include 'unsafe-inline': {directive}"
    )
    assert "'unsafe-eval'" not in directive, (
        f"script-src must never include 'unsafe-eval': {directive}"
    )


def test_csp_api_main_locked():
    """api/app/main.py security_headers middleware must keep default-src 'none'."""
    main_py = Path(__file__).resolve().parent.parent / "api" / "app" / "main.py"
    if not main_py.exists():
        return
    text = main_py.read_text(encoding="utf-8")
    assert "default-src 'none'" in text, (
        "api/app/main.py CSP must keep 'default-src \\'none\\''"
    )
    # Extract the CSP string to check for unsafe-* tokens
    m = re.search(
        r"Content-Security-Policy[^\n]*?['\"]([^'\"]+)['\"]", text
    )
    if m:
        csp = m.group(1)
        assert "'unsafe-inline'" not in csp, (
            f"api/app/main.py CSP must never include 'unsafe-inline': {csp}"
        )
        assert "'unsafe-eval'" not in csp, (
            f"api/app/main.py CSP must never include 'unsafe-eval': {csp}"
        )


def test_escjs_not_needed():
    """After CSP migration, escJs() should no longer be needed (no onclick context)."""
    uses = []
    for f in _JS_FILES:
        if not f.exists():
            continue
        text = _read(f)
        for i, line in enumerate(text.splitlines(), 1):
            if "escJs(" in line and "import" not in line:
                uses.append(f"{f.name}:{i}")
    # escJs is only needed for onclick="fn('${escJs(x)}')" context
    # With data-action + data-id, we use esc() for HTML attributes instead
    assert not uses, (
        "escJs() still used (should be replaced by esc() in data-* attributes):\n"
        + "\n".join(uses[:20])
    )
