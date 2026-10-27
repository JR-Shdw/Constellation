"""innerHTML XSS safety ratchet — every `${...}` injected into innerHTML
must be wrapped in `esc(...)` or returned by a whitelisted helper that
escapes internally.

Pure static analysis; no browser. Mirrors the CSP ratchet pattern in
test_csp_compliance.py — current count locked as budget, must only
decrease. Goal: 0 (every interpolation explicitly escaped).
"""

import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "js"

_JS_FILES = sorted(FRONTEND.rglob("*.js"))

# Helpers known to return safe/escaped HTML. Adding to this list = audit
# the helper to confirm it escapes user input internally.
_SAFE_HELPERS = {
    "esc",
    "_h",  # attestation: HTML chunk already escaped at source — see api.js
    "typeBadges",
    "exposureBadge",
    "txtColor",
    "timeAgo",
    "formatBytes",
    "paginator",
    "tabBar",
    "renderEmpty",
    "loadingDots",
    "Number",
    "String",
    "JSON.stringify",
}

# innerHTML = <RHS>; — RHS captured up to the closing semicolon (handles
# multi-line template literals).
_ASSIGN_RE = re.compile(
    r"\.innerHTML\s*=\s*(`(?:[^`\\]|\\.)*`|[^;]+);",
    re.DOTALL,
)
_INTERP_RE = re.compile(r"\$\{([^{}]+(?:\{[^{}]*\}[^{}]*)*)\}")

_SAFE_IDENT = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_SAFE_LITERAL = re.compile(r"^[\d\s+\-*/().<>?:!=&|`'\",]+$")
_SAFE_CALL = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*\(")


def _is_safe(expr: str) -> bool:
    e = expr.strip()
    if not e:
        return True
    if _SAFE_LITERAL.match(e):
        return True
    if _SAFE_IDENT.match(e):
        return True
    m = _SAFE_CALL.match(e)
    if m and m.group(1) in _SAFE_HELPERS:
        return True
    return False


def _unsafe_interpolations() -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for f in _JS_FILES:
        text = f.read_text(encoding="utf-8")
        for m in _ASSIGN_RE.finditer(text):
            rhs = m.group(1)
            if "${" not in rhs:
                continue
            line = text[: m.start()].count("\n") + 1
            for im in _INTERP_RE.finditer(rhs):
                expr = im.group(1)
                if not _is_safe(expr):
                    findings.append((f.name, line, expr.strip()[:80]))
    return findings


# Ratchet: must only decrease. Lower as you migrate to esc()/helpers.
_INNERHTML_BUDGET = 0


def test_innerhtml_interpolations_not_regressing():
    """Unsafe ${expr} count in innerHTML stays <= budget."""
    findings = _unsafe_interpolations()
    count = len(findings)
    if count > _INNERHTML_BUDGET:
        sample = "\n".join(f"  {f}:{ln} -> {e}" for f, ln, e in findings[:20])
        raise AssertionError(
            f"Unsafe innerHTML interpolations regressed: {count} > "
            f"budget {_INNERHTML_BUDGET}. Wrap with esc() or use a "
            f"whitelisted helper. Sample:\n{sample}"
        )
    if count < _INNERHTML_BUDGET:
        # Loud success — prompts the dev to lower the ratchet.
        print(
            f"\n[info] innerHTML budget can be lowered: "
            f"{_INNERHTML_BUDGET} -> {count} in tests/test_innerhtml_safety.py"
        )
