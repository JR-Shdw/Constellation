# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Canonical severity normalization.

Every ingest path used to lowercase the scanner's raw severity straight into
a CHECK-constrained column, so a present-but-non-canonical value (a vendor
4-tier rating, an Ubuntu/Debian band, an empty string) aborted the insert.
This maps any known scanner/vendor severity onto the canonical set
(critical/high/medium/low/unknown) once, in one place.

Vendor scales handled:
  - CVSS / Trivy / Wazuh : critical/high/medium/low/unknown (pass-through)
  - Red Hat / Microsoft / SUSE 4-tier : important->high, moderate->medium
    (these vendors have no separate "High" label — Important IS their High)
  - Ubuntu : negligible->low
  - Debian security tracker : unimportant->low (NOT "important" — opposite end)
  - misc : info/informational->low, none/untriaged/""->unknown
"""

# raw (lowercased, stripped) -> canonical. Canonical values map to themselves.
_ALIASES = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "low",
    "unimportant": "low",
    "info": "low",
    "informational": "low",
    "unknown": "unknown",
    "none": "unknown",
    "untriaged": "unknown",
    "": "unknown",
}


def normalize_severity(
    raw: str | None, *, allow_unknown: bool = True, fallback: str = "medium"
) -> str:
    """Map a scanner/vendor severity onto the canonical set.

    Anything unrecognized or empty -> 'unknown'. For columns whose CHECK
    forbids 'unknown' (drift_reports, secret_rules), pass allow_unknown=False
    and a `fallback` in {critical,high,medium,low}; an otherwise-'unknown'
    value resolves to that fallback instead.
    """
    canon = _ALIASES.get((raw or "").strip().lower(), "unknown")
    if canon == "unknown" and not allow_unknown:
        return fallback
    return canon
