# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CVE finding score computation.

Score is contextual to the infrastructure — NOT a global CVE property.
Range: 0–100.

This MUST stay in lockstep with the SQL `cve_score()` function in
`schema.sql`: the list view (`/cves`) serves the stored `score` column
computed by `cve_score()` at write time, while the CVE detail panel and
the findings `/score` what-if endpoints recompute here. Any drift makes
the same finding show two different scores depending on the view.
`tests/test_score_parity.py` pins the two implementations together.
"""


def compute_score(
    cvss_score: float | None,
    exploited: bool,
    listen: str,
    fix_status: str,
    exploitability_context: str,
    severity: str | None,
) -> int:
    # Base CVSS (0–10 → 0–50)
    score = float(cvss_score or 0) * 5

    # Distro severity down-grade: trust Debian/RHEL/... when it rates a CVE
    # low/medium despite a high NVD CVSS (backported fixes, disputed /
    # not-affected). Applied to the base before exposure/exploit bonuses,
    # mirroring cve_score().
    if severity == "low":
        score = min(score, 15)
    elif severity == "medium" and score > 35:
        score = 35

    # Known exploited (+25)
    if exploited:
        score += 25

    # Network exposure
    exposure_bonus = {
        "internet": 20,
        "private_network": 10,
        "docker_internal": 5,
        "localhost": 2,
    }
    score += exposure_bonus.get(listen, 5)

    # Fix available increases urgency (+8); vendor won't-fix / not-affected
    # cap or zero the score (mutually exclusive fix_status values).
    if fix_status == "fixed_available":
        score += 8
    elif fix_status == "will_not_fix":
        score = min(score, 10)
    elif fix_status == "not_affected":
        score = 0

    # Reduce for exploitation difficulty
    context_penalty = {
        "requires_auth": -10,
        "requires_local_access": -15,
        "requires_user_interaction": -8,
        "likely_exploitable": 5,  # bonus
        "unclear": 0,
    }
    score += context_penalty.get(exploitability_context, 0)

    # cve_score() casts a numeric to integer (round half away from zero),
    # then clamps. On the non-negative clamped domain that is round-half-up.
    return min(100, max(0, int(score + 0.5) if score >= 0 else int(score - 0.5)))
