"""Lockstep parity: Python compute_score() == SQL cve_score().

The list view serves the stored `score` column (written by the SQL
`cve_score()`), while the CVE detail panel and the findings `/score`
what-if endpoints recompute via the Python `compute_score()`. If the two
drift, the same finding shows different scores depending on the view.
This test pins them together over the full input grid against real PG.
"""

import itertools

import asyncpg
import pytest

from api.app.utils.score import compute_score

from .conftest import ASYNCPG_DSN

# Cover the boundaries that matter: the .5 CVSS values exercise PG's
# numeric round-half-away-from-zero vs Python truncation; severity and
# fix_status exercise the caps; every listen / exploit context branch.
_CVSS = [None, 0.0, 0.1, 2.5, 4.9, 5.0, 7.5, 9.8, 10.0]
_EXPLOITED = [False, True]
_LISTEN = ["internet", "private_network", "docker_internal", "localhost", "unknown"]
_FIX = ["fixed_available", "will_not_fix", "not_affected", "unfixed", "affected"]
_CTX = [
    "requires_auth",
    "requires_local_access",
    "requires_user_interaction",
    "likely_exploitable",
    "unclear",
    "weird_unknown",
]
_SEV = [None, "low", "medium", "high", "critical"]


@pytest.mark.anyio
async def test_compute_score_matches_sql_cve_score():
    conn = await asyncpg.connect(ASYNCPG_DSN)
    mismatches = []
    try:
        for cvss, exploited, listen, fix, ctx, sev in itertools.product(
            _CVSS, _EXPLOITED, _LISTEN, _FIX, _CTX, _SEV
        ):
            sql = await conn.fetchval(
                "SELECT cve_score($1::numeric, $2, $3, $4, $5, $6)",
                cvss,
                exploited,
                listen,
                fix,
                ctx,
                sev,
            )
            py = compute_score(
                cvss_score=cvss,
                exploited=exploited,
                listen=listen,
                fix_status=fix,
                exploitability_context=ctx,
                severity=sev,
            )
            if py != sql:
                mismatches.append(
                    f"cvss={cvss} expl={exploited} listen={listen} fix={fix} "
                    f"ctx={ctx} sev={sev}: py={py} sql={sql}"
                )
    finally:
        await conn.close()

    assert not mismatches, "Python/SQL score drift:\n" + "\n".join(mismatches[:20])
