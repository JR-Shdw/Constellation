"""notify._send_once_external — atomic claim-then-send dedup + release-on-failure."""

import asyncpg
import pytest

from api.app.notify import _send_once_external

from .conftest import ASYNCPG_DSN


async def _claim_count(cve_id: str) -> int:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        rows = await conn.fetch("SELECT 1 FROM alert_sent WHERE cve_id = $1", cve_id)
        return len(rows)
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_claim_then_send_dedups_concurrent_slot():
    """First call claims + fires; a second call for the same slot skips the
    send (claim conflict) instead of double-sending."""
    cve = "CVE-2099-DEDUP1"
    calls = {"n": 0}

    async def _send():
        calls["n"] += 1

    r1 = await _send_once_external(cve, "n1", "pkg", "matrix", _send)
    assert r1 is True
    assert calls["n"] == 1
    assert await _claim_count(cve) == 1

    # Same (cve, node, target, channel) — claim conflicts, no second send.
    r2 = await _send_once_external(cve, "n1", "pkg", "matrix", _send)
    assert r2 is False
    assert calls["n"] == 1
    assert await _claim_count(cve) == 1


@pytest.mark.anyio
async def test_failed_send_releases_claim_for_retry():
    """A send that raises releases its claim, so a later ingest can retry."""
    cve = "CVE-2099-DEDUP2"
    calls = {"n": 0}

    async def _boom():
        calls["n"] += 1
        raise RuntimeError("matrix down")

    r1 = await _send_once_external(cve, "n1", "pkg", "matrix", _boom)
    assert r1 is False
    assert await _claim_count(cve) == 0  # claim released after failure

    async def _ok():
        calls["n"] += 1

    r2 = await _send_once_external(cve, "n1", "pkg", "matrix", _ok)
    assert r2 is True
    assert calls["n"] == 2  # boom then ok
    assert await _claim_count(cve) == 1
