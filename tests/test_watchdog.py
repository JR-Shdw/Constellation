# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Watchdog tripwires + state machine + Matrix dispatch."""

import pytest

from api.app.utils import watchdog


@pytest.fixture(autouse=True)
def _reset_watchdog_state():
    """Each test starts with a clean tripwire state."""
    watchdog.reset_state_for_tests()
    yield
    watchdog.reset_state_for_tests()


# Tripwire detection (pure)


def test_pool_saturated_fires_on_free_zero():
    triggered, payload = watchdog._check_pool_saturated(
        {"free": 0, "in_use": 30, "overflow_used": 0, "total_capacity": 30}, {}
    )
    assert triggered is True
    assert payload["free"] == 0
    assert payload["in_use"] == 30


def test_pool_saturated_fires_on_overflow_above_threshold():
    triggered, _ = watchdog._check_pool_saturated(
        {"free": 5, "in_use": 25, "overflow_used": 15, "total_capacity": 30}, {}
    )
    assert triggered is True


def test_pool_saturated_quiet_when_healthy():
    triggered, _ = watchdog._check_pool_saturated(
        {"free": 20, "in_use": 10, "overflow_used": 0, "total_capacity": 30}, {}
    )
    assert triggered is False


def test_idle_in_tx_fires_above_threshold():
    db_snap = {
        "slow": [
            {
                "wait": "idle-in-tx",
                "age_s": 90,
                "pid": 123,
                "app": "cmdb_api",
                "query": "ROLLBACK;",
            },
        ]
    }
    triggered, payload = watchdog._check_idle_in_tx({}, db_snap)
    assert triggered is True
    assert payload["oldest_pid"] == 123
    assert payload["oldest_age_s"] == 90


def test_idle_in_tx_ignores_active_queries():
    """active queries with another wait_event must not trigger this tripwire."""
    db_snap = {
        "slow": [
            {"wait": "Lock:relation", "age_s": 500, "pid": 1, "query": "SELECT"},
        ]
    }
    triggered, _ = watchdog._check_idle_in_tx({}, db_snap)
    assert triggered is False


def test_query_stuck_fires_above_threshold():
    db_snap = {
        "slow": [
            {"wait": "IO:DataFileRead", "age_s": 240, "pid": 7, "query": "SELECT *"},
        ]
    }
    triggered, payload = watchdog._check_query_stuck({}, db_snap)
    assert triggered is True
    assert payload["oldest_pid"] == 7


def test_query_stuck_ignores_idle_in_tx():
    db_snap = {
        "slow": [
            {"wait": "idle-in-tx", "age_s": 500, "pid": 7, "query": "ROLLBACK;"},
        ]
    }
    triggered, _ = watchdog._check_query_stuck({}, db_snap)
    assert triggered is False


def test_lock_pileup_fires_above_threshold():
    db_snap = {"blocked": [{"pid": i} for i in range(7)]}
    triggered, payload = watchdog._check_lock_pileup({}, db_snap)
    assert triggered is True
    assert payload["count"] == 7


def test_lock_pileup_quiet_below_threshold():
    db_snap = {"blocked": [{"pid": 1}, {"pid": 2}]}
    triggered, _ = watchdog._check_lock_pileup({}, db_snap)
    assert triggered is False


# State machine + dispatch


@pytest.mark.anyio
async def test_evaluate_once_triggers_and_notifies(monkeypatch):
    """First tick triggered → _notify called once, state transitions."""
    sent = []

    async def fake_notify(name, payload, is_resolution=False):
        sent.append((name, is_resolution))

    monkeypatch.setattr(watchdog, "_notify", fake_notify)

    pool_snap = {"free": 0, "in_use": 30, "overflow_used": 20, "total_capacity": 30}
    db_snap = {"slow": [], "blocked": []}

    state = await watchdog.evaluate_once(pool_snap, db_snap)
    assert state["pool_saturated"]["triggered"] is True
    assert ("pool_saturated", False) in sent


@pytest.mark.anyio
async def test_evaluate_once_cooldown_blocks_second_notify(monkeypatch):
    """Re-trigger within cooldown → no second notif."""
    sent = []

    async def fake_notify(name, payload, is_resolution=False):
        sent.append((name, is_resolution))

    monkeypatch.setattr(watchdog, "_notify", fake_notify)

    pool_snap = {"free": 0, "in_use": 30, "overflow_used": 20, "total_capacity": 30}
    db_snap = {"slow": [], "blocked": []}

    await watchdog.evaluate_once(pool_snap, db_snap)
    await watchdog.evaluate_once(pool_snap, db_snap)
    # Only the first tick notifies; the second is still within cooldown.
    assert sent == [("pool_saturated", False)]


@pytest.mark.anyio
async def test_evaluate_once_emits_resolution(monkeypatch):
    """Triggered then cleared → resolution notif fires."""
    sent = []

    async def fake_notify(name, payload, is_resolution=False):
        sent.append((name, is_resolution))

    monkeypatch.setattr(watchdog, "_notify", fake_notify)

    trig = {"free": 0, "in_use": 30, "overflow_used": 20, "total_capacity": 30}
    ok = {"free": 20, "in_use": 10, "overflow_used": 0, "total_capacity": 30}
    db_snap = {"slow": [], "blocked": []}

    await watchdog.evaluate_once(trig, db_snap)
    await watchdog.evaluate_once(ok, db_snap)

    assert ("pool_saturated", False) in sent  # alert
    assert ("pool_saturated", True) in sent  # resolution


@pytest.mark.anyio
async def test_evaluate_once_no_resolution_when_never_triggered(monkeypatch):
    """Clean state stays clean - no spurious resolution notif."""
    sent = []

    async def fake_notify(name, payload, is_resolution=False):
        sent.append((name, is_resolution))

    monkeypatch.setattr(watchdog, "_notify", fake_notify)

    ok = {"free": 20, "in_use": 10, "overflow_used": 0, "total_capacity": 30}
    db_snap = {"slow": [], "blocked": []}
    await watchdog.evaluate_once(ok, db_snap)

    assert sent == []


# Message formatting


def test_message_pool_saturated_human_readable():
    msg = watchdog._format_message(
        "pool_saturated",
        {"pid": 42, "in_use": 30, "total_capacity": 30, "overflow_used": 20, "free": 0},
    )
    assert "pool_saturated" in msg
    assert "pid=42" in msg
    assert "30/30" in msg


def test_message_idle_in_tx_includes_query_excerpt():
    msg = watchdog._format_message(
        "idle_in_tx_stuck",
        {
            "count": 1,
            "oldest_pid": 7,
            "oldest_age_s": 120,
            "oldest_app": "cmdb_api",
            "oldest_query": "ROLLBACK;",
        },
    )
    assert "pid=7" in msg
    assert "ROLLBACK" in msg


def test_message_resolution_short():
    msg = watchdog._format_message("query_stuck", {}, is_resolution=True)
    assert "RESOLVED" in msg
    assert "query_stuck" in msg


# Endpoint


@pytest.mark.anyio
async def test_health_watchdog_endpoint(client, auth):
    """GET /api/v1/health/watchdog returns the tripwire state dict."""
    r = await client.get("/api/v1/health/watchdog", headers=auth)
    assert r.status_code == 200
    # Empty state on fresh boot is OK; the endpoint just returns whatever
    # is in memory for this worker.
    assert isinstance(r.json(), dict)
