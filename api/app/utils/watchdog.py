# DO NOT REMOVE: SPDX header + copyright are part of the Apache-2.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Constellation - Author: shdw - License: Apache-2.0
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""API health watchdog - detect pool/PG saturation, push Matrix alerts.

Designed as the missing piece behind the 2026-05-11 incident: zombie
sessions held locks for 60h and the API saturated silently because
nothing was wired to alert on the WARNINGs the existing pool/db
activity loggers already emit. This module turns those signals into
state-machined notifications that fire on transition (not on every
tick) and emit a resolution event when the symptom clears.

Each uvicorn worker runs its own evaluation loop, but a PG advisory
lock around the actual notification call ensures only one worker out
of N sends each event. Trim staggers the start so 4 workers don't all
poll pg_stat_activity at the same instant.
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field

from sqlalchemy import text

from ..config import settings
from ..database import async_session, db_activity_snapshot, pool_snapshot
from ..notify import send_automation_notification

logger = logging.getLogger(__name__)

# Advisory lock id reserved for watchdog notification fan-out. 42 is
# used by schema migration in main.py; 43 leaves a gap and stays out
# of the way of any other future locks.
_ADVISORY_LOCK_ID = 43


@dataclass
class _TripwireState:
    """Per-tripwire state machine: ok -> triggered -> notified -> resolved."""

    name: str
    triggered_at: float | None = None  # time.monotonic when first detected
    notified_at: float | None = None  # last notification timestamp
    last_payload: dict = field(default_factory=dict)

    def is_triggered(self) -> bool:
        return self.triggered_at is not None

    def should_notify(self, cooldown: float) -> bool:
        """True if we may emit a notification right now (cooldown elapsed)."""
        if not self.is_triggered():
            return False
        if self.notified_at is None:
            return True
        return (time.monotonic() - self.notified_at) >= cooldown

    def mark_triggered(self, payload: dict) -> None:
        if self.triggered_at is None:
            self.triggered_at = time.monotonic()
        self.last_payload = payload

    def mark_notified(self) -> None:
        self.notified_at = time.monotonic()

    def mark_resolved(self) -> bool:
        """Reset state. Returns True iff a transition actually happened."""
        was = self.is_triggered()
        self.triggered_at = None
        self.notified_at = None
        self.last_payload = {}
        return was


_STATES: dict[str, _TripwireState] = {}


def _state(name: str) -> _TripwireState:
    if name not in _STATES:
        _STATES[name] = _TripwireState(name=name)
    return _STATES[name]


# Tripwire checks - pure functions for testability.


def _check_pool_saturated(pool_snap: dict, _db_snap: dict) -> tuple[bool, dict]:
    """Pool has no free slot or overflow is heavily in use."""
    free = pool_snap.get("free")
    overflow_used = pool_snap.get("overflow_used") or 0
    threshold = settings.watchdog_overflow_alert_threshold
    if free == 0 or overflow_used >= threshold:
        return True, {
            "free": free,
            "in_use": pool_snap.get("in_use"),
            "overflow_used": overflow_used,
            "total_capacity": pool_snap.get("total_capacity"),
            "pid": os.getpid(),
        }
    return False, {}


def _check_idle_in_tx(_pool_snap: dict, db_snap: dict) -> tuple[bool, dict]:
    """At least one PG session is `idle in transaction` past threshold."""
    threshold = settings.watchdog_idle_in_tx_threshold_seconds
    candidates = [
        q
        for q in db_snap.get("slow", [])
        if q.get("wait") == "idle-in-tx" and (q.get("age_s") or 0) >= threshold
    ]
    if not candidates:
        return False, {}
    worst = max(candidates, key=lambda q: q.get("age_s") or 0)
    return True, {
        "count": len(candidates),
        "oldest_age_s": worst.get("age_s"),
        "oldest_pid": worst.get("pid"),
        "oldest_app": worst.get("app"),
        "oldest_query": worst.get("query"),
    }


def _check_query_stuck(_pool_snap: dict, db_snap: dict) -> tuple[bool, dict]:
    """At least one active (non-idle-in-tx) query past threshold."""
    threshold = settings.watchdog_query_stuck_threshold_seconds
    candidates = [
        q
        for q in db_snap.get("slow", [])
        if q.get("wait") != "idle-in-tx" and (q.get("age_s") or 0) >= threshold
    ]
    if not candidates:
        return False, {}
    worst = max(candidates, key=lambda q: q.get("age_s") or 0)
    return True, {
        "count": len(candidates),
        "oldest_age_s": worst.get("age_s"),
        "oldest_pid": worst.get("pid"),
        "oldest_wait": worst.get("wait"),
        "oldest_query": worst.get("query"),
    }


def _check_lock_pileup(_pool_snap: dict, db_snap: dict) -> tuple[bool, dict]:
    """Multiple queries blocked on locks - usually a stuck tx upstream."""
    threshold = settings.watchdog_lock_pileup_threshold
    blocked = db_snap.get("blocked", []) or []
    if len(blocked) < threshold:
        return False, {}
    return True, {"count": len(blocked), "sample": blocked[:3]}


_CHECKS = {
    "pool_saturated": _check_pool_saturated,
    "idle_in_tx_stuck": _check_idle_in_tx,
    "query_stuck": _check_query_stuck,
    "lock_pileup": _check_lock_pileup,
}


# Message formatting


def _format_message(tripwire: str, payload: dict, is_resolution: bool = False) -> str:
    """Build a human-readable Matrix message for a tripwire event."""
    prefix = "RESOLVED" if is_resolution else "ALERT"
    host = os.uname().nodename
    if is_resolution:
        return f"[CMDB:{host}] {prefix} {tripwire} - symptom cleared"

    if tripwire == "pool_saturated":
        return (
            f"[CMDB:{host}] {prefix} pool_saturated - worker pid={payload.get('pid')} "
            f"in_use={payload.get('in_use')}/{payload.get('total_capacity')} "
            f"overflow={payload.get('overflow_used')} free={payload.get('free')}"
        )
    if tripwire == "idle_in_tx_stuck":
        cnt = payload.get("count")
        pid = payload.get("oldest_pid")
        age = payload.get("oldest_age_s")
        app = payload.get("oldest_app")
        q = payload.get("oldest_query")
        return (
            f"[CMDB:{host}] {prefix} idle_in_tx_stuck - "
            f"{cnt} session(s), oldest pid={pid} age={age}s app={app}\n"
            f"query: {q}"
        )
    if tripwire == "query_stuck":
        cnt = payload.get("count")
        pid = payload.get("oldest_pid")
        age = payload.get("oldest_age_s")
        wait = payload.get("oldest_wait")
        q = payload.get("oldest_query")
        return (
            f"[CMDB:{host}] {prefix} query_stuck - "
            f"{cnt} query/queries, oldest pid={pid} age={age}s wait={wait}\n"
            f"query: {q}"
        )
    if tripwire == "lock_pileup":
        return (
            f"[CMDB:{host}] {prefix} lock_pileup - "
            f"{payload.get('count')} queries blocked on locks"
        )
    return f"[CMDB:{host}] {prefix} {tripwire}: {payload}"


# Notification dispatch with advisory-locked fan-out


async def _notify(tripwire: str, payload: dict, is_resolution: bool = False) -> None:
    """Send a Matrix/webhook notification for a tripwire event.

    Wrapped in `pg_try_advisory_lock(43)` so only one worker out of N
    actually sends the alert. If another worker holds the lock we just
    skip silently - the event is still being emitted somewhere.
    """
    msg = _format_message(tripwire, payload, is_resolution=is_resolution)
    try:
        async with async_session() as db:
            row = await db.execute(
                text("SELECT pg_try_advisory_lock(:lid)"),
                {"lid": _ADVISORY_LOCK_ID},
            )
            if not row.scalar_one():
                logger.debug(
                    "[watchdog] another worker holds notify lock for %s", tripwire
                )
                return
            try:
                await send_automation_notification(
                    trigger_type="api_health",
                    message=msg,
                    db=db,
                )
            finally:
                await db.execute(
                    text("SELECT pg_advisory_unlock(:lid)"),
                    {"lid": _ADVISORY_LOCK_ID},
                )
    except Exception as e:
        logger.warning("[watchdog] notify failed for %s: %s", tripwire, e)


# Public API


def watchdog_snapshot() -> dict:
    """Snapshot of all tripwire states - exposed via /health/watchdog."""
    return {
        name: {
            "triggered": state.is_triggered(),
            "triggered_at": state.triggered_at,
            "notified_at": state.notified_at,
            "payload": state.last_payload,
        }
        for name, state in _STATES.items()
    }


async def evaluate_once(
    pool_snap: dict | None = None, db_snap: dict | None = None
) -> dict:
    """One evaluation pass - exposed for tests and the loop body.

    Returns the post-evaluation state snapshot. Notifications are sent
    as a side effect. Pool/db snapshots can be injected for tests.
    """
    if pool_snap is None:
        pool_snap = pool_snapshot()
    if db_snap is None:
        db_snap = await db_activity_snapshot(
            slow_query_seconds=min(
                settings.watchdog_idle_in_tx_threshold_seconds,
                settings.watchdog_query_stuck_threshold_seconds,
            )
        )
    cooldown = settings.watchdog_cooldown_seconds
    for name, check in _CHECKS.items():
        state = _state(name)
        triggered, payload = check(pool_snap, db_snap)
        if triggered:
            state.mark_triggered(payload)
            if state.should_notify(cooldown):
                await _notify(name, payload)
                state.mark_notified()
        else:
            if state.mark_resolved():
                await _notify(name, {}, is_resolution=True)
    return watchdog_snapshot()


async def watchdog_loop() -> None:
    """Background loop running once per worker.

    Started from the FastAPI lifespan. Staggered start across workers
    to avoid all 4 hitting pg_stat_activity simultaneously every tick.
    """
    if not settings.watchdog_enabled:
        logger.info("[watchdog] disabled by settings")
        return

    interval = settings.watchdog_interval_seconds
    cooldown = settings.watchdog_cooldown_seconds
    pid = os.getpid()
    await asyncio.sleep(pid % max(interval, 1))

    logger.info(
        "[watchdog] starting pid=%s interval=%ss cooldown=%ss",
        pid,
        interval,
        cooldown,
    )

    while True:
        try:
            await evaluate_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("[watchdog] tick failed")
        await asyncio.sleep(interval)


def reset_state_for_tests() -> None:
    """Drop all tripwire state - test fixture only."""
    _STATES.clear()
