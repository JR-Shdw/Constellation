# DO NOT REMOVE: SPDX header + copyright are part of the Apache-2.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Constellation · Author: shdw · License: Apache-2.0
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
# -----------------------------------------------------------------------------
# Constellation - (c) 2024-2026 shdw <contact@resurgamus.com> - Apache-2.0
# Self-hosted CAASM/CMDB platform
# -----------------------------------------------------------------------------
"""Constellation API entry point - FastAPI app with lifespan migrations.

Author: shdw <contact@resurgamus.com>
Project: Constellation - open-source CAASM/CMDB platform.
License: Apache-2.0
See: NOTICE, LICENSE
"""

import logging

# Uvicorn's default logging only configures `uvicorn*` loggers — `app.*`
# loggers fall through to the unconfigured root and lastResort drops INFO.
# Attach a root handler before any app.* import so logger.info() reaches stderr.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

import asyncio  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from pathlib import Path  # noqa: E402

import asyncpg  # noqa: E402
from fastapi import Depends, FastAPI, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from .auth import require_auth, require_permission  # noqa: E402
from .config import settings  # noqa: E402
from .routes import (  # noqa: E402
    audit,
    automation,
    backup,
    cicd,
    collect,
    container_images,
    cve_feeds,
    deployments,
    drift,
    export,
    filters,
    findings,
    heartbeat,
    history,
    incidents,
    itsm,
    managers,
    metrics,
    misconf,
    opencve,
    pkg_repositories,
    pkg_updates,
    plugins,
    read,
    repositories,
    resync,
    retention,
    sbom,
    sca,
    scan,
    scheduler,
    tokens,
    webhooks_itsm,
)
from .routes import settings as settings_router  # noqa: E402
from .security import SecurityMiddleware  # noqa: E402

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path("/app/migrations/schema.sql")


MIGRATIONS_DIR = Path("/app/migrations")


def _split_sql(sql: str) -> list[str]:
    """Split SQL into individual statements, respecting $$ blocks."""
    statements = []
    current = []
    in_dollar = False
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") and not in_dollar:
            continue
        if "$$" in line:
            in_dollar = not in_dollar
        current.append(line)
        if not in_dollar and stripped.endswith(";"):
            stmt = "\n".join(current).strip()
            if stmt and stmt != ";":
                statements.append(stmt)
            current = []
    if current:
        stmt = "\n".join(current).strip()
        if stmt and stmt != ";":
            statements.append(stmt)
    return statements


async def _apply_schema():
    """Run migrations + schema.sql on startup, statement by statement.

    Uses a PG advisory lock so only one worker applies the schema
    when running with multiple uvicorn workers.
    """
    if not SCHEMA_PATH.exists() or SCHEMA_PATH.is_dir():
        logger.warning("schema.sql not found at %s, skipping", SCHEMA_PATH)
        return
    dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    try:
        # Advisory lock — only one worker runs migrations
        acquired = await conn.fetchval("SELECT pg_try_advisory_lock(42)")
        if not acquired:
            logger.info("schema migration: another worker holds the lock, skipping")
            return

        # 1. Migrations (each file as single block, errors ignored)
        if MIGRATIONS_DIR.exists():
            for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
                try:
                    await conn.execute(f.read_text())
                except Exception:
                    logger.debug("migration %s skipped (already applied)", f.name)

        # 2. Schema.sql as single block (all DROPs at top, then CREATE)
        try:
            await conn.execute(SCHEMA_PATH.read_text())
            logger.info("schema.sql applied successfully")
        except Exception as e:
            logger.warning("schema.sql failed: %s", str(e)[:200])

        # 3. Re-run migrations (some depend on schema tables)
        if MIGRATIONS_DIR.exists():
            for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
                try:
                    await conn.execute(f.read_text())
                except Exception:
                    logger.debug("migration %s skipped (already applied)", f.name)

        await conn.execute("SELECT pg_advisory_unlock(42)")
    finally:
        await conn.close()


async def _load_db_settings():
    """Load config overrides from alert_settings table (DB > env vars).

    Only overrides keys that are empty in env vars — env takes priority
    when explicitly set, DB fills the gaps for UI-configured values.
    """
    dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
    config_keys = {
        "woodpecker_url",
        "woodpecker_token",
        "gitea_url",
        "gitea_token",
        "gitlab_url",
        "gitlab_token",
        "forgejo_url",
        "forgejo_token",
        "opencve_web_url",
        "opencve_url",
        "opencve_user",
        "opencve_password",
        "vault_url",
        "vault_token",
    }
    try:
        conn = await asyncpg.connect(dsn)
        try:
            rows = await conn.fetch(
                "SELECT key, value FROM alert_settings WHERE key = ANY($1)",
                list(config_keys),
            )
            from .crypto import decrypt_setting

            for row in rows:
                # Only override if env var is empty
                if not getattr(settings, row["key"], ""):
                    value = decrypt_setting(row["value"]) if row["value"] else ""
                    # Skip corrupted masked values that leaked into DB
                    if value == "********":
                        logger.warning(
                            "config from DB: %s has masked value, skipping",
                            row["key"],
                        )
                        continue
                    setattr(settings, row["key"], value)
                    logger.info("config from DB: %s", row["key"])
        finally:
            await conn.close()
    except Exception:
        logger.debug("alert_settings not available yet, skipping DB config")


_VAULT_DISCOVER_URLS = [
    "http://rhorizon_api:8200",
    "http://rhorizon-api:8200",
    "http://rhorizon:8200",
]


async def _discover_vault():
    """Auto-discover rhorizon on the Docker network if not configured."""
    if settings.vault_url:
        return
    import httpx

    for url in _VAULT_DISCOVER_URLS:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{url}/api/v1/vault/status")
                if r.status_code == 200:
                    settings.vault_url = url
                    logger.info("vault auto-discovered at %s", url)
                    return
        except Exception:
            continue


async def _load_vault_secrets():
    """Load secrets from rhorizon if configured.

    Overrides .env values for sensitive keys. Falls back silently
    if vault is unavailable or sealed — .env values remain.
    """
    await _discover_vault()

    if not settings.vault_url or not settings.vault_token:
        return

    import httpx

    # Map: vault secret name → settings attribute
    secret_map = {
        "cmdb-secret-key": "secret_key",
        "cmdb-collect-token": "collect_token",
        "cmdb-token-hmac-key": "token_hmac_key",
        "cmdb-woodpecker-token": "woodpecker_token",
        "cmdb-gitea-token": "gitea_token",
        "cmdb-gitlab-token": "gitlab_token",
        "cmdb-forgejo-token": "forgejo_token",
        "cmdb-opencve-password": "opencve_password",
    }

    headers = {"Authorization": f"Bearer {settings.vault_token}"}
    loaded = 0

    try:
        async with httpx.AsyncClient(base_url=settings.vault_url, timeout=10) as client:
            # Check vault is unsealed
            r = await client.get("/api/v1/vault/status")
            if r.status_code != 200 or r.json().get("sealed"):
                logger.warning(
                    "vault at %s is sealed or unreachable — using .env",
                    settings.vault_url,
                )
                return

            for vault_name, attr in secret_map.items():
                try:
                    r = await client.get(
                        f"/api/v1/vault/secrets/{vault_name}",
                        headers=headers,
                    )
                    if r.status_code == 200:
                        setattr(settings, attr, r.json()["value"])
                        loaded += 1
                    # 404 = secret not in vault, keep .env value
                except Exception as e:
                    logger.debug("vault secret %s unavailable: %s", vault_name, e)

        if loaded:
            logger.info(
                "vault: loaded %d secret(s) from %s", loaded, settings.vault_url
            )
    except Exception as e:
        logger.warning("vault unreachable (%s) — using .env secrets", str(e)[:100])


_ENCRYPT_KEYS = {
    "matrix_token",
    "woodpecker_token",
    "gitea_token",
    "gitlab_token",
    "forgejo_token",
    "opencve_password",
    "vault_token",
    "smtp_password",
}


async def _migrate_encrypt_settings():
    """One-time migration: encrypt plaintext secrets in alert_settings."""
    from .crypto import ENC_PREFIX, encrypt_setting

    dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
    try:
        conn = await asyncpg.connect(dsn)
        try:
            rows = await conn.fetch(
                "SELECT key, value FROM alert_settings WHERE key = ANY($1)",
                list(_ENCRYPT_KEYS),
            )
            migrated = 0
            for row in rows:
                if row["value"] and not row["value"].startswith(ENC_PREFIX):
                    encrypted = encrypt_setting(row["value"])
                    await conn.execute(
                        "UPDATE alert_settings SET value = $1 WHERE key = $2",
                        encrypted,
                        row["key"],
                    )
                    migrated += 1
            if migrated:
                logger.info(
                    "encrypted %d plaintext secret(s) in alert_settings",
                    migrated,
                )
        finally:
            await conn.close()
    except Exception:
        logger.debug("settings encryption migration skipped (table not ready)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _load_vault_secrets()
    try:
        await _apply_schema()
    except Exception:
        logger.exception("schema migration failed — API starts without it")
    await _load_db_settings()

    # Encrypt any plaintext secrets still in alert_settings
    await _migrate_encrypt_settings()

    # Load SSO group mappings from DB
    try:
        from .auth import reload_group_mappings
        from .database import async_session

        async with async_session() as db:
            await reload_group_mappings(db)
    except Exception:
        logger.debug("SSO group mappings not loaded yet, using builtins")

    # Start scheduler background loop
    from .scheduler import cleanup_stale_runs, initialize_next_runs, scheduler_loop

    await cleanup_stale_runs()
    await initialize_next_runs()
    scheduler_task = asyncio.create_task(scheduler_loop())

    archiver_task: asyncio.Task | None = None
    if settings.audit_compact_interval_hours > 0:
        archiver_task = asyncio.create_task(_audit_archiver_loop())

    pool_logger_task: asyncio.Task | None = None
    if settings.db_pool_log_interval > 0:
        pool_logger_task = asyncio.create_task(_pool_logger_loop())

    db_activity_task: asyncio.Task | None = None
    if settings.db_activity_log_interval > 0:
        db_activity_task = asyncio.create_task(_db_activity_logger_loop())

    # Cross-worker automation cache invalidation via PG NOTIFY/LISTEN
    from .routes.automation import listener_loop as _automation_listener_loop

    automation_listener_task = asyncio.create_task(_automation_listener_loop())

    # API health watchdog — pool/PG saturation tripwires + Matrix alerts
    from .utils.watchdog import watchdog_loop

    watchdog_task: asyncio.Task | None = None
    if settings.watchdog_enabled:
        watchdog_task = asyncio.create_task(watchdog_loop())

    yield

    scheduler_task.cancel()
    if archiver_task:
        archiver_task.cancel()
    if pool_logger_task:
        pool_logger_task.cancel()
    if db_activity_task:
        db_activity_task.cancel()
    automation_listener_task.cancel()
    if watchdog_task:
        watchdog_task.cancel()
    for t in (
        scheduler_task,
        archiver_task,
        pool_logger_task,
        db_activity_task,
        automation_listener_task,
        watchdog_task,
    ):
        if t is None:
            continue
        try:
            await t
        except asyncio.CancelledError:
            pass


async def _pool_logger_loop():
    """Log SQLAlchemy pool stats when under pressure.

    Emits at WARNING when free slots drop below `db_pool_warn_free`
    or any overflow connection is in use. Otherwise stays silent.
    Runs once per `db_pool_log_interval` seconds in every uvicorn
    worker (so the worker id appears via the standard logging
    `process` field — useful to correlate per-worker leaks).
    """
    import os

    from .database import pool_snapshot

    interval = settings.db_pool_log_interval
    warn_free = settings.db_pool_warn_free
    pid = os.getpid()
    while True:
        try:
            snap = pool_snapshot()
            free = snap.get("free")
            overflow_used = snap.get("overflow_used") or 0
            in_use = snap.get("in_use") or 0
            total = snap.get("total_capacity")
            under_pressure = (free is not None and free <= warn_free) or (
                overflow_used > 0
            )
            if under_pressure:
                logger.warning(
                    "[pool] pid=%s in_use=%s free=%s overflow=%s total=%s",
                    pid,
                    in_use,
                    free,
                    overflow_used,
                    total,
                )
            else:
                logger.debug(
                    "[pool] pid=%s in_use=%s free=%s overflow=%s",
                    pid,
                    in_use,
                    free,
                    overflow_used,
                )
        except Exception:
            logger.exception("[pool] logger loop tick failed")
        await asyncio.sleep(interval)


async def _db_activity_logger_loop():
    """Log pg_stat_activity when something looks bad.

    Emits WARNING when a query is running ≥ db_activity_slow_seconds,
    when any query is blocked on a lock, or when the total connection
    count to this database exceeds db_activity_warn_total. Otherwise
    stays silent. Runs once per worker — but the snapshot reflects
    the WHOLE database (all workers + sync containers + ansible
    scripts), so a single noisy worker is enough; that's expected.
    """
    import os

    from .database import db_activity_snapshot

    interval = settings.db_activity_log_interval
    slow_threshold = settings.db_activity_slow_seconds
    warn_total = settings.db_activity_warn_total
    pid = os.getpid()
    # Stagger workers so 4 uvicorn processes don't all hit pg_stat_activity
    # at the same instant.
    await asyncio.sleep(pid % interval)
    while True:
        try:
            snap = await db_activity_snapshot(slow_query_seconds=slow_threshold)
            total = snap["total"]
            states = snap["states"]
            slow = snap["slow"]
            blocked = snap["blocked"]

            problems = []
            if total >= warn_total:
                problems.append(f"total={total}")
            if slow:
                problems.append(f"slow={len(slow)}")
            if blocked:
                problems.append(f"blocked={len(blocked)}")
            iit = states.get("idle in transaction", 0)
            if iit >= 5:
                problems.append(f"idle_in_tx={iit}")

            if problems:
                logger.warning(
                    "[db] pid=%s %s states=%s by_source=%s",
                    pid,
                    " ".join(problems),
                    states,
                    snap["by_source"],
                )
                # Detail dump for actionable items
                for q in slow[:5]:
                    logger.warning(
                        "[db] slow pid=%s age=%ss app=%s wait=%s sql=%s",
                        q["pid"],
                        q["age_s"],
                        q.get("app"),
                        q.get("wait"),
                        (q.get("query") or "")[:160],
                    )
                for q in blocked[:5]:
                    logger.warning(
                        "[db] blocked pid=%s by=%s age=%ss sql=%s",
                        q["pid"],
                        q["blocked_by"],
                        q.get("age_s"),
                        (q.get("query") or "")[:160],
                    )
            else:
                logger.debug(
                    "[db] pid=%s total=%s states=%s",
                    pid,
                    total,
                    states,
                )
        except Exception:
            logger.exception("[db] activity logger tick failed")
        await asyncio.sleep(interval)


async def _audit_archiver_loop():
    """Periodically compact old audit_log rows and prune stale archives.

    Interval, compaction threshold and retention are controlled by
    `audit_compact_interval_hours`, `audit_compact_days` and
    `audit_retention_days` in `config.py`.
    """
    from .database import async_session
    from .routes.audit import _compact_entries, _prune_old_archives

    interval = settings.audit_compact_interval_hours * 3600
    # Small initial delay so API startup isn't blocked by a long scan.
    await asyncio.sleep(60)
    while True:
        try:
            async with async_session() as db:
                result = await _compact_entries(
                    db, settings.audit_compact_days, actor="system:audit-archiver"
                )
                pruned = await _prune_old_archives(db, settings.audit_retention_days)
                await db.commit()
                if result["archived"] or pruned:
                    logger.info(
                        "[audit] archiver: compacted %d day(s) / %d entries"
                        ", pruned %d archive(s)",
                        result["archived"],
                        result["entries"],
                        pruned,
                    )
        except Exception:
            logger.exception("audit archiver loop error")
        await asyncio.sleep(interval)


app = FastAPI(
    title="Constellation API",
    version="0.1.0",
    description="Infrastructure Security & Asset Management",
    docs_url="/api/docs" if settings.enable_swagger else None,
    redoc_url="/api/redoc" if settings.enable_swagger else None,
    openapi_url="/api/openapi.json" if settings.enable_swagger else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(SecurityMiddleware)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    # API serves JSON only — lock down to no sources + block framing.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


app.include_router(audit.router)
app.include_router(collect.router)
app.include_router(read.router)
app.include_router(backup.router)
app.include_router(opencve.router)
app.include_router(sca.router)
app.include_router(scan.router)
app.include_router(settings_router.router)
app.include_router(repositories.router)
app.include_router(pkg_repositories.router)
app.include_router(pkg_updates.router)
app.include_router(findings.router)
app.include_router(misconf.router)
app.include_router(automation.router)
app.include_router(cicd.router)
app.include_router(deployments.router)
app.include_router(managers.router)
app.include_router(tokens.router)
app.include_router(scheduler.router)
app.include_router(heartbeat.router)
app.include_router(incidents.router)
app.include_router(itsm.router)
app.include_router(webhooks_itsm.router)
app.include_router(drift.router)
app.include_router(metrics.router)
app.include_router(resync.router)
app.include_router(export.router)
app.include_router(container_images.router)
app.include_router(retention.router)
app.include_router(history.router)
app.include_router(sbom.router)
app.include_router(filters.router)
app.include_router(plugins.router)
app.include_router(cve_feeds.router)


@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/health/pool")
async def health_pool():
    """Snapshot of the SQLAlchemy connection pool — leak diagnostics.

    Returned counters are per uvicorn worker (each worker owns its
    own pool). Hit the endpoint repeatedly during a saturation event
    to see where connections accumulate.
    """
    from .database import pool_snapshot

    return pool_snapshot()


@app.get("/api/v1/health/db")
async def health_db(
    slow_seconds: int = 5,
    _: str = Depends(require_permission("settings", "r")),
):
    """Server-side `pg_stat_activity` snapshot — saturation diagnostics.

    Complements `/api/v1/health/pool` (per-worker pool view) with what
    PostgreSQL itself reports for ALL connections to this database:
    state counts, application_name breakdown, slow queries (≥
    `slow_seconds`), and blocked queries (waiting on a lock).
    Authenticated because query excerpts may surface column names.
    """
    from .database import db_activity_snapshot

    return await db_activity_snapshot(slow_query_seconds=slow_seconds)


@app.get("/api/v1/health/watchdog")
async def health_watchdog(
    _: str = Depends(require_permission("settings", "r")),
):
    """Watchdog tripwire state — see api/app/utils/watchdog.py.

    Returns the current state of each tripwire (pool_saturated,
    idle_in_tx_stuck, query_stuck, lock_pileup): triggered flag,
    triggered_at / notified_at timestamps (monotonic, per-worker),
    and the last payload that caused the trigger.
    """
    from .utils.watchdog import watchdog_snapshot

    return watchdog_snapshot()


@app.get("/api/v1/whoami")
async def whoami(
    request: Request,
    actor: str = Depends(require_auth),
):
    """Return current user identity and SSO role for frontend."""
    return {
        "user": actor,
        "role": getattr(request.state, "sso_role", "admin"),
        "name": getattr(request.state, "sso_name", actor),
        "groups": getattr(request.state, "sso_groups", ""),
    }
