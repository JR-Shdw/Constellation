# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import logging
import secrets
import sys

from pydantic import field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://cmdb:cmdb@postgres:5432/cmdb"
    secret_key: str = "change-me"
    collect_token: str = "change-me"
    token_hmac_key: str = ""
    allowed_origins: list[str] = []
    trusted_proxy_header: str = "X-Forwarded-For"
    woodpecker_url: str = ""
    woodpecker_token: str = ""
    gitea_url: str = ""
    gitea_token: str = ""
    gitlab_url: str = ""
    gitlab_token: str = ""
    forgejo_url: str = ""
    forgejo_token: str = ""
    opencve_web_url: str = ""
    opencve_url: str = ""
    opencve_user: str = ""
    opencve_password: str = ""
    # Feature flags
    enable_swagger: bool = False  # API docs at /api/docs + /api/redoc
    # rhorizon integration (optional)
    vault_url: str = ""  # e.g. http://rhorizon-api:8200
    vault_token: str = ""  # rh_xxx — scope secrets:r
    # Rate limiting (per-IP sliding window, in-memory)
    # Defaults are deliberately light: CMDB runs behind VPN/SSO, so the goal
    # is to catch a misbehaving script, not to harden against internet bots.
    # Tighten these in .env if the instance is shared or exposed on a wider LAN.
    rate_limit_requests: int = 2000  # requests per window per IP
    rate_limit_window_seconds: int = 60
    # Brute-force protection for Bearer token auth
    bf_max_failures: int = 30  # failed Bearer attempts before ban
    bf_window_seconds: int = 300  # counting window (5 min)
    bf_ban_seconds: int = 300  # ban duration (5 min)
    # Audit log archiver — background task running in lifespan.
    # Entries older than `audit_compact_days` are moved to `audit_archives`
    # (gzip-compressed JSON), and the live `audit_log` table is pruned.
    # Set `audit_compact_interval_hours` to 0 to disable the background task
    # (manual POST /audit/compact still works).
    audit_compact_days: int = 30
    audit_compact_interval_hours: int = 24
    audit_retention_days: int = 365
    # SQLAlchemy connection pool — per uvicorn worker.
    # Effective concurrent DB connections = (db_pool_size + db_max_overflow)
    # × UVICORN_WORKERS. Keep the product below PG `max_connections`.
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_recycle: int = 300
    # Fail-fast: how long a request waits for a free connection
    # before raising TimeoutError (default 30s, dropped to 10s so a
    # saturated pool surfaces fast instead of stacking 30s waiters).
    db_pool_timeout: int = 10
    # Periodic pool stats logging — emits a line every N seconds at
    # INFO level when the pool is under pressure (any overflow used
    # or fewer than `db_pool_warn_free` slots free). Set to 0 to
    # disable. Useful to localize a leak.
    db_pool_log_interval: int = 60
    db_pool_warn_free: int = 3
    # Periodic pg_stat_activity logging — server-side connection
    # state. Emits WARNING when any query is running ≥
    # db_activity_slow_seconds, when queries are blocked, or when
    # the total connection count exceeds db_activity_warn_total.
    # Set interval to 0 to disable.
    db_activity_log_interval: int = 60
    db_activity_slow_seconds: int = 10
    db_activity_warn_total: int = 80
    # Anti-zombie timeouts pushed via asyncpg server_settings.
    # Mirrors the PG-side values in docker-compose.yml so the client
    # enforces its own kill switches even if the server config drifts.
    # idle_in_tx 60s: kills sessions stuck after a worker crash mid-tx
    #   (the original socket-saturation incident). Safe — a legit tx
    #   does work, it doesn't sit idle for a minute.
    # statement_timeout 0 (disabled): too many legit hot paths run > 30s
    #   (CVE ingestion upserts, v_all_cves exports, OpenCVE sync). Apply
    #   per-endpoint via `SET LOCAL statement_timeout` if a specific
    #   route needs a cap. Override globally via env if needed.
    pg_idle_in_tx_timeout_ms: int = 60000
    pg_statement_timeout_ms: int = 0
    # Per-endpoint statement_timeout profiles, applied opt-in via
    # `utils.sql.set_statement_timeout(db, "batch"|"long")` at the top
    # of long-running handlers. Global statement_timeout stays at 0 so
    # untagged routes are not capped; this is layered defense in depth
    # on top of idle_in_transaction_session_timeout (which kills idle
    # zombies, not long-but-busy queries).
    # Large côté serveur, ajustement fin via les timeouts des workers.
    # Mieux vaut ne pas couper une ingestion légitime que d'avoir un cap
    # PG trop serré qui force à tuner partout. Si une query dépasse ces
    # seuils, c'est un vrai problème (boucle / explosion de plan).
    pg_statement_timeout_batch_ms: int = 3600000  # 1 h — ingestion / sync
    pg_statement_timeout_long_ms: int = 7200000  # 2 h — admin / cleanup
    # API health watchdog — background loop that catches pool/PG
    # saturation patterns (idle-in-tx zombies, query stalls, lock
    # pileups, pool exhaustion) and pushes Matrix alerts BEFORE the
    # frontend starts 500ing. Tripwires fire once per state change
    # (cooldown protects against re-fire spam) and emit a resolution
    # message when the symptom clears.
    watchdog_enabled: bool = True
    watchdog_interval_seconds: int = 30
    watchdog_cooldown_seconds: int = 300
    watchdog_idle_in_tx_threshold_seconds: int = 60
    # 180s = ~aligned with batch ingestion that can legitimately run
    # 60-120s under load. Below 180s we'd spam Matrix during normal
    # batches; above it the alert lands well before the 5 min batch
    # statement_timeout would even fire.
    watchdog_query_stuck_threshold_seconds: int = 180
    watchdog_lock_pileup_threshold: int = 5
    watchdog_overflow_alert_threshold: int = 10

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

if (
    settings.secret_key == "change-me" or settings.collect_token == "change-me"
) and "pytest" not in sys.modules:
    logger.critical(
        "FATAL: secret_key and collect_token must be set in .env — "
        "refusing to start with default 'change-me' values"
    )
    sys.exit(1)

# Auto-generate HMAC key for token hashing if not configured
if not settings.token_hmac_key:
    settings.token_hmac_key = secrets.token_hex(32)
    logger.warning(
        "TOKEN_HMAC_KEY not set — generated ephemeral key. "
        "Add TOKEN_HMAC_KEY to .env for persistent token hashing."
    )
