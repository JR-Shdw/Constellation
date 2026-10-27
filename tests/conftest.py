import os
from pathlib import Path

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient

# Point to test database (CI service or local)
TEST_DB = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://cmdb_test:cmdb_test@localhost:5433/cmdb_test",
)
ASYNCPG_DSN = TEST_DB.replace("postgresql+asyncpg://", "postgresql://")

# Override settings BEFORE importing app
os.environ["DATABASE_URL"] = TEST_DB.replace("postgresql://", "postgresql+asyncpg://")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["COLLECT_TOKEN"] = "test-collect-token"


_schema_applied = False

# All data tables (no views, no system catalogs)
_DATA_TABLES = [
    "incident_tickets",
    "itsm_integrations",
    "incident_events",
    "incidents",
    "priority_rule_sets",
    "scheduler_runs",
    "scheduler_jobs",
    "deployments",
    "cicd_workers",
    "cicd_pipelines",
    "cicd_servers",
    "cicd_repositories",
    "container_managers",
    "automation_log",
    "automation_policies",
    "api_tokens",
    "audit_log",
    "audit_archives",
    "alert_sent",
    "alert_settings",
    "notification_webhooks",
    "sca_results",
    "opencve_alerts",
    "opencve_subscriptions",
    "cve_advisories",
    "cve_feeds",
    "secret_rotation_alerts",
    "secrets_detected",
    "secret_rules",
    "backup_runs",
    "backup_repositories",
    "cve_status",
    "node_heartbeats",
    "misconfigurations",
    "misconf_rules",
    "drift_reports",
    "cve_containers",
    "cve_host_packages",
    "cve_catalog",
    "repositories",
    "package_repositories",
    "sbom_components",
    "saved_filters",
    "containers",
    "container_images",
    "package_availability",
    "packages",
    "package_catalog",
    "nodes",
]


async def _ensure_schema():
    """Apply migrations + schema once (idempotent)."""
    global _schema_applied
    if _schema_applied:
        return
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        root = Path(__file__).parent.parent
        schema = root / "schema.sql"
        mig_dir = root / "migrations"

        # Migrations first (create columns that schema.sql views need)
        if mig_dir.exists():
            for f in sorted(mig_dir.glob("*.sql")):
                try:
                    await conn.execute(f.read_text())
                except Exception:
                    pass

        # Schema as single block (DROPs at top, then tables, then views)
        if schema.exists():
            await conn.execute(schema.read_text())

        # Re-run migrations (some need tables from schema)
        if mig_dir.exists():
            for f in sorted(mig_dir.glob("*.sql")):
                try:
                    await conn.execute(f.read_text())
                except Exception:
                    pass
    finally:
        await conn.close()
    _schema_applied = True


async def _truncate_all():
    """Truncate all data tables between tests — clean slate."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(f"TRUNCATE {', '.join(_DATA_TABLES)} CASCADE")
        # Reset incident UID sequence so UIDs are predictable across tests.
        try:
            await conn.execute("ALTER SEQUENCE incidents_uid_seq RESTART WITH 1")
        except Exception:
            pass
        # Invalidate in-process caches that cross test boundaries.
        try:
            from api.app.utils.incidents import invalidate_rule_set_cache

            invalidate_rule_set_cache()
        except Exception:
            pass
    finally:
        await conn.close()


CISA_SSVC_RULES = [
    {
        "name": "P1-kev-internet-prod",
        "priority": "P1",
        "conditions": {
            "in_kev": True,
            "exposure": ["internet"],
            "environment": ["production"],
        },
    },
    {
        "name": "P2-cvss9-or-kev-prod",
        "priority": "P2",
        "conditions": {
            "any": [{"cvss_min": 9.0}, {"in_kev": True}],
            "environment": ["production"],
        },
    },
    {
        "name": "P3-cvss7-prod-or-internet",
        "priority": "P3",
        "conditions": {
            "any": [
                {"cvss_min": 7.0, "environment": ["production"]},
                {"exposure": ["internet"]},
            ]
        },
    },
    {"name": "P4-default", "priority": "P4", "conditions": {}},
]


async def _seed_ruleset():
    """Insert + activate CISA SSVC preset for tests that need a ruleset."""
    import json as _json

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            """
            INSERT INTO priority_rule_sets (name, description, is_active, rules)
            VALUES ($1, $2, true, $3::jsonb)
            ON CONFLICT (name) DO UPDATE SET
                is_active = true,
                rules = EXCLUDED.rules,
                updated_at = NOW()
            """,
            "CISA SSVC + ITIL v1",
            "Default SSVC preset — test fixture",
            _json.dumps(CISA_SSVC_RULES),
        )
    finally:
        await conn.close()


@pytest.fixture
async def seeded_ruleset(client):
    """Fixture: ensure the CISA SSVC preset is active for this test.

    Depends on `client` so the TRUNCATE in client setup happens BEFORE seeding.
    """
    await _seed_ruleset()
    try:
        from api.app.utils.incidents import invalidate_rule_set_cache

        invalidate_rule_set_cache()
    except Exception:
        pass
    yield


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """Async HTTP client — clean DB per test via TRUNCATE."""
    await _ensure_schema()
    await _truncate_all()

    from api.app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    # Drain detached notify_* tasks so SQLAlchemy sessions they opened
    # close before the event loop shuts down (otherwise pytest warns
    # about "Event loop is closed" during GC of orphan connections).
    from api.app.notify import flush_bg_tasks

    await flush_bg_tasks()


@pytest.fixture
def auth():
    return {"Authorization": "Bearer test-secret-key"}


@pytest.fixture
def collect_auth():
    return {"Authorization": "Bearer test-collect-token"}
