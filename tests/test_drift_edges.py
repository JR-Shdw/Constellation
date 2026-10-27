"""drift.py — JSON-string item parse path, fallback values, automation
eval failure swallowed, list filters."""

import uuid

import pytest


async def _seed_node(hostname: str) -> str:
    """Insert a minimal node row directly so drift INSERTs land."""
    import asyncpg

    from .conftest import ASYNCPG_DSN

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, is_active)
            VALUES ($1, 'vm', true)
            ON CONFLICT (hostname) DO UPDATE SET hostname = EXCLUDED.hostname
            RETURNING id
            """,
            hostname,
        )
    finally:
        await conn.close()
    return str(node_id)


@pytest.mark.anyio
async def test_drift_report_jsonstring_items_and_fallbacks(
    client, collect_auth
):
    """Items as JSON strings are parsed (lines 41-47); invalid drift_type
    falls back to 'config' (62); empty resource_name skipped (65); invalid
    severity falls back to 'medium' (68)."""
    host = f"drift-{uuid.uuid4().hex[:6]}"
    await _seed_node(host)

    payload = {
        "hostname": host,
        "items": [
            # valid JSON string with weird drift_type → fallback 'config'
            # and weird severity → fallback 'medium' (lines 62, 68)
            '{"drift_type": "weird", "resource_name": "/etc/x",'
            ' "severity": "weird-sev"}',
            # invalid JSON string → JSONDecodeError, skipped (line 46-47)
            "not-json-{{{",
            # JSON string parsing to non-dict → not appended (line 44 fails)
            '"plain string"',
            # dict with empty resource_name → skipped (line 64-65)
            {"drift_type": "package", "resource_name": ""},
            # valid dict — should insert (proves we got past line 55)
            {
                "drift_type": "package",
                "resource_name": "openssh",
                "severity": "high",
                "expected": "1.0",
                "actual": "0.9",
            },
        ],
    }
    r = await client.post(
        "/api/v1/drift/report", json=payload, headers=collect_auth
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    # 2 valid items: the JSON-string with fallbacks + the trailing dict
    assert data["inserted"] == 2


@pytest.mark.anyio
async def test_drift_report_automation_eval_swallowed(
    client, collect_auth, monkeypatch
):
    """run_evaluation raising on critical drift → logged, ingestion still ok
    (lines 122-123)."""
    import api.app.routes.drift as dmod

    async def _boom(*a, **kw):
        raise RuntimeError("eval boom")

    monkeypatch.setattr(dmod, "run_evaluation", _boom)

    host = f"drift-{uuid.uuid4().hex[:6]}"
    await _seed_node(host)

    r = await client.post(
        "/api/v1/drift/report",
        json={
            "hostname": host,
            "items": [
                {
                    "drift_type": "config",
                    "resource_name": "/etc/passwd",
                    "severity": "critical",
                }
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["inserted"] == 1


@pytest.mark.anyio
async def test_list_drift_status_filter(client, auth):
    """status filter exercises clauses lines 147-148."""
    r = await client.get("/api/v1/drift?status=open", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["status"] == "open" for i in items)


@pytest.mark.anyio
async def test_list_drift_drift_type_filter(client, auth):
    """drift_type filter exercises clauses lines 150-151."""
    r = await client.get("/api/v1/drift?drift_type=config", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["drift_type"] == "config" for i in items)
