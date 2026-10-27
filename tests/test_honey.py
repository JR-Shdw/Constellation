# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Honeytoken IDS — verify decoy api_tokens fire honey_access audit entry."""

import json

import asyncpg
import pytest
from sqlalchemy import text

from .conftest import ASYNCPG_DSN


async def _seed_honey_token(token: str, name: str, scope: dict) -> None:
    from api.app.auth import hash_token
    th = hash_token(token)
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "INSERT INTO api_tokens (name, token_hash, permissions, is_honey) "
            "VALUES ($1, $2, $3::jsonb, TRUE) "
            "ON CONFLICT (name) DO UPDATE SET "
            "  token_hash = $2, permissions = $3::jsonb, is_honey = TRUE",
            name, th, json.dumps(scope),
        )
    finally:
        await conn.close()


async def _read_audit(action: str, target: str) -> dict | None:
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        row = await conn.fetchrow(
            "SELECT actor, target_id, detail FROM audit_log "
            "WHERE action = $1 ORDER BY created_at DESC LIMIT 1",
            action,
        )
    finally:
        await conn.close()
    return dict(row) if row else None


@pytest.mark.anyio
async def test_honey_token_collect_fires_alert(client):
    """A honey token used on /collect endpoint writes honey_access audit."""
    raw = "honeyc-collect-decoy-not-real"
    await _seed_honey_token(raw, "honey-collect-fake", {"collect": "w"})

    r = await client.post(
        "/api/v1/nodes/report",
        json={"hostname": "honey-test-host", "type": "vm", "os": "debian"},
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code in (200, 422)

    row = await _read_audit("honey_access", "honey-collect-fake")
    assert row is not None, "honey_access audit entry not written"
    assert row["actor"] == "honey-collect-fake"
    detail = row["detail"]
    if isinstance(detail, str):
        detail = json.loads(detail)
    assert detail.get("kind") == "token"


@pytest.mark.anyio
async def test_normal_token_does_not_fire_honey_alert(client):
    """A regular (non-honey) token must not generate a honey_access entry."""
    from api.app.auth import hash_token

    raw = "normal-token-no-decoy-flag"
    th = hash_token(raw)
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        await conn.execute(
            "INSERT INTO api_tokens (name, token_hash, permissions, is_honey) "
            "VALUES ('normal-tok', $1, $2::jsonb, FALSE) "
            "ON CONFLICT (name) DO UPDATE SET token_hash = $1, is_honey = FALSE",
            th, json.dumps({"read": "r"}),
        )
    finally:
        await conn.close()

    r = await client.get(
        "/api/v1/stats",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 200

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        n = await conn.fetchval(
            "SELECT count(*) FROM audit_log "
            "WHERE action = 'honey_access' AND actor = 'normal-tok'"
        )
    finally:
        await conn.close()
    assert n == 0
