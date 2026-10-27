"""Priority rule sets — SSVC scoring, seed, single-active invariant."""

import asyncpg
import pytest

from api.app.utils.incidents import compute_priority
from tests.conftest import ASYNCPG_DSN, CISA_SSVC_RULES


@pytest.mark.anyio
async def test_seeded_preset_is_active(client, auth, seeded_ruleset):
    r = await client.get("/api/v1/priority-rules?active_only=true", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(it["name"] == "CISA SSVC + ITIL v1" and it["is_active"] for it in items)


def test_compute_priority_p1_kev_internet_prod():
    rs = {"rules": CISA_SSVC_RULES}
    event = {
        "in_kev": True,
        "exposure": "internet",
        "environment": "production",
        "cvss": 7.0,
    }
    p, name = compute_priority(event, rs)
    assert p == "P1"
    assert "kev-internet-prod" in name


def test_compute_priority_p2_cvss9_prod():
    rs = {"rules": CISA_SSVC_RULES}
    event = {
        "in_kev": False,
        "exposure": "private_network",
        "environment": "production",
        "cvss": 9.5,
    }
    p, _ = compute_priority(event, rs)
    assert p == "P2"


def test_compute_priority_p3_cvss7_internet():
    rs = {"rules": CISA_SSVC_RULES}
    event = {
        "in_kev": False,
        "exposure": "internet",
        "environment": "lab",
        "cvss": 5.0,
    }
    p, _ = compute_priority(event, rs)
    assert p == "P3"


def test_compute_priority_p4_default():
    rs = {"rules": CISA_SSVC_RULES}
    event = {
        "in_kev": False,
        "exposure": "localhost",
        "environment": "lab",
        "cvss": 2.0,
    }
    p, name = compute_priority(event, rs)
    assert p == "P4"


def test_compute_priority_no_rule_set():
    p, name = compute_priority({"cvss": 9.0}, None)
    assert p == "P4"
    assert name == "no-rule-set"


@pytest.mark.anyio
async def test_partial_unique_blocks_two_active(client, auth, seeded_ruleset):
    """Only one ruleset can be is_active=true at the same time."""
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        # Seeded fixture already has "CISA SSVC + ITIL v1" active.
        await conn.execute(
            """
            INSERT INTO priority_rule_sets (name, description, is_active, rules)
            VALUES ('second-set', 'x', false, '[]'::jsonb)
            ON CONFLICT (name) DO UPDATE SET is_active = false
            """
        )
        # Trying to activate a second set directly → unique violation
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute(
                "UPDATE priority_rule_sets SET is_active = true "
                "WHERE name = 'second-set'"
            )
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_activate_flips_active(client, auth, seeded_ruleset):
    """POST /priority-rules/{id}/activate deactivates the previous active set."""
    # Create a new set via API (not active yet)
    r = await client.post(
        "/api/v1/priority-rules",
        json={
            "name": "new-preset",
            "description": "test",
            "rules": [
                {"name": "P4-default", "priority": "P4", "conditions": {}},
            ],
        },
        headers=auth,
    )
    assert r.status_code == 200
    new_id = r.json()["id"]

    # Activate it
    r2 = await client.post(f"/api/v1/priority-rules/{new_id}/activate", headers=auth)
    assert r2.status_code == 200

    # Only one active ruleset now, and it's the new one
    r3 = await client.get("/api/v1/priority-rules?active_only=true", headers=auth)
    active = r3.json()["items"]
    assert len(active) == 1
    assert active[0]["name"] == "new-preset"
