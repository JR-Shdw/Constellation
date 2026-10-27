"""Incidents — state machine: transitions, timestamps, closed terminal."""

import pytest

from api.app.utils.incidents import can_transition, timestamp_field_for


def test_allowed_transitions():
    assert can_transition("new", "triaged")
    assert can_transition("new", "in_progress")
    assert can_transition("new", "closed")
    assert can_transition("triaged", "in_progress")
    assert can_transition("in_progress", "resolved")
    assert can_transition("resolved", "in_progress")  # reopen
    assert can_transition("resolved", "closed")


def test_illegal_transitions():
    # closed is terminal
    assert not can_transition("closed", "new")
    assert not can_transition("closed", "triaged")
    assert not can_transition("closed", "in_progress")
    assert not can_transition("closed", "resolved")
    # Cannot skip backwards
    assert not can_transition("triaged", "new")
    assert not can_transition("in_progress", "new")
    assert not can_transition("in_progress", "triaged")


def test_timestamp_mapping():
    assert timestamp_field_for("triaged") == "triaged_at"
    assert timestamp_field_for("resolved") == "resolved_at"
    assert timestamp_field_for("closed") == "closed_at"
    assert timestamp_field_for("new") is None
    assert timestamp_field_for("in_progress") is None


@pytest.mark.anyio
async def test_status_transition_sets_timestamp(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "sm test", "affected_asset": "sm-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"status": "triaged"},
        headers=auth,
    )
    assert r2.status_code == 200
    assert r2.json()["triaged_at"] is not None


@pytest.mark.anyio
async def test_illegal_transition_returns_409(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "illegal test", "affected_asset": "il-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    # new → resolved is illegal
    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"status": "resolved"},
        headers=auth,
    )
    assert r2.status_code == 409


@pytest.mark.anyio
async def test_close_requires_close_reason(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "close test", "affected_asset": "cl-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    # Closing without close_reason → 400
    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"status": "closed"},
        headers=auth,
    )
    assert r2.status_code == 400

    # Closing with close_reason → OK
    r3 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"status": "closed", "close_reason": "fixed"},
        headers=auth,
    )
    assert r3.status_code == 200
    assert r3.json()["close_reason"] == "fixed"
    assert r3.json()["closed_at"] is not None


@pytest.mark.anyio
async def test_closed_is_terminal(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "term test", "affected_asset": "t-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    # Close it
    await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"status": "closed", "close_reason": "fixed"},
        headers=auth,
    )

    # Any further transition → 409
    for target in ("new", "triaged", "in_progress", "resolved"):
        r2 = await client.patch(
            f"/api/v1/incidents/{iid}",
            json={"status": target, "close_reason": "fixed"},
            headers=auth,
        )
        assert r2.status_code == 409, f"{target} should be illegal from closed"


@pytest.mark.anyio
async def test_event_emitted_per_delta(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "events test", "affected_asset": "e-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    # Status + assignee in a single PATCH → 2 events
    await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"status": "triaged", "assignee": "bob"},
        headers=auth,
    )

    r2 = await client.get(f"/api/v1/incidents/{iid}", headers=auth)
    events = r2.json()["events"]
    kinds = [e["event_type"] for e in events]
    assert "created" in kinds
    assert "status_changed" in kinds
    assert "assigned" in kinds


@pytest.mark.anyio
async def test_reopen_clears_resolved_at(client, auth, seeded_ruleset):
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "reopen test", "affected_asset": "r-host"},
        headers=auth,
    )
    iid = r.json()["id"]

    # new → in_progress → resolved
    await client.patch(
        f"/api/v1/incidents/{iid}", json={"status": "in_progress"}, headers=auth
    )
    r2 = await client.patch(
        f"/api/v1/incidents/{iid}", json={"status": "resolved"}, headers=auth
    )
    assert r2.json()["resolved_at"] is not None

    # Reopen
    r3 = await client.patch(
        f"/api/v1/incidents/{iid}", json={"status": "in_progress"}, headers=auth
    )
    assert r3.status_code == 200
    assert r3.json()["resolved_at"] is None
