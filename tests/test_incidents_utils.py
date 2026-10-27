"""utils/incidents.py — pure-function edges + patch 404/invalid/no-op."""

import uuid

import pytest

from api.app.utils import incidents as inc


def test_check_condition_any_empty_list_false():
    """`any: []` cannot match → False (line 94)."""
    assert inc._check_one_condition({"severity": "critical"}, {"any": []}) is False


def test_check_condition_any_not_a_list_false():
    """`any: "nope"` → not a list → False (line 94)."""
    assert inc._check_one_condition({}, {"any": "nope"}) is False


def test_check_condition_cvss_min_non_numeric_returns_false():
    """cvss value that can't be float → caught TypeError/ValueError (105-106)."""
    assert inc._check_one_condition({"cvss": "oops"}, {"cvss_min": 7}) is False


def test_check_condition_cvss_none_returns_false():
    """cvss absent when cvss_min requires a value."""
    assert inc._check_one_condition({}, {"cvss_min": 5}) is False


def test_compute_priority_rule_set_none():
    """No rule set → ('P4', 'no-rule-set') (line 118)."""
    assert inc.compute_priority({}, None) == ("P4", "no-rule-set")


def test_compute_priority_rules_as_json_string():
    """rules stored as JSON string → json.loads path (line 121)."""
    rs = {"rules": '[{"priority":"P1","name":"kev","conditions":{"in_kev":true}}]'}
    pri, name = inc.compute_priority({"in_kev": True}, rs)
    assert pri == "P1"
    assert name == "kev"


def test_compute_priority_fallthrough():
    """No rule matches → ('P4', 'fallthrough') (line 125)."""
    rs = {
        "rules": [
            {
                "priority": "P1",
                "name": "kev",
                "conditions": {"in_kev": True},
            }
        ]
    }
    pri, name = inc.compute_priority({"in_kev": False}, rs)
    assert pri == "P4"
    assert name == "fallthrough"


@pytest.mark.anyio
async def test_find_dedup_all_criteria_none_returns_none():
    """No cve/asset/package → short-circuit (line 137)."""
    # db is never touched — passing None is safe
    result = await inc.find_dedup(
        None, cve_id=None, affected_asset=None, affected_package=None
    )
    assert result is None


@pytest.mark.anyio
async def test_dedup_non_cve_distinguishes_source_trigger(seeded_ruleset):
    """Non-CVE incidents on one host but different triggers must NOT merge.

    cve_id/package are NULL for backup_overdue / worker_offline, so the
    (NULL, host, NULL) tuple alone would collapse them — source_trigger keeps
    them distinct.
    """
    from api.app.database import async_session

    host = f"dedup-host-{uuid.uuid4().hex[:8]}"
    async with async_session() as db:
        i1 = await inc.create_incident(
            db,
            title="backup overdue",
            affected_asset=host,
            source_trigger="backup_overdue",
        )
        i2 = await inc.create_incident(
            db,
            title="worker offline",
            affected_asset=host,
            source_trigger="worker_offline",
        )
        assert i2.get("deduped") is False
        assert i1["id"] != i2["id"]
        # Same trigger on the same host → dedup hit.
        i3 = await inc.create_incident(
            db,
            title="backup overdue again",
            affected_asset=host,
            source_trigger="backup_overdue",
        )
        assert i3.get("deduped") is True
        assert i3["id"] == i1["id"]


@pytest.mark.anyio
async def test_dedup_cve_ignores_source_trigger(seeded_ruleset):
    """The same CVE on the same asset dedups regardless of detection path."""
    from api.app.database import async_session

    host = f"cve-host-{uuid.uuid4().hex[:8]}"
    cve = "CVE-2024-4242"
    async with async_session() as db:
        i1 = await inc.create_incident(
            db,
            title="manual cve",
            cve_id=cve,
            affected_asset=host,
            affected_package="openssl",
            source_trigger="manual",
        )
        i2 = await inc.create_incident(
            db,
            title="auto cve",
            cve_id=cve,
            affected_asset=host,
            affected_package="openssl",
            source_trigger="cve_detected",
        )
        assert i2.get("deduped") is True
        assert i2["id"] == i1["id"]


@pytest.mark.anyio
async def test_patch_incident_not_found_raises_404():
    """patch on unknown id → HTTPException 404 (line 425)."""
    from fastapi import HTTPException

    from api.app.database import async_session

    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await inc.patch_incident(
                db,
                "00000000-0000-0000-0000-000000000000",
                actor="tester",
                status_="triaged",
            )
        assert exc.value.status_code == 404


@pytest.mark.anyio
async def test_patch_incident_invalid_priority_raises_400(client, auth, seeded_ruleset):
    """priority='P99' → HTTPException 400 (lines 461-464)."""
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "prio-test", "affected_asset": "xprio"},
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"priority": "P99"},
        headers=auth,
    )
    assert r2.status_code == 400


@pytest.mark.anyio
async def test_patch_incident_priority_change(client, auth, seeded_ruleset):
    """PATCH priority='P2' → updates dict + priority_changed event (lines 463-471)."""
    r = await client.post(
        "/api/v1/incidents",
        json={
            "title": "prio-change",
            "affected_asset": "xprio-c",
            "severity": "low",
        },
        headers=auth,
    )
    iid = r.json()["id"]
    # Change to a priority known to differ from default
    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"priority": "P1"},
        headers=auth,
    )
    assert r2.status_code == 200
    assert r2.json()["priority"] == "P1"


@pytest.mark.anyio
async def test_patch_incident_no_changes_returns_current(client, auth, seeded_ruleset):
    """PATCH with no deltas → early return of current record (line 488)."""
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "no-op", "affected_asset": "xnoop"},
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={},
        headers=auth,
    )
    assert r2.status_code == 200


@pytest.mark.anyio
async def test_push_to_itsm_auth_config_str_falls_back(monkeypatch):
    """Feed a fake db returning auth_config as str → json.loads path (227-230).
    Uses stub connector so no real HTTP happens."""
    from api.app.utils import incidents as inc_mod

    class _Row(dict):
        pass

    class _Result:
        def __init__(self, rows):
            self._rows = rows

        def mappings(self):
            class _M:
                def __init__(self, rows):
                    self._rows = rows

                def all(self):
                    return self._rows

            return _M(self._rows)

    class _DB:
        def __init__(self):
            self.executed = []

        async def execute(self, *a, **kw):
            self.executed.append((a, kw))
            # First call is the SELECT on itsm_integrations; return the fixture row
            if len(self.executed) == 1:
                return _Result(
                    [
                        _Row(
                            id="11111111-1111-1111-1111-111111111111",
                            platform="glpi",
                            base_url="http://x",
                            auth_config="not-json-{{{",
                            project_key="X",
                        )
                    ]
                )
            return _Result([])

        async def commit(self):
            pass

    class _Conn:
        async def create_ticket(self, title, description, priority, labels):
            return ("EXT-1", "http://x/1")

    import api.app.connectors as connectors_mod

    monkeypatch.setattr(connectors_mod, "get_itsm", lambda *a, **kw: _Conn())

    db = _DB()
    created = await inc_mod.push_to_itsm(
        db,
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "uid": "INC-000001",
            "title": "t",
            "description": "d",
            "priority": "P3",
        },
    )
    assert len(created) == 1
    assert created[0]["external_id"] == "EXT-1"


@pytest.mark.anyio
async def test_create_incident_push_to_itsm_raises_logged(
    client, auth, seeded_ruleset, monkeypatch
):
    """push_to_itsm raising inside create_incident is caught (lines 406-407)."""
    from api.app.utils import incidents as inc_mod

    async def _boom(db, incident):
        raise RuntimeError("push exploded")

    monkeypatch.setattr(inc_mod, "push_to_itsm", _boom)

    r = await client.post(
        "/api/v1/incidents",
        json={"title": "itsm-boom", "affected_asset": "ia-boom"},
        headers=auth,
    )
    # Creation must succeed — ITSM failure is swallowed
    assert r.status_code in (200, 201)


@pytest.mark.anyio
async def test_patch_incident_literal_now_not_treated_as_timestamp(
    client, auth, seeded_ruleset
):
    """Free-text 'now' must be stored verbatim, not rewritten to SQL NOW().

    Regression: the timestamp-column marker used to be the string "now", which
    collided with free-text columns (description/assignee).
    """
    r = await client.post(
        "/api/v1/incidents",
        json={"title": "now-literal", "affected_asset": "xnow"},
        headers=auth,
    )
    iid = r.json()["id"]
    r2 = await client.patch(
        f"/api/v1/incidents/{iid}",
        json={"assignee": "now", "description": "now"},
        headers=auth,
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["assignee"] == "now"
    assert body["description"] == "now"
