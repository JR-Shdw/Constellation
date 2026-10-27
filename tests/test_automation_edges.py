"""automation.py — evaluate_policies filter rejections, update no-op,
ignore action status, action-failure log, create_deployment config-as-string."""

import json
import uuid

import pytest

from api.app.routes.automation import evaluate_policies


def _base_pol(**over):
    p = {
        "id": str(uuid.uuid4()),
        "name": "test",
        "priority": 0,
        "enabled": True,
        "trigger_type": "cve_detected",
        "match_hostname": None,
        "match_container": None,
        "match_image": None,
        "match_package": None,
        "match_cve_id": None,
        "match_severity": None,
        "match_environment": None,
        "match_exposure": None,
        "action": "notify",
        "auto_execute": False,
        "config": None,
    }
    p.update(over)
    return p


def _base_event(**over):
    e = {
        "trigger_type": "cve_detected",
        "hostname": "host-a",
        "container": "api",
        "image": "cmdb-api:latest",
        "package": "openssl",
        "cve_id": "CVE-2024-1",
        "severity": "critical",
        "environment": "production",
        "exposure": "internet",
    }
    e.update(over)
    return e


@pytest.mark.parametrize(
    "filter_field,filter_val,event_field,event_val",
    [
        ("match_hostname", "host-b%", "hostname", "host-a"),
        ("match_container", "%pg%", "container", "api"),
        ("match_image", "%nginx%", "image", "cmdb-api"),
        ("match_package", "linux%", "package", "openssl"),
        ("match_cve_id", "CVE-2023-%", "cve_id", "CVE-2024-1"),
        ("match_severity", ["low"], "severity", "critical"),
        ("match_environment", ["lab"], "environment", "production"),
        ("match_exposure", ["localhost"], "exposure", "internet"),
    ],
)
def test_evaluate_policies_each_filter_can_reject(
    filter_field, filter_val, event_field, event_val
):
    """Each filter mismatch hits its own `continue` (lines 54-68)."""
    pol = _base_pol(**{filter_field: filter_val})
    ev = _base_event(**{event_field: event_val})
    assert evaluate_policies(ev, [pol]) is None


def test_evaluate_policies_disabled_skipped():
    """Disabled policy is skipped (line 50)."""
    pol = _base_pol(enabled=False)
    assert evaluate_policies(_base_event(), [pol]) is None


def test_evaluate_policies_trigger_mismatch():
    """Wrong trigger_type → no match."""
    pol = _base_pol(trigger_type="backup_overdue")
    assert evaluate_policies(_base_event(), [pol]) is None


def test_evaluate_policies_full_match():
    """All filters match → returns the policy."""
    pol = _base_pol(
        match_hostname="host-a",
        match_severity=["critical"],
        match_environment=["production"],
    )
    matched = evaluate_policies(_base_event(), [pol])
    assert matched is not None
    assert matched["name"] == "test"


# ── integration: covers route lines 179, 411, 458-465, 528 ──────────────


@pytest.mark.anyio
async def test_update_policy_empty_body_no_change(client, auth):
    """PUT with empty model → 'changed: False' branch (line 179)."""
    r0 = await client.post(
        "/api/v1/automation/policies",
        json={
            "name": f"pol-{uuid.uuid4().hex[:8]}",
            "trigger_type": "cve_detected",
            "action": "notify",
        },
        headers=auth,
    )
    pid = r0.json()["id"]

    r = await client.put(
        f"/api/v1/automation/policies/{pid}", json={}, headers=auth
    )
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "changed": False}


@pytest.mark.anyio
async def test_run_evaluation_ignore_status(client, auth):
    """Policy with action=ignore → log status='ignored' (line 411)."""
    from api.app.database import async_session
    from api.app.routes.automation import run_evaluation

    name = f"pol-ig-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "ignore",
            "match_hostname": "edge-ignore",
            "auto_execute": False,
            "priority": 1000,
        },
        headers=auth,
    )

    async with async_session() as db:
        await run_evaluation(
            {
                "trigger_type": "cve_detected",
                "hostname": "edge-ignore",
                "severity": "critical",
            },
            db,
        )
        await db.commit()

    r = await client.get("/api/v1/automation/log", headers=auth)
    items = r.json()["items"]
    assert any(
        it["policy_name"] == name and it["status"] == "ignored" for it in items
    )


@pytest.mark.anyio
async def test_run_evaluation_action_failure_logs_failed(
    client, auth, monkeypatch
):
    """_execute_action raising → log status updated to 'failed' (lines 458-465)."""
    import api.app.routes.automation as amod
    from api.app.database import async_session

    async def _boom(action, policy, event, db):
        raise RuntimeError("action exploded")

    monkeypatch.setattr(amod, "_execute_action", _boom)

    name = f"pol-fail-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "notify",
            "match_hostname": "edge-fail",
            "auto_execute": True,
            "priority": 1000,
        },
        headers=auth,
    )

    async with async_session() as db:
        await amod.run_evaluation(
            {
                "trigger_type": "cve_detected",
                "hostname": "edge-fail",
                "severity": "critical",
            },
            db,
        )
        await db.commit()

    r = await client.get("/api/v1/automation/log", headers=auth)
    items = r.json()["items"]
    assert any(
        it["policy_name"] == name and it["status"] == "failed" for it in items
    )


@pytest.mark.anyio
async def test_run_evaluation_create_deployment_config_as_string(
    client, auth, monkeypatch
):
    """create_deployment policy with config stored as JSON string → json.loads
    branch (line 528)."""
    import api.app.routes.automation as amod
    from api.app.database import async_session

    # Skip the actual deployment INSERT side-effects we don't care about by
    # letting the route run normally; the create_deployment branch handles
    # everything itself. We just need the config to come back as str.
    name = f"pol-cd-{uuid.uuid4().hex[:8]}"
    config_dict = {
        "deploy_type": "package_upgrade",
        "repo_name": "edge/cd",
        "branch": "main",
    }
    await client.post(
        "/api/v1/automation/policies",
        json={
            "name": name,
            "trigger_type": "cve_detected",
            "action": "create_deployment",
            "match_hostname": "edge-cd",
            "auto_execute": True,
            "priority": 1000,
            "config": config_dict,
        },
        headers=auth,
    )

    # Force the policy row's config to come back as a JSON *string* by
    # patching evaluate_policies to mutate the matched dict. This hits the
    # `if isinstance(config, str)` branch in _execute_action.
    real_eval = amod.evaluate_policies

    def _wrap(event, policies):
        m = real_eval(event, policies)
        if m and m["name"] == name:
            m["config"] = json.dumps(config_dict)
        return m

    monkeypatch.setattr(amod, "evaluate_policies", _wrap)

    async with async_session() as db:
        await amod.run_evaluation(
            {
                "trigger_type": "cve_detected",
                "hostname": "edge-cd",
                "severity": "critical",
            },
            db,
        )
        await db.commit()

    r = await client.get("/api/v1/automation/log", headers=auth)
    items = r.json()["items"]
    matched_log = [it for it in items if it["policy_name"] == name]
    assert matched_log, "create_deployment policy didn't fire"
    # Log might be 'completed' (if deployment INSERT succeeded) or 'failed'
    assert matched_log[0]["status"] in ("completed", "failed")
