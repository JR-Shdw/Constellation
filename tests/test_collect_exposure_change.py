"""collect/nodes.py — exposure_change automation trigger branches."""

import pytest


async def _report(client, headers, hostname: str, port_bindings: list):
    """Helper: submit a node report with a single container."""
    return await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [
                {
                    "name": "exposed-svc",
                    "image": "nginx:1.25",
                    "status": "running",
                    "port_bindings": port_bindings,
                    "networks": [],
                    "labels": {},
                }
            ],
        },
        headers=headers,
    )


@pytest.mark.anyio
async def test_exposure_change_fires_automation(client, collect_auth, monkeypatch):
    """First report: docker_internal. Second: internet → run_evaluation called."""
    import api.app.routes.collect.nodes as nodes_mod

    called = {"n": 0, "events": []}

    async def _fake_eval(event, db):
        called["n"] += 1
        called["events"].append(event)

    monkeypatch.setattr(nodes_mod, "run_evaluation", _fake_eval)

    # First report: no port bindings → docker_internal
    r1 = await _report(client, collect_auth, "exp-change-host", [])
    assert r1.status_code == 200

    # Second report: 0.0.0.0 binding → internet
    r2 = await _report(
        client,
        collect_auth,
        "exp-change-host",
        [{"host_ip": "0.0.0.0", "host_port": 80, "container_port": 80}],
    )
    assert r2.status_code == 200

    # Run evaluation must have fired with exposure_change
    exp_change = [
        e for e in called["events"] if e.get("trigger_type") == "exposure_change"
    ]
    assert exp_change, f"no exposure_change fired; got: {called['events']}"
    assert exp_change[0]["container"] == "exposed-svc"
    assert exp_change[0]["exposure"] == "internet"


@pytest.mark.anyio
async def test_exposure_change_eval_exception_swallowed(
    client, collect_auth, monkeypatch
):
    """run_evaluation raising → logged, does not break ingestion."""
    import api.app.routes.collect.nodes as nodes_mod

    async def _boom(*a, **kw):
        raise RuntimeError("eval boom")

    monkeypatch.setattr(nodes_mod, "run_evaluation", _boom)

    r1 = await _report(client, collect_auth, "exp-boom-host", [])
    assert r1.status_code == 200
    r2 = await _report(
        client,
        collect_auth,
        "exp-boom-host",
        [{"host_ip": "0.0.0.0", "host_port": 81, "container_port": 80}],
    )
    # Second report still succeeds — exception is swallowed
    assert r2.status_code == 200


@pytest.mark.anyio
async def test_exposure_change_event_uses_listen_vocabulary(
    client, collect_auth, monkeypatch
):
    """A WG ('vpn') exposure must reach the event as 'private_network' so a
    match_exposure:["private_network"] policy fires the same way it does for
    image_update_available events (which carry repositories.listen)."""
    import api.app.routes.collect.nodes as nodes_mod

    called = {"events": []}

    async def _fake_eval(event, db):
        called["events"].append(event)

    monkeypatch.setattr(nodes_mod, "run_evaluation", _fake_eval)

    # First report: no bindings → docker_internal
    r1 = await _report(client, collect_auth, "exp-vpn-host", [])
    assert r1.status_code == 200
    # Second: bound to a WireGuard address → classified 'vpn' internally
    r2 = await _report(
        client,
        collect_auth,
        "exp-vpn-host",
        [{"host_ip": "10.0.0.1", "host_port": 80, "container_port": 80}],
    )
    assert r2.status_code == 200

    exp_change = [
        e for e in called["events"] if e.get("trigger_type") == "exposure_change"
    ]
    assert exp_change, f"no exposure_change fired; got: {called['events']}"
    # Normalized to the listen vocabulary, NOT the raw 'vpn'
    assert exp_change[0]["exposure"] == "private_network"
