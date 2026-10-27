"""History endpoint tests."""

import pytest


@pytest.mark.anyio
async def test_history_default(client, auth):
    r = await client.get("/api/v1/history", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["days"] == 7
    assert "summary" in data
    for key in (
        "new_nodes",
        "new_packages",
        "new_containers",
        "new_host_cves",
        "new_container_cves",
        "workflow_changes",
    ):
        assert key in data["summary"]
        assert key in data


@pytest.mark.anyio
async def test_history_custom_days(client, auth):
    r = await client.get("/api/v1/history?days=30", headers=auth)
    assert r.status_code == 200
    assert r.json()["days"] == 30


@pytest.mark.anyio
async def test_history_with_data(client, auth, collect_auth):
    """Ingest a node, then check history picks it up."""
    await client.post(
        "/api/v1/nodes/report",
        json={"hostname": "hist-node", "type": "vm", "os": "debian", "packages": []},
        headers=collect_auth,
    )
    r = await client.get("/api/v1/history?days=1", headers=auth)
    assert r.status_code == 200
    hostnames = [n["hostname"] for n in r.json()["new_nodes"]]
    assert "hist-node" in hostnames
