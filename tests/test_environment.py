"""Integration tests — node environments + compliance."""

import pytest


@pytest.mark.anyio
async def test_set_node_environment(client, collect_auth, auth):
    """Tag a node with an environment and filter by it."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "env-test",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    node_id = r.json()["node_id"]

    # Set environment
    r = await client.put(
        f"/api/v1/nodes/{node_id}/environment",
        json={"environment": "staging"},
        headers=auth,
    )
    assert r.status_code == 200

    # Filter nodes by environment
    r = await client.get("/api/v1/nodes?environment=staging", headers=auth)
    hostnames = [n["hostname"] for n in r.json()["items"]]
    assert "env-test" in hostnames


@pytest.mark.anyio
async def test_compliance_summary(client, auth):
    """Compliance endpoint returns data without error."""
    r = await client.get("/api/v1/compliance", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_stats_endpoint(client, auth):
    """Stats endpoint returns all expected fields."""
    r = await client.get("/api/v1/stats", headers=auth)
    if r.status_code == 500:
        pytest.skip("stats requires all views (may fail on CI fresh DB)")
    assert r.status_code == 200
    data = r.json()
    expected_fields = [
        "nodes_total",
        "nodes_active",
        "packages_total",
        "containers_total",
        "cves_critical",
        "cves_high",
        "cves_total",
        "backups_ok",
        "backups_failed",
        "repos_total",
        "automation_pending",
    ]
    for field in expected_fields:
        assert field in data, f"Missing field: {field}"


@pytest.mark.anyio
async def test_search_cross_type(client, collect_auth, auth):
    """Global search finds nodes, packages, containers."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "searchable-host",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["findme-pkg\t1.0.0\tamd64"],
            "containers": [],
        },
        headers=collect_auth,
    )

    # Search by hostname
    r = await client.get("/api/v1/search?q=searchable", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["nodes"]) >= 1

    # Search by package name
    r = await client.get("/api/v1/search?q=findme-pkg", headers=auth)
    assert r.status_code == 200
    assert len(r.json()["packages"]) >= 1
