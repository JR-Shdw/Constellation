"""Integration tests — node collection + container exposure."""

import pytest


@pytest.mark.anyio
async def test_collect_node_with_packages(client, collect_auth):
    """Full collect cycle: node + packages + containers."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "test-node",
            "type": ["vm", "container_host"],
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["nginx\t1.24.0\tamd64", "curl\t7.88.1\tamd64"],
            "containers": [
                '{"name":"web","image":"nginx:1.24","status":"Up",'
                '"port_bindings":[{"container_port":"80/tcp",'
                '"host_ip":"0.0.0.0","host_port":"80"}],'
                '"networks":["traefik_proxy"],'
                '"labels":{"traefik.enable":"true"}}'
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["hostname"] == "test-node"
    node_id = data["node_id"]

    # Verify node exists
    r = await client.get(
        f"/api/v1/nodes/{node_id}",
        headers={"Authorization": "Bearer test-secret-key"},
    )
    assert r.status_code == 200
    node = r.json()["node"]
    assert node["hostname"] == "test-node"
    assert "vm" in node["type"]
    assert "container_host" in node["type"]
    assert node["package_count"] == 2
    assert node["container_count"] == 1


@pytest.mark.anyio
async def test_container_exposure_classification(client, collect_auth, auth):
    """Containers get correct exposure from port bindings."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "exposure-test",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [
                '{"name":"public-web","image":"nginx:latest","status":"Up",'
                '"port_bindings":[{"container_port":"80/tcp",'
                '"host_ip":"0.0.0.0","host_port":"80"}],'
                '"networks":["bridge"],"labels":{}}',
                # host_ip must match _WG_PREFIXES in routes/collect/__init__.py
                # to assert "vpn" classification — keep in the 10.0.1.x range.
                '{"name":"wg-svc","image":"app:1.0","status":"Up",'
                '"port_bindings":[{"container_port":"8080/tcp",'
                '"host_ip":"10.0.1.1","host_port":"8080"}],'
                '"networks":["wg"],"labels":{}}',
                '{"name":"internal","image":"redis:7","status":"Up",'
                '"port_bindings":[],"networks":["backend"],"labels":{}}',
            ],
        },
        headers=collect_auth,
    )

    r = await client.get("/api/v1/exposure", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    by_name = {i["name"]: i for i in items}

    assert by_name["public-web"]["exposure"] == "internet"
    assert by_name["wg-svc"]["exposure"] == "vpn"
    assert by_name["internal"]["exposure"] == "docker_internal"


@pytest.mark.anyio
async def test_traefik_authelia_detection(client, collect_auth, auth):
    """Detect Traefik and Authelia from container labels."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "proxy-test",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [
                '{"name":"protected-app","image":"myapp:1.0","status":"Up",'
                '"port_bindings":[],"networks":["traefik_proxy"],'
                '"labels":{"traefik.enable":"true",'
                '"traefik.http.routers.app.middlewares":"authelia@docker"}}'
            ],
        },
        headers=collect_auth,
    )

    r = await client.get("/api/v1/containers?group=false", headers=auth)
    items = [i for i in r.json()["items"] if i.get("hostname") == "proxy-test"]
    assert len(items) >= 1
    app = items[0]
    assert app["traefik"] is True


@pytest.mark.anyio
async def test_nodes_report_batch(client, collect_auth, auth):
    """Bulk endpoint upserts multiple nodes in a single transaction."""
    r = await client.post(
        "/api/v1/nodes/report-batch",
        json={
            "items": [
                {
                    "hostname": "batch-a",
                    "type": "vm",
                    "os": "debian",
                    "os_version": "12",
                    "arch": "x86_64",
                    "kernel": "6.1.0",
                    "packages": ["nginx\t1.24.0\tamd64"],
                    "containers": [],
                },
                {
                    "hostname": "batch-b",
                    "type": "vm",
                    "os": "ubuntu",
                    "os_version": "24.04",
                    "arch": "x86_64",
                    "kernel": "6.8.0",
                    "packages": ["curl\t8.5.0\tamd64"],
                    "containers": [],
                },
                {
                    "hostname": "batch-c",
                    "type": "container_host",
                    "os": "archlinux",
                    "os_version": "rolling",
                    "arch": "x86_64",
                    "kernel": "6.7.0",
                    "packages": [],
                    "containers": [],
                },
            ]
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["count"] == 3
    hosts = {item["hostname"] for item in data["items"]}
    assert hosts == {"batch-a", "batch-b", "batch-c"}

    for item in data["items"]:
        r = await client.get(f"/api/v1/nodes/{item['node_id']}", headers=auth)
        assert r.status_code == 200
        assert r.json()["node"]["hostname"] == item["hostname"]


@pytest.mark.anyio
async def test_nodes_report_batch_rollback_on_error(client, collect_auth, auth):
    """If one node fails, whole batch rolls back (atomicity)."""
    r = await client.post(
        "/api/v1/nodes/report-batch",
        json={
            "items": [
                {
                    "hostname": "rollback-ok",
                    "type": "vm",
                    "os": "debian",
                    "os_version": "12",
                    "arch": "x86_64",
                    "kernel": "6.1.0",
                    "packages": [],
                    "containers": [],
                },
                {
                    "hostname": "rollback-bad",
                    "type": "vm",
                    "os": "debian",
                    "os_version": "12",
                    "arch": "x86_64",
                    "kernel": "6.1.0",
                    "packages": [],
                    "hw_info": "not-valid-json",
                    "containers": [],
                },
            ]
        },
        headers=collect_auth,
    )
    assert r.status_code in (422, 500)
    r = await client.get("/api/v1/nodes?search=rollback-ok", headers=auth)
    hostnames = [n["hostname"] for n in r.json()["items"]]
    assert "rollback-ok" not in hostnames


@pytest.mark.anyio
async def test_nodes_report_batch_requires_collect_token(client):
    """Bulk endpoint enforces collect_token auth."""
    r = await client.post(
        "/api/v1/nodes/report-batch",
        json={"items": []},
    )
    assert r.status_code in (401, 403)
