"""Read — CVE list filters, node detail, container list extras."""

import uuid

import pytest

# CVE list filters


@pytest.mark.anyio
async def test_cve_list_filter_severity(client, auth):
    """CVE list filtered by severity."""
    r = await client.get("/api/v1/cves?severity=critical", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.anyio
async def test_cve_list_filter_target_type(client, auth):
    """CVE list filtered by target_type."""
    r = await client.get("/api/v1/cves?target_type=host", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_source(client, auth):
    """CVE list filtered by source."""
    r = await client.get("/api/v1/cves?source=trivy", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_exploited(client, auth):
    """CVE list filtered by exploited flag."""
    r = await client.get("/api/v1/cves?exploited=true", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_workflow_status(client, auth):
    """CVE list filtered by workflow_status."""
    r = await client.get("/api/v1/cves?workflow_status=open", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_environment(client, auth):
    """CVE list filtered by environment."""
    r = await client.get("/api/v1/cves?environment=production", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_hostname(client, auth):
    """CVE list filtered by hostname."""
    r = await client.get("/api/v1/cves?hostname=test", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_filter_node_id(client, auth):
    """CVE list filtered by node_id."""
    fake_id = str(uuid.uuid4())
    r = await client.get(f"/api/v1/cves?node_id={fake_id}", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_sort_score(client, auth):
    """CVE list sorted by score."""
    r = await client.get("/api/v1/cves?sort=score&order=desc", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_triage_mode(client, auth):
    """CVE list in triage mode."""
    r = await client.get("/api/v1/cves?triage=true", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_search(client, auth):
    """CVE list with search parameter."""
    r = await client.get("/api/v1/cves?search=CVE-2024", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_list_pagination(client, auth):
    """CVE list pagination parameters."""
    r = await client.get("/api/v1/cves?page=1&per_page=10", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "page" in data or "items" in data


# Node list


@pytest.mark.anyio
async def test_nodes_list_dropdown(client, auth):
    """Nodes list endpoint for dropdown."""
    r = await client.get("/api/v1/nodes/list", headers=auth)
    assert r.status_code == 200


# Containers list


@pytest.mark.anyio
async def test_containers_list_empty(client, auth):
    """Container list with no data."""
    r = await client.get("/api/v1/containers", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
