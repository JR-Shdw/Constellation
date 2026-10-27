"""Misconfigurations — extra filters (status, hostname, sort) + compliance."""

import pytest


@pytest.fixture
async def misconf_data(client, collect_auth):
    """Create a node with misconfigurations."""
    hostname = "misconf-extra-node"
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/misconfigurations/report",
        json={
            "hostname": hostname,
            "source": "trivy",
            "misconfigurations": [
                {
                    "ID": "EXTRA-CRIT-001",
                    "Title": "Critical misconfiguration",
                    "Severity": "CRITICAL",
                    "Target": "etc/ssh/sshd_config",
                    "Message": "PermitRootLogin enabled",
                    "Resolution": "Set PermitRootLogin no",
                    "Status": "FAIL",
                },
                {
                    "ID": "EXTRA-LOW-002",
                    "Title": "Low misconfiguration",
                    "Severity": "LOW",
                    "Target": "etc/passwd",
                    "Message": "Unused user found",
                    "Resolution": "Remove unused users",
                    "Status": "PASS",
                },
            ],
        },
        headers=collect_auth,
    )
    return hostname


@pytest.mark.anyio
async def test_misconf_filter_status(client, auth, misconf_data):
    """Filter misconfigurations by status."""
    r = await client.get("/api/v1/misconfigurations?status=FAIL", headers=auth)
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["status"].upper() == "FAIL"


@pytest.mark.anyio
async def test_misconf_filter_hostname(client, auth, misconf_data):
    """Filter misconfigurations by hostname partial match."""
    r = await client.get(
        "/api/v1/misconfigurations?hostname=misconf-extra", headers=auth
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


@pytest.mark.anyio
async def test_misconf_sort_severity(client, auth, misconf_data):
    """Sort misconfigurations by severity."""
    r = await client.get(
        "/api/v1/misconfigurations?sort_by=severity&sort_dir=asc", headers=auth
    )
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_misconf_sort_hostname(client, auth, misconf_data):
    """Sort misconfigurations by hostname."""
    r = await client.get(
        "/api/v1/misconfigurations?sort_by=hostname&sort_dir=desc", headers=auth
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_misconf_sort_detected_at(client, auth, misconf_data):
    """Sort misconfigurations by detection date."""
    r = await client.get(
        "/api/v1/misconfigurations?sort_by=detected_at&sort_dir=desc", headers=auth
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_misconf_sort_rule_id(client, auth, misconf_data):
    """Sort misconfigurations by rule_id."""
    r = await client.get(
        "/api/v1/misconfigurations?sort_by=rule_id&sort_dir=asc", headers=auth
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_misconf_combined_filters(client, auth, misconf_data):
    """Combine multiple filters: severity + hostname + sort."""
    r = await client.get(
        "/api/v1/misconfigurations?severity=critical&hostname=misconf-extra"
        "&sort_by=severity&sort_dir=desc",
        headers=auth,
    )
    assert r.status_code == 200
    for item in r.json()["items"]:
        assert item["severity"] == "critical"


@pytest.mark.anyio
async def test_misconf_pagination(client, auth, misconf_data):
    """Misconfigurations pagination."""
    r = await client.get("/api/v1/misconfigurations?page=1&per_page=1", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) <= 1
    assert "total" in data
