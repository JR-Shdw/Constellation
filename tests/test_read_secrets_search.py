"""Read module — secrets list, patch, global search, stats feature flags."""

import pytest


# Secrets list

@pytest.mark.anyio
async def test_secrets_list_empty(client, auth):
    """Secrets list with no data returns empty."""
    r = await client.get("/api/v1/secrets", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.anyio
async def test_secrets_list_with_filters(client, auth):
    """Secrets list with filters returns valid response."""
    r = await client.get(
        "/api/v1/secrets?status=open&severity=high&search=test",
        headers=auth,
    )
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_secrets_list_sort(client, auth):
    """Secrets list with sort parameters."""
    r = await client.get(
        "/api/v1/secrets?sort_by=severity&sort_dir=desc",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_secrets_list_hostname_filter(client, auth):
    """Secrets list filtered by hostname."""
    r = await client.get(
        "/api/v1/secrets?hostname=test",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_secrets_list_node_filter(client, auth):
    """Secrets list filtered by node_id."""
    r = await client.get(
        "/api/v1/secrets?node_id=00000000-0000-0000-0000-000000000001",
        headers=auth,
    )
    assert r.status_code == 200


# Secrets patch

@pytest.mark.anyio
async def test_patch_secret_not_found(client, auth):
    """Patch non-existent secret still returns ok (no row matched)."""
    r = await client.patch(
        "/api/v1/secrets/00000000-0000-0000-0000-000000000001",
        json={"status": "resolved"},
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_patch_secret_invalid_status(client, auth):
    """Patch secret with invalid status returns 400."""
    r = await client.patch(
        "/api/v1/secrets/00000000-0000-0000-0000-000000000001",
        json={"status": "invalid_status"},
        headers=auth,
    )
    assert r.status_code == 400


# Global search

@pytest.mark.anyio
async def test_global_search(client, auth, collect_auth):
    """Global search returns structured results."""
    # Create some data first
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "searchable-host",
            "os": "Debian 12",
            "os_family": "debian",
            "kernel": "6.1.0",
            "arch": "x86_64",
            "packages": [{"name": "openssl", "version": "3.0.11", "source": "apt"}],
            "containers": [],
        },
        headers=collect_auth,
    )

    r = await client.get("/api/v1/search?q=searchable", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "nodes" in data
    assert "packages" in data
    assert "containers" in data
    assert "cves" in data


@pytest.mark.anyio
async def test_global_search_short_query(client, auth):
    """Global search with too-short query returns 422."""
    r = await client.get("/api/v1/search?q=a", headers=auth)
    assert r.status_code == 422


# Stats

@pytest.mark.anyio
async def test_stats_has_fields(client, auth):
    """Stats returns expected fields."""
    r = await client.get("/api/v1/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "feature_cve_enabled" in data
    assert "feature_backup_enabled" in data
    assert "cve_count_exclude_medium" in data
    assert "cve_count_exclude_low" in data


@pytest.mark.anyio
async def test_stats_exclude_settings(client, auth):
    """Stats with medium/low exclusion settings."""
    await client.put(
        "/api/v1/settings/alerts",
        json={
            "cve_count_exclude_medium": "true",
            "cve_count_exclude_low": "true",
        },
        headers=auth,
    )
    # Stats may be cached, but settings are saved
    r = await client.get("/api/v1/stats", headers=auth)
    assert r.status_code == 200

    # Reset
    await client.put(
        "/api/v1/settings/alerts",
        json={
            "cve_count_exclude_medium": "false",
            "cve_count_exclude_low": "false",
        },
        headers=auth,
    )


# Stats trends

@pytest.mark.anyio
async def test_stats_trends(client, auth):
    """Stats trends returns time series."""
    r = await client.get("/api/v1/stats/trends?days=7", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_stats_trends_1day(client, auth):
    """Stats trends with 1 day (hourly grouping)."""
    r = await client.get("/api/v1/stats/trends?days=1", headers=auth)
    assert r.status_code == 200
