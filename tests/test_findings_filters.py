"""Findings — filter builder, cleanup preview with filters, container score."""

import pytest


# Cleanup preview with filters

@pytest.mark.anyio
async def test_cleanup_preview_empty(client, auth):
    """Cleanup preview with no data."""
    r = await client.get("/api/v1/findings/cleanup/preview", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "host_count" in data or "total" in data


@pytest.mark.anyio
async def test_cleanup_preview_with_severity(client, auth):
    """Cleanup preview with severity filter."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?severity=low",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cleanup_preview_with_status(client, auth):
    """Cleanup preview with status filter."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?status=open",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cleanup_preview_exploited(client, auth):
    """Cleanup preview with exploited filter."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?exploited=false",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cleanup_preview_os_arch(client, auth):
    """Cleanup preview with os and arch filters."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?os_filter=debian&arch_filter=x86_64",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cleanup_preview_pkg_name(client, auth):
    """Cleanup preview with pkg_name filter."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?pkg_name=openssl",
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cleanup_preview_older_than(client, auth):
    """Cleanup preview with older_than_days filter."""
    r = await client.get(
        "/api/v1/findings/cleanup/preview?older_than_days=30",
        headers=auth,
    )
    assert r.status_code == 200


# Cleanup list

@pytest.mark.anyio
async def test_cleanup_list_empty(client, auth):
    """Cleanup list with no data."""
    r = await client.get("/api/v1/findings/cleanup/list", headers=auth)
    assert r.status_code == 200


# Container finding score

@pytest.mark.anyio
async def test_container_score_not_found(client, auth):
    """Container finding score for non-existent ID."""
    fake_id = "00000000-0000-0000-0000-000000000001"
    r = await client.get(
        f"/api/v1/findings/container/{fake_id}/score?listen=internet",
        headers=auth,
    )
    assert r.status_code == 200
    assert "error" in r.json()


# Host finding score

@pytest.mark.anyio
async def test_host_score_not_found(client, auth):
    """Host finding score for non-existent ID."""
    fake_id = "00000000-0000-0000-0000-000000000001"
    r = await client.get(
        f"/api/v1/findings/host/{fake_id}/score",
        headers=auth,
    )
    assert r.status_code == 200


# Patch host finding

@pytest.mark.anyio
async def test_patch_host_finding_not_found(client, auth):
    """Patch non-existent host finding."""
    fake_id = "00000000-0000-0000-0000-000000000001"
    r = await client.patch(
        f"/api/v1/findings/host/{fake_id}",
        json={"status": "resolved"},
        headers=auth,
    )
    assert r.status_code in (200, 404)


# Auto-resolve

@pytest.mark.anyio
async def test_auto_resolve_empty(client, auth):
    """Auto-resolve with no fixed CVEs."""
    r = await client.post("/api/v1/findings/auto-resolve", headers=auth)
    assert r.status_code == 200
