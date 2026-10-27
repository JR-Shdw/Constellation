"""Resync endpoints — reset CVE coverage (no trigger tests that poll)."""

import pytest


# Reset CVE

@pytest.mark.anyio
async def test_reset_cve_correct_confirm(client, auth):
    """Reset CVE with correct confirmation truncates tables."""
    await client.put(
        "/api/v1/settings/alerts",
        json={"feature_cve_enabled": "true"},
        headers=auth,
    )
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={"confirm": "RESET CVE"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "truncated" in r.json()["detail"]


@pytest.mark.anyio
async def test_reset_cve_with_resync_flags(client, auth):
    """Reset CVE with resync flags (trigger files may fail, that's ok)."""
    await client.put(
        "/api/v1/settings/alerts",
        json={"feature_cve_enabled": "true"},
        headers=auth,
    )
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={
            "confirm": "RESET CVE",
            "resync_wazuh": True,
            "resync_opencve": True,
            "opencve_hours": 48,
        },
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_reset_cve_disabled(client, auth):
    """Reset CVE when feature disabled returns error."""
    await client.put(
        "/api/v1/settings/alerts",
        json={"feature_cve_enabled": "false"},
        headers=auth,
    )
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={"confirm": "RESET CVE"},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_reset_cve_wrong_confirm(client, auth):
    """Reset CVE with wrong confirm returns 400."""
    await client.put(
        "/api/v1/settings/alerts",
        json={"feature_cve_enabled": "true"},
        headers=auth,
    )
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={"confirm": "wrong"},
        headers=auth,
    )
    assert r.status_code == 400
