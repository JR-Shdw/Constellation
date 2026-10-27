"""Resync tests — trigger endpoints + reset-cve with confirmation."""

import pytest


@pytest.fixture(autouse=True)
def _fast_resync(monkeypatch, tmp_path):
    """Mock trigger dir + wait for ALL resync tests (avoid 300s poll)."""
    import api.app.routes.resync as resync_mod

    monkeypatch.setattr(resync_mod, "TRIGGER_DIR", tmp_path)

    async def _instant(*a, **kw):
        return None

    monkeypatch.setattr(resync_mod, "_wait_for_result", _instant)


@pytest.mark.anyio
async def test_resync_wazuh(client, auth):
    """Wazuh resync triggers successfully."""
    r = await client.post("/api/v1/resync/wazuh", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_resync_opencve(client, auth):
    """OpenCVE resync triggers successfully."""
    r = await client.post(
        "/api/v1/resync/opencve",
        json={"hours": 24},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_reset_cve_wrong_confirmation(client, auth):
    """Reset CVE without proper confirmation returns 400."""
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={"confirm": "wrong"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_reset_cve_empty_confirmation(client, auth):
    """Reset CVE without confirm field returns 400."""
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_reset_cve_success(client, auth):
    """Reset CVE with correct confirmation truncates tables."""
    r = await client.post(
        "/api/v1/resync/reset-cve",
        json={"confirm": "RESET CVE"},
        headers=auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "truncated" in data["detail"]


@pytest.mark.anyio
async def test_reset_cve_with_resync(client, auth):
    """Reset CVE with resync triggers."""
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
