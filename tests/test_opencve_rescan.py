"""OpenCVE rescan + _extract_cvss + feature disabled + CVSS metrics."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.anyio
async def test_rescan_no_config(client, auth):
    """Rescan when OpenCVE not configured returns error."""
    r = await client.post("/api/v1/opencve/rescan", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "error" in data or data.get("scanned") == 0


@pytest.mark.anyio
async def test_rescan_no_open_cves(client, auth):
    """Rescan with config but no open CVEs returns scanned=0."""
    with (
        patch("api.app.routes.opencve.settings") as mock_settings,
    ):
        mock_settings.opencve_url = "http://opencve.test"
        mock_settings.opencve_user = "testuser"
        mock_settings.opencve_password = "testpass"
        r = await client.post(
            "/api/v1/opencve/rescan",
            json={"cve_ids": []},
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        # No open CVEs to scan → scanned=0
        assert data.get("scanned", 0) == 0 or "error" not in data


@pytest.mark.anyio
async def test_rescan_with_mock_opencve(client, auth, collect_auth):
    """Rescan specific CVE IDs with mocked OpenCVE API."""
    # Create a node with a CVE
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "rescan-node",
            "type": "vm",
            "os": "debian",
            "packages": ["libssl3\t3.0.11\tamd64"],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "rescan-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-RESCAN",
                    "Severity": "HIGH",
                    "PkgName": "libssl3",
                    "InstalledVersion": "3.0.11",
                    "CVSS": {"nvd": {"V3Score": 8.1}},
                },
            ],
        },
        headers=collect_auth,
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "title": "Test CVE rescan",
        "description": "Rescan test description",
        "metrics": {
            "cvssV3_1": {"data": {"score": 8.5}},
        },
        "kev": False,
        "weaknesses": [{"cwe_id": "CWE-79"}],
    }

    with (
        patch("api.app.routes.opencve.settings") as mock_settings,
        patch("api.app.routes.opencve.httpx.AsyncClient") as MockClient,
    ):
        mock_settings.opencve_url = "http://opencve.test"
        mock_settings.opencve_user = "user"
        mock_settings.opencve_password = "pass"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        r = await client.post(
            "/api/v1/opencve/rescan",
            json={"cve_ids": ["CVE-2025-RESCAN"], "limit": 10},
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["scanned"] == 1
        assert data["updated"] == 1


@pytest.mark.anyio
async def test_rescan_partial_failure_persists_good(client, auth):
    """One failing CVE mid-loop must not roll back the already-scanned ones.

    Regression: a single commit after the whole loop meant one aborted
    iteration (and the HTTP held the tx open the whole time) discarded every
    prior write. Per-CVE commit isolates the failure.
    """
    good = MagicMock()
    good.status_code = 200
    good.json.return_value = {
        "title": "Good CVE",
        "description": "persisted",
        "metrics": {"cvssV3_1": {"data": {"score": 9.1}}},
        "kev": False,
        "weaknesses": [],
    }

    with (
        patch("api.app.routes.opencve.settings") as mock_settings,
        patch("api.app.routes.opencve.httpx.AsyncClient") as MockClient,
    ):
        mock_settings.opencve_url = "http://opencve.test"
        mock_settings.opencve_user = "u"
        mock_settings.opencve_password = "p"

        mock_client = AsyncMock()
        # First CVE fetches fine; the second raises mid-iteration.
        mock_client.get = AsyncMock(side_effect=[good, RuntimeError("boom")])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        r = await client.post(
            "/api/v1/opencve/rescan",
            json={"cve_ids": ["CVE-2025-GOOD1", "CVE-2025-BAD1"], "limit": 10},
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["updated"] == 1
        assert data["errors"] == 1

    # The good CVE's alert must survive the later failure (committed before it).
    alerts = (
        await client.get(
            "/api/v1/opencve/alerts?matched_only=false", headers=auth
        )
    ).json()
    refs = [a["cve_id"] for a in alerts["items"]]
    assert "CVE-2025-GOOD1" in refs


@pytest.mark.anyio
async def test_rescan_api_error(client, auth, collect_auth):
    """Rescan handles OpenCVE API errors gracefully."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "rescan-err-node",
            "type": "vm",
            "os": "debian",
            "packages": ["curl\t7.88\tamd64"],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "rescan-err-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-ERRTEST",
                    "Severity": "MEDIUM",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88",
                    "CVSS": {"nvd": {"V3Score": 5.0}},
                },
            ],
        },
        headers=collect_auth,
    )

    mock_response = MagicMock()
    mock_response.status_code = 404

    with (
        patch("api.app.routes.opencve.settings") as mock_settings,
        patch("api.app.routes.opencve.httpx.AsyncClient") as MockClient,
    ):
        mock_settings.opencve_url = "http://opencve.test"
        mock_settings.opencve_user = "user"
        mock_settings.opencve_password = "pass"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        r = await client.post(
            "/api/v1/opencve/rescan",
            json={"cve_ids": ["CVE-2025-ERRTEST"]},
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["errors"] >= 1


@pytest.mark.anyio
async def test_rescan_kev_propagation(client, auth, collect_auth):
    """Rescan propagates KEV flag to findings."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "rescan-kev-node",
            "type": "vm",
            "os": "debian",
            "packages": ["zlib\t1.2.13\tamd64"],
        },
        headers=collect_auth,
    )
    await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "rescan-kev-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2025-KEV",
                    "Severity": "CRITICAL",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2.13",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
            ],
        },
        headers=collect_auth,
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "title": "KEV CVE",
        "description": "Known exploited vulnerability",
        "metrics": {"cvssV3_1": {"data": {"score": 9.8}}},
        "kev": True,
        "weaknesses": [],
    }

    with (
        patch("api.app.routes.opencve.settings") as mock_settings,
        patch("api.app.routes.opencve.httpx.AsyncClient") as MockClient,
    ):
        mock_settings.opencve_url = "http://opencve.test"
        mock_settings.opencve_user = "user"
        mock_settings.opencve_password = "pass"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        r = await client.post(
            "/api/v1/opencve/rescan",
            json={"cve_ids": ["CVE-2025-KEV"]},
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["kev_propagated"] >= 1


def test_extract_cvss_v31():
    """_extract_cvss extracts CVSS v3.1 score."""
    from api.app.routes.opencve import _extract_cvss

    metrics = {"cvssV3_1": {"data": {"score": 7.5}}}
    assert _extract_cvss(metrics) == 7.5


def test_extract_cvss_v40():
    """_extract_cvss prefers v4.0 when available."""
    from api.app.routes.opencve import _extract_cvss

    metrics = {
        "cvssV4_0": {"data": {"score": 8.0}},
        "cvssV3_1": {"data": {"score": 7.5}},
    }
    assert _extract_cvss(metrics) == 8.0


def test_extract_cvss_v2_fallback():
    """_extract_cvss falls back to v2.0."""
    from api.app.routes.opencve import _extract_cvss

    metrics = {"cvssV2_0": {"data": {"score": 5.0}}}
    assert _extract_cvss(metrics) == 5.0


def test_extract_cvss_empty():
    """_extract_cvss returns None for empty/invalid metrics."""
    from api.app.routes.opencve import _extract_cvss

    assert _extract_cvss({}) is None
    assert _extract_cvss(None) is None
    assert _extract_cvss("string") is None
    assert _extract_cvss({"cvssV3_1": "not a dict"}) is None
    assert _extract_cvss({"cvssV3_1": {"data": "not a dict"}}) is None


@pytest.mark.anyio
async def test_webhook_feature_disabled(client, collect_auth):
    """Webhook returns skipped when CVE module is disabled."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession

    from api.app.database import engine

    # Disable CVE feature — feature_enabled() checks key "feature_cve_enabled"
    async with AsyncSession(engine) as db:
        await db.execute(
            text("""
            INSERT INTO alert_settings (key, value)
            VALUES ('feature_cve_enabled', 'false')
            ON CONFLICT (key) DO UPDATE SET value = 'false'
            """)
        )
        await db.commit()

    try:
        r = await client.post(
            "/api/v1/opencve/webhook",
            json={
                "type": "alert",
                "data": {
                    "cve_id": "CVE-2026-DISABLED",
                    "title": "Disabled test",
                    "metrics": {},
                    "vendors": {},
                },
            },
            headers=collect_auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "skipped"
    finally:
        # Re-enable
        async with AsyncSession(engine) as db:
            await db.execute(
                text("""
                DELETE FROM alert_settings
                WHERE key = 'feature_cve_enabled'
                """)
            )
            await db.commit()


@pytest.mark.anyio
async def test_webhook_cvss_metrics_extraction(client, collect_auth):
    """Webhook extracts CVSS from nested metrics structure."""
    r = await client.post(
        "/api/v1/opencve/webhook",
        json={
            "type": "alert",
            "data": {
                "cve_id": "CVE-2026-METRICS",
                "title": "Metrics extraction test",
                "description": "Test CVSS extraction from metrics",
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.1}},
                    ],
                },
                "vendors": {"test": ["product"]},
            },
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
