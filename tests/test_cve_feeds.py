"""CVE feeds — connector parsing + CRUD + fetch ingestion."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import asyncpg
import httpx
import pytest

from api.app.connectors import cve_feed

from .conftest import ASYNCPG_DSN

_RSS_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>CERT-FR Avis</title>
<item>
  <title>Multiples vulnérabilités dans Roundcube (gravité critique)</title>
  <link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2099-AVI-001/</link>
  <guid>CERTFR-2099-AVI-001</guid>
  <description>Plusieurs failles dont CVE-2099-9001 et CVE-2099-9002.</description>
  <pubDate>Mon, 03 Mar 2099 12:34:00 +0000</pubDate>
</item>
<item>
  <title>Bulletin générique sans CVE</title>
  <link>https://example.test/no-cve</link>
  <guid>NO-CVE-001</guid>
  <description>Pas de référence CVE ici, gravité faible.</description>
  <pubDate>Tue, 04 Mar 2099 09:00:00 +0000</pubDate>
</item>
</channel>
</rss>
""".encode()

_ATOM_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Custom Atom feed</title>
  <entry>
    <title>Heads-up on CVE-2099-7777 (high severity)</title>
    <id>tag:example.test,2099:atom-001</id>
    <link rel="alternate" href="https://example.test/atom-001"/>
    <summary>Affecting many products. Critical fix incoming.</summary>
    <published>2099-03-05T08:00:00Z</published>
  </entry>
</feed>
""".encode()


# ── Connector parsing ──────────────────────────────────────────────────


def test_parse_rss_extracts_cves_and_severity():
    advs = cve_feed.parse_feed(_RSS_FIXTURE)
    assert len(advs) == 2
    a = advs[0]
    assert a.advisory_ref == "CERTFR-2099-AVI-001"
    assert "CVE-2099-9001" in a.cve_ids
    assert "CVE-2099-9002" in a.cve_ids
    assert a.severity == "critical"
    # Item without CVE references
    assert advs[1].cve_ids == []
    assert advs[1].severity == "low"


def test_parse_atom_extracts_cve_and_link():
    advs = cve_feed.parse_feed(_ATOM_FIXTURE)
    assert len(advs) == 1
    a = advs[0]
    assert a.url == "https://example.test/atom-001"
    assert a.cve_ids == ["CVE-2099-7777"]
    # "critical fix" matches "critical" before "high" in our ordering — we want
    # the rule to detect the highest severity word present in the blob.
    assert a.severity in ("critical", "high")


def test_parse_invalid_xml_raises():
    with pytest.raises(cve_feed.FeedError):
        cve_feed.parse_feed(b"not xml")


def test_parse_date_normalises_naive_iso_to_utc():
    """Atom feeds without an offset (e.g. '2099-03-05T08:00:00') must come
    back as aware UTC datetimes — otherwise asyncpg's astimezone(utc) would
    silently shift them by the API container's local TZ offset."""
    from datetime import timezone

    naive_dt = cve_feed._parse_date("2099-03-05T08:00:00")
    assert naive_dt is not None
    assert naive_dt.tzinfo is not None, "_parse_date must never return a naive dt"
    assert naive_dt.utcoffset() == timezone.utc.utcoffset(None)

    # Z and explicit offsets keep working too.
    z_dt = cve_feed._parse_date("2099-03-05T08:00:00Z")
    assert z_dt is not None and z_dt.tzinfo is not None
    off_dt = cve_feed._parse_date("2099-03-05T10:00:00+02:00")
    assert off_dt is not None and off_dt.utcoffset() == timezone.utc.utcoffset(None)
    assert off_dt.hour == 8  # normalised back to UTC


# ── CRUD over the API ──────────────────────────────────────────────────


@pytest.mark.anyio
async def test_feeds_crud_lifecycle(client, auth):
    # Listing works on an empty (truncated) table.
    r = await client.get("/api/v1/cve-feeds", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()

    # Create
    r = await client.post(
        "/api/v1/cve-feeds",
        json={
            "name": "Test feed",
            "url": "https://example.test/feed.xml",
            "feed_type": "rss",
            "source_label": "custom",
        },
        headers=auth,
    )
    assert r.status_code == 200
    feed_id = r.json()["id"]

    # Duplicate URL → 409
    r = await client.post(
        "/api/v1/cve-feeds",
        json={"name": "dup", "url": "https://example.test/feed.xml"},
        headers=auth,
    )
    assert r.status_code == 409

    # Patch (rename + disable)
    r = await client.patch(
        f"/api/v1/cve-feeds/{feed_id}",
        json={"name": "Renamed", "enabled": False},
        headers=auth,
    )
    assert r.status_code == 200

    # Delete
    r = await client.delete(f"/api/v1/cve-feeds/{feed_id}", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_create_feed_rejects_bad_input(client, auth):
    r = await client.post(
        "/api/v1/cve-feeds",
        json={"name": "no url"},
        headers=auth,
    )
    assert r.status_code == 400
    r = await client.post(
        "/api/v1/cve-feeds",
        json={"name": "x", "url": "u", "feed_type": "json"},
        headers=auth,
    )
    assert r.status_code == 400


# ── Fetch + ingestion ──────────────────────────────────────────────────


def _httpx_mock(body: bytes, status: int = 200):
    """Return a mocked httpx response."""
    req = httpx.Request("GET", "https://example.test/feed")
    return httpx.Response(status, content=body, request=req)


@pytest.mark.anyio
async def test_fetch_feed_ingests_advisories_and_matches(client, auth):
    # Seed a CVE that the RSS fixture references, on a real node so the
    # advisory gets a non-zero matched_node_count.
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ('feed-host', 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_catalog (cve_id, description)
            VALUES ('CVE-2099-9001', 'feed match'),
                   ('CVE-2099-9002', 'feed match 2')
            ON CONFLICT (cve_id) DO NOTHING
            """
        )
        await conn.execute(
            """
            INSERT INTO cve_host_packages
                (node_id, cve_id, severity, pkg_name, installed_ver,
                 status, source)
            VALUES ($1, 'CVE-2099-9001', 'high', 'libfoo', '1.0',
                    'open', 'trivy')
            """,
            node_id,
        )
    finally:
        await conn.close()

    # Create a feed pointing at a fake URL.
    r = await client.post(
        "/api/v1/cve-feeds",
        json={
            "name": "Fixture",
            "url": "https://example.test/fix-feed.xml",
            "feed_type": "rss",
        },
        headers=auth,
    )
    feed_id = r.json()["id"]

    # Mock httpx so the connector doesn't actually hit the network.
    fake_get = AsyncMock(return_value=_httpx_mock(_RSS_FIXTURE))
    with patch("httpx.AsyncClient.get", fake_get):
        r = await client.post(
            f"/api/v1/cve-feeds/{feed_id}/fetch",
            headers=auth,
        )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["total"] == 2
    assert data["new"] == 2
    assert data["matched_cves"] >= 1

    # Advisories endpoint surfaces the new entry, with matched count.
    r = await client.get(
        f"/api/v1/cve-feeds/advisories?feed_id={feed_id}&matched_only=true",
        headers=auth,
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(it["advisory_ref"] == "CERTFR-2099-AVI-001" for it in items)
    matched = next(i for i in items if i["advisory_ref"] == "CERTFR-2099-AVI-001")
    assert matched["matched_cve_count"] >= 1
    assert matched["matched_node_count"] >= 1
    # cve_ids must contain the FULL list from the bulletin, not just the
    # subset that's in cve_catalog. Only CVE-2099-9001 is seeded above —
    # the second one (CVE-2099-9002) is intentionally not in the catalog,
    # but it must still be persisted on the advisory row so a later catalog
    # update can correlate it.
    cve_ids = matched.get("cve_ids") or []
    assert "CVE-2099-9001" in cve_ids
    assert "CVE-2099-9002" in cve_ids


@pytest.mark.anyio
async def test_advisory_with_many_matches_sends_one_notification(client, auth):
    """Regression : an advisory referencing N inventory CVEs must produce
    exactly ONE notify_advisory call, not N notify_cve calls. Previous
    behavior fanned out into N Matrix/email/webhook messages per advisory."""
    # Seed a node + 3 CVEs both in catalog and in cve_host_packages → all
    # match, all are "open" on a real node. CVE IDs MUST be all-digit —
    # cve_feed._CVE_RE is r"CVE-\d{4}-\d{4,7}", so any letter in the ID
    # silently fails to match and notify_advisory is never called.
    suffix = uuid.uuid4().hex[:8]
    cve_ids = ("CVE-2099-8001", "CVE-2099-8002", "CVE-2099-8003")
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_id = await conn.fetchval(
            """
            INSERT INTO nodes (hostname, type, os, os_version, arch)
            VALUES ($1, 'vm', 'debian', '12', 'amd64')
            RETURNING id
            """,
            f"adv-batch-{suffix}",
        )
        for cid in cve_ids:
            await conn.execute(
                "INSERT INTO cve_catalog (cve_id, description) VALUES ($1, 'b')"
                " ON CONFLICT (cve_id) DO NOTHING",
                cid,
            )
            await conn.execute(
                """
                INSERT INTO cve_host_packages
                    (node_id, cve_id, severity, pkg_name, installed_ver,
                     status, source)
                VALUES ($1, $2, 'critical', 'libfoo', '1.0', 'open', 'trivy')
                ON CONFLICT DO NOTHING
                """,
                node_id,
                cid,
            )
    finally:
        await conn.close()

    # Build a fixture referencing all three CVEs.
    fixture = (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<rss version='2.0'><channel>"
        "<item>"
        "<title>Avis multi-CVE (gravité critique)</title>"
        "<link>https://example.test/multi</link>"
        f"<guid>BATCH-{suffix}</guid>"
        f"<description>Avis {', '.join(cve_ids)}</description>"
        "<pubDate>Mon, 03 Mar 2099 12:34:00 +0000</pubDate>"
        "</item></channel></rss>"
    ).encode()

    r = await client.post(
        "/api/v1/cve-feeds",
        json={
            "name": f"Batch fixture {suffix}",
            "url": f"https://example.test/batch-{suffix}.xml",
            "feed_type": "rss",
        },
        headers=auth,
    )
    feed_id = r.json()["id"]

    fake_get = AsyncMock(return_value=_httpx_mock(fixture))
    with (
        patch("httpx.AsyncClient.get", fake_get),
        patch(
            "api.app.routes.cve_feeds.notify_advisory",
            new=AsyncMock(),
        ) as notif,
    ):
        r = await client.post(
            f"/api/v1/cve-feeds/{feed_id}/fetch",
            headers=auth,
        )
    assert r.status_code == 200
    # ONE call for the advisory regardless of matched CVE count.
    assert notif.await_count == 1, (
        f"expected 1 advisory notification, got {notif.await_count}"
    )
    kwargs = notif.await_args.kwargs
    assert kwargs["advisory_ref"] == f"BATCH-{suffix}"
    assert sorted(kwargs["cve_ids"]) == list(cve_ids)


@pytest.mark.anyio
async def test_auto_fetch_schedule_lifecycle(client, auth):
    # Initially nothing scheduled
    r = await client.get("/api/v1/cve-feeds/auto-fetch", headers=auth)
    assert r.status_code == 200
    assert r.json()["scheduled"] is False

    # Schedule with custom cron
    r = await client.post(
        "/api/v1/cve-feeds/auto-fetch",
        json={"cron_expr": "*/15 * * * *", "enabled": True},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json()["cron_expr"] == "*/15 * * * *"

    # Status now reflects the job
    r = await client.get("/api/v1/cve-feeds/auto-fetch", headers=auth)
    data = r.json()
    assert data["scheduled"] is True
    assert data["cron_expr"] == "*/15 * * * *"
    assert data["enabled"] is True

    # Update cron — same job, no duplicate
    r = await client.post(
        "/api/v1/cve-feeds/auto-fetch",
        json={"cron_expr": "0 */2 * * *", "enabled": True},
        headers=auth,
    )
    assert r.status_code == 200
    r = await client.get("/api/v1/cve-feeds/auto-fetch", headers=auth)
    assert r.json()["cron_expr"] == "0 */2 * * *"

    # next_run_at must be set so the scheduler tick actually picks it up.
    # NULL would silently pass tests that only check cron_expr, then make
    # the job invisible to `WHERE next_run_at <= NOW()` until restart.
    assert data.get("next_run_at"), "next_run_at must be populated"

    # Updating the cron must recompute next_run_at — otherwise a cron edit
    # from daily to */15 wouldn't take effect for up to 24h.
    # Use a fixed-minute cron whose schedule never coincides with */15
    # (minutes 0/15/30/45) — otherwise both crons can resolve to the same
    # next tick and falsely fail the != check.
    prev_next = data["next_run_at"]
    r = await client.post(
        "/api/v1/cve-feeds/auto-fetch",
        json={"cron_expr": "13 * * * *", "enabled": True},
        headers=auth,
    )
    assert r.status_code == 200
    r = await client.get("/api/v1/cve-feeds/auto-fetch", headers=auth)
    new_data = r.json()
    assert new_data["cron_expr"] == "13 * * * *"
    assert new_data["next_run_at"] != prev_next

    # Invalid cron must be rejected up front.
    r = await client.post(
        "/api/v1/cve-feeds/auto-fetch",
        json={"cron_expr": "not a cron", "enabled": True},
        headers=auth,
    )
    assert r.status_code == 400

    # Disable — DELETE drops the job
    r = await client.delete("/api/v1/cve-feeds/auto-fetch", headers=auth)
    assert r.status_code == 200
    assert r.json()["deleted"] == 1

    r = await client.get("/api/v1/cve-feeds/auto-fetch", headers=auth)
    assert r.json()["scheduled"] is False


@pytest.mark.anyio
async def test_fetch_feed_records_error_on_http_failure(client, auth):
    r = await client.post(
        "/api/v1/cve-feeds",
        json={"name": "broken", "url": "https://example.test/broken.xml"},
        headers=auth,
    )
    feed_id = r.json()["id"]

    async def boom(*_a, **_k):
        raise httpx.ConnectError("DNS fail")

    with patch("httpx.AsyncClient.get", boom):
        r = await client.post(
            f"/api/v1/cve-feeds/{feed_id}/fetch",
            headers=auth,
        )
    assert r.status_code == 200
    assert r.json()["status"] == "error"

    r = await client.get("/api/v1/cve-feeds", headers=auth)
    feed = next(f for f in r.json()["items"] if f["id"] == feed_id)
    assert feed["last_status"] == "error"
    assert feed["last_error"]
