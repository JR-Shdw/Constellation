"""CI/CD — servers validation, pipeline event/repo filters, workers list, stats."""

import uuid

import pytest

# Server validation


@pytest.mark.anyio
async def test_server_missing_name(client, auth):
    """Server without name returns 400."""
    r = await client.post(
        "/api/v1/cicd/servers",
        json={"url": "https://ci.test.com", "server_type": "woodpecker"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_server_missing_url(client, auth):
    """Server without url returns 400."""
    r = await client.post(
        "/api/v1/cicd/servers",
        json={"name": "test", "server_type": "woodpecker"},
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_server_token_encrypted_at_rest(client, auth):
    """CI/CD server tokens are Fernet-encrypted in the DB, and round-trip.

    A DB dump must not expose CI credentials in plaintext (parity with the
    Settings-managed forge/CI tokens).
    """
    import asyncpg

    from api.app.crypto import decrypt_setting
    from tests.conftest import ASYNCPG_DSN

    name = f"enc-srv-{uuid.uuid4().hex[:8]}"
    secret = "wp_tok_supersecret_12345"
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": name,
            "server_type": "woodpecker",
            "url": "https://wp.example",
            "token": secret,
        },
        headers=auth,
    )
    assert r.status_code == 200

    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        stored = await conn.fetchval(
            "SELECT token FROM cicd_servers WHERE name = $1", name
        )
    finally:
        await conn.close()

    assert stored != secret  # not plaintext
    assert stored.startswith("enc:")  # encrypted at rest
    assert decrypt_setting(stored) == secret  # readers get the real token


@pytest.mark.anyio
async def test_server_invalid_type(client, auth):
    """Server with invalid server_type returns 400."""
    r = await client.post(
        "/api/v1/cicd/servers",
        json={
            "name": "bad-type",
            "url": "https://ci.test.com",
            "server_type": "jenkins",
        },
        headers=auth,
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_server_delete_not_found(client, auth):
    """Delete non-existent server returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.delete(f"/api/v1/cicd/servers/{fake_id}", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_server_test_not_found(client, auth):
    """Test non-existent server returns 404."""
    fake_id = str(uuid.uuid4())
    r = await client.post(f"/api/v1/cicd/servers/{fake_id}/test", headers=auth)
    assert r.status_code == 404


# Pipeline filters (repo + event)


@pytest.mark.anyio
async def test_pipelines_filter_by_repo(client, auth, collect_auth):
    """Filter pipelines by repo name."""
    name = f"shdw/filter-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": name,
                "number": 1,
                "status": "success",
                "event": "push",
                "branch": "main",
            },
        ],
        headers=collect_auth,
    )
    r = await client.get(f"/api/v1/cicd/pipelines?repo={name}", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    for p in data["items"]:
        assert p["repo_name"] == name


@pytest.mark.anyio
async def test_pipelines_filter_by_event(client, auth, collect_auth):
    """Filter pipelines by event type."""
    name = f"shdw/evt-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": name,
                "number": 10,
                "status": "success",
                "event": "tag",
                "branch": "main",
            },
        ],
        headers=collect_auth,
    )
    r = await client.get("/api/v1/cicd/pipelines?event=tag", headers=auth)
    assert r.status_code == 200
    for p in r.json()["items"]:
        assert p["event"] == "tag"


# Workers list


@pytest.mark.anyio
async def test_workers_list_empty(client, auth):
    """Workers list with no data returns empty items."""
    r = await client.get("/api/v1/cicd/workers", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_workers_report_with_labels(client, collect_auth, auth):
    """Workers with labels and platform are ingested."""
    r = await client.post(
        "/api/v1/cicd/workers/report",
        json=[
            {
                "ci_system": "woodpecker",
                "external_id": "w-label-1",
                "name": "labeled-agent",
                "hostname": "worker-host",
                "platform": "linux/amd64",
                "labels": {"host": "worker-host", "env": "prod"},
                "capacity": 4,
                "status": "connected",
            },
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1

    # Verify in list
    r = await client.get("/api/v1/cicd/workers", headers=auth)
    items = r.json()["items"]
    found = [w for w in items if w.get("name") == "labeled-agent"]
    assert len(found) >= 1


@pytest.mark.anyio
async def test_workers_report_skip_no_id(client, collect_auth):
    """Workers without external_id are skipped."""
    r = await client.post(
        "/api/v1/cicd/workers/report",
        json=[
            {
                "ci_system": "woodpecker",
                "name": "no-id-agent",
                "hostname": "ghost",
            },
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] == 0


# Stats


@pytest.mark.anyio
async def test_cicd_stats_empty(client, auth):
    """Stats with no data returns structure."""
    r = await client.get("/api/v1/cicd/stats", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "total_repos" in data
    assert "latest_per_repo" in data


# Pipeline with all optional fields


@pytest.mark.anyio
async def test_pipeline_with_author_and_link(client, collect_auth):
    """Pipeline with all optional fields ingests correctly."""
    r = await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "repo_name": "shdw/full-fields",
                "number": 50,
                "status": "success",
                "event": "push",
                "branch": "main",
                "commit": "abc123",
                "message": "full pipeline",
                "author": "testuser",
                "duration_secs": 120,
                "link": "https://ci.example.com/1",
            },
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] >= 1


# Pipeline skip incomplete


@pytest.mark.anyio
async def test_pipeline_skip_no_repo(client, collect_auth):
    """Pipeline without repo_name is skipped."""
    r = await client.post(
        "/api/v1/cicd/pipelines/report",
        json=[
            {
                "ci_system": "woodpecker",
                "number": 1,
                "status": "success",
            },
        ],
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["upserted"] == 0
