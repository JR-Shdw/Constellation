# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Materialized CVE score column — write-time computation + invalidations.

The score lives on cve_host_packages/cve_containers (smallint) and is
maintained by api/app/utils/scoring.py. These tests assert directly in
PG (asyncpg) because the /cves API response is TTL-cached at module
level and would serve stale snapshots across test steps.

Score model (cve_score): cvss*5 + exploited(+25) + exposure(internet
+20 / private_network +10 / docker_internal +5) + fixed_available(+8),
not_affected forces 0.
"""

import asyncpg
import pytest

from tests.conftest import ASYNCPG_DSN

HOST_NODE = "score-host-node"
CTR_NODE = "score-ctr-node"
IMAGE = "scoreimg"


async def _seed_node(client, collect_auth, hostname):
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": hostname,
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["openssl\t3.0.11\tamd64"],
            "containers": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


async def _post_cve(client, collect_auth, hostname, cve_id, **kw):
    payload = {
        "hostname": hostname,
        "source": "trivy",
        "target_type": kw.get("target_type", "package"),
        "vulnerabilities": [
            {
                "VulnerabilityID": cve_id,
                "Severity": "HIGH",
                "PkgName": kw.get("pkg", "openssl"),
                "InstalledVersion": "3.0.11",
                "CVSS": {"nvd": {"V3Score": kw.get("cvss", 8.0)}},
            }
        ],
    }
    if kw.get("image"):
        payload["image"] = kw["image"]
    r = await client.post("/api/v1/cves/report", json=payload, headers=collect_auth)
    assert r.status_code == 200


async def _db_val(query, *args):
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        return await conn.fetchval(query, *args)
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_ingest_sets_host_score(client, collect_auth):
    """Ingest computes the stored score in the same transaction."""
    await _seed_node(client, collect_auth, HOST_NODE)
    await _post_cve(client, collect_auth, HOST_NODE, "CVE-2099-1001", cvss=8.0)
    score = await _db_val(
        "SELECT hp.score FROM cve_host_packages hp"
        " JOIN nodes n ON n.id = hp.node_id"
        " WHERE hp.cve_id = $1 AND n.hostname = $2",
        "CVE-2099-1001",
        HOST_NODE,
    )
    # 8.0*5 + private_network(10) = 50
    assert score == 50


@pytest.mark.anyio
async def test_view_serves_stored_score(client, collect_auth):
    """v_all_cves exposes the column, not a per-row computation."""
    await _seed_node(client, collect_auth, HOST_NODE)
    await _post_cve(client, collect_auth, HOST_NODE, "CVE-2099-1002", cvss=8.0)
    score = await _db_val(
        "SELECT score FROM v_all_cves WHERE cve_id = $1", "CVE-2099-1002"
    )
    assert score == 50


@pytest.mark.anyio
async def test_kev_flip_rescores(client, collect_auth):
    """OpenCVE KEV propagation re-scores existing findings (+25)."""
    await _seed_node(client, collect_auth, HOST_NODE)
    await _post_cve(client, collect_auth, HOST_NODE, "CVE-2099-1003", cvss=8.0)
    r = await client.post(
        "/api/v1/opencve/webhook",
        json={
            "cve_id": "CVE-2099-1003",
            "vendor": "openssl",
            "product": "openssl",
            "title": "KEV flip",
            "severity": "high",
            "kev": True,
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    score = await _db_val(
        "SELECT hp.score FROM cve_host_packages hp"
        " JOIN nodes n ON n.id = hp.node_id"
        " WHERE hp.cve_id = $1 AND n.hostname = $2",
        "CVE-2099-1003",
        HOST_NODE,
    )
    # 50 + exploited(25) = 75
    assert score == 75


@pytest.mark.anyio
async def test_fix_status_patch_rescores(client, auth, collect_auth):
    """PATCH fix_status=not_affected forces the stored score to 0."""
    await _seed_node(client, collect_auth, HOST_NODE)
    await _post_cve(client, collect_auth, HOST_NODE, "CVE-2099-1004", cvss=8.0)
    finding_id = await _db_val(
        "SELECT hp.id FROM cve_host_packages hp"
        " JOIN nodes n ON n.id = hp.node_id"
        " WHERE hp.cve_id = $1 AND n.hostname = $2",
        "CVE-2099-1004",
        HOST_NODE,
    )
    r = await client.patch(
        f"/api/v1/findings/host/{finding_id}",
        json={"fix_status": "not_affected"},
        headers=auth,
    )
    assert r.status_code == 200
    score = await _db_val(
        "SELECT score FROM cve_host_packages WHERE id = $1", finding_id
    )
    assert score == 0


@pytest.mark.anyio
async def test_container_score_matches_registry_port_image(client, collect_auth):
    """A registry-with-port image must match its repositories.listen for scoring.

    Regression: SPLIT_PART(image, ':', 1) split at the registry port colon, so
    'reg.local:5000/team/app:1.0' never matched image_name
    'reg.local:5000/team/app' (last-colon strip) and the container silently
    fell back to docker_internal (+5) instead of its real internet (+20).
    """
    node = "score-port-node"
    img_name = "reg.local:5000/team/app"
    await _seed_node(client, collect_auth, node)
    r = await client.post(
        "/api/v1/repositories/report",
        json={
            "hostname": node,
            "images": [
                {"image_name": img_name, "current_tag": "1.0", "listen": "internet"}
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    await _post_cve(
        client,
        collect_auth,
        node,
        "CVE-2099-PORT1",
        cvss=8.0,
        target_type="container",
        image=f"{img_name}:1.0",
    )
    score = await _db_val(
        "SELECT cc.score FROM cve_containers cc"
        " JOIN nodes n ON n.id = cc.node_id"
        " WHERE cc.cve_id = $1 AND n.hostname = $2",
        "CVE-2099-PORT1",
        node,
    )
    # 8.0*5 + internet(20) = 60 — pre-fix the port colon broke the match → 45.
    assert score == 60


@pytest.mark.anyio
async def test_container_score_follows_repo_listen(client, auth, collect_auth):
    """Container score uses repositories.listen and follows its changes."""
    await _seed_node(client, collect_auth, CTR_NODE)
    r = await client.post(
        "/api/v1/repositories/report",
        json={
            "hostname": CTR_NODE,
            "images": [
                {"image_name": IMAGE, "current_tag": "1.0", "listen": "internet"}
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    await _post_cve(
        client,
        collect_auth,
        CTR_NODE,
        "CVE-2099-1005",
        cvss=8.0,
        target_type="container",
        image=f"{IMAGE}:1.0",
    )
    score = await _db_val(
        "SELECT cc.score FROM cve_containers cc"
        " JOIN nodes n ON n.id = cc.node_id"
        " WHERE cc.cve_id = $1 AND n.hostname = $2",
        "CVE-2099-1005",
        CTR_NODE,
    )
    # 8.0*5 + internet(20) = 60
    assert score == 60

    repo_id = await _db_val(
        "SELECT r.id FROM repositories r JOIN nodes n ON n.id = r.node_id"
        " WHERE r.image_name = $1 AND n.hostname = $2",
        IMAGE,
        CTR_NODE,
    )
    r = await client.patch(
        f"/api/v1/repositories/{repo_id}",
        json={"listen": "docker_internal"},
        headers=auth,
    )
    assert r.status_code == 200
    score = await _db_val(
        "SELECT score FROM cve_containers WHERE cve_id = $1", "CVE-2099-1005"
    )
    # 8.0*5 + docker_internal(5) = 45
    assert score == 45
