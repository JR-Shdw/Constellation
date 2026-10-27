"""Performance bench at 1000-node scale (CI-gated by RUN_BENCH=1).

Seeds a realistic dataset (1k nodes, 50k packages, 5k containers, ~30k CVE
rows) directly via asyncpg COPY, then hits the real HTTP endpoints through
the ASGI client and measures latency (min / median / p95 over 5 runs).

Why a test rather than a standalone script: same fixtures, same PG service,
same lint/coverage pipeline. Gated by env flag so the regular `make test`
stays fast — runs only in the weekly `.woodpecker/bench.yml` cron.

Run locally:
    RUN_BENCH=1 pytest tests/test_bench_1k_nodes.py -s --timeout=600
"""

import os
import random
import statistics
import time
import uuid

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient

from .conftest import ASYNCPG_DSN, _ensure_schema, _truncate_all

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_BENCH"),
    reason="bench gated by RUN_BENCH=1 (weekly Woodpecker cron)",
)

N_NODES = 1000
PKGS_PER_NODE = 50
CONTAINERS_PER_NODE = 5
CVES_HOST_PER_NODE = 20
CVES_CONTAINER_PER_NODE = 10
UNIQUE_PACKAGES = 500  # must be >= PKGS_PER_NODE for random.sample()
UNIQUE_IMAGES = 5
UNIQUE_CVES = 200

BENCH_RUNS = 5

BUDGET_MS = {
    "GET /stats": 3000,
    "GET /cves?severity=critical&per_page=50": 2500,
    "GET /nodes?per_page=50": 1500,
    "GET /exposure": 1500,
    "GET /compliance": 2500,
}

_SEVERITIES = ["critical", "high", "medium", "low"]
_SEV_WEIGHTS = [0.10, 0.25, 0.40, 0.25]
_ENVS = ["production", "staging", "development", "lab"]
_ENV_WEIGHTS = [0.60, 0.20, 0.15, 0.05]
_EXPOSURES = [
    "internet",
    "vpn",
    "private",
    "docker_internal",
    "localhost",
    "unknown",
]


async def _seed_bench_dataset() -> None:
    """Bulk-seed the bench dataset via asyncpg COPY."""
    random.seed(42)
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        # Nodes
        node_ids = [uuid.uuid4() for _ in range(N_NODES)]
        nodes = [
            (
                nid,
                f"bench-{i:04d}",
                "vm",
                "debian",
                "12",
                "amd64",
                random.choices(_ENVS, _ENV_WEIGHTS)[0],
                True,
            )
            for i, nid in enumerate(node_ids)
        ]
        await conn.copy_records_to_table(
            "nodes",
            records=nodes,
            columns=[
                "id",
                "hostname",
                "type",
                "os",
                "os_version",
                "arch",
                "environment",
                "is_active",
            ],
        )

        # Package catalog
        pkg_ids = [uuid.uuid4() for _ in range(UNIQUE_PACKAGES)]
        pkg_catalog = [
            (pid, f"pkg-{i:02d}", f"1.{i}.{random.randint(0, 99)}", "apt")
            for i, pid in enumerate(pkg_ids)
        ]
        await conn.copy_records_to_table(
            "package_catalog",
            records=pkg_catalog,
            columns=["id", "name", "version", "manager"],
        )

        # Packages per node
        packages = []
        seen = set()
        for nid in node_ids:
            chosen = random.sample(pkg_ids, PKGS_PER_NODE)
            for pid in chosen:
                key = (nid, pid)
                if key in seen:
                    continue
                seen.add(key)
                packages.append((uuid.uuid4(), nid, pid))
        await conn.copy_records_to_table(
            "packages",
            records=packages,
            columns=["id", "node_id", "package_id"],
        )

        # Container images
        img_ids = [uuid.uuid4() for _ in range(UNIQUE_IMAGES)]
        images = [(iid, f"img-{i}", f"v{i}.0") for i, iid in enumerate(img_ids)]
        await conn.copy_records_to_table(
            "container_images",
            records=images,
            columns=["id", "image", "tag"],
        )

        # Containers per node
        containers = []
        ctr_ids = []
        for nid in node_ids:
            for j in range(CONTAINERS_PER_NODE):
                cid = uuid.uuid4()
                ctr_ids.append((cid, nid))
                containers.append(
                    (
                        cid,
                        nid,
                        random.choice(img_ids),
                        f"ctr-{j}",
                        "running",
                        random.choice(_EXPOSURES),
                    )
                )
        await conn.copy_records_to_table(
            "containers",
            records=containers,
            columns=["id", "node_id", "image_id", "name", "status", "exposure"],
        )

        # CVE catalog
        cve_ids = [f"CVE-2024-{90000 + i:05d}" for i in range(UNIQUE_CVES)]
        cve_cat = [
            (
                c,
                round(random.uniform(3.0, 9.9), 1),
                "bench CVE",
                random.random() < 0.15,  # exploited
                "unclear",
                random.random() < 0.10,  # kev
            )
            for c in cve_ids
        ]
        await conn.copy_records_to_table(
            "cve_catalog",
            records=cve_cat,
            columns=[
                "cve_id",
                "cvss_score",
                "description",
                "exploited",
                "exploitability_context",
                "kev",
            ],
        )

        # cve_host_packages — pre-dedup (node,cve,pkg_name)
        host_cves = []
        seen_hp: set[tuple] = set()
        pkg_name_by_id = {pid: f"pkg-{i:02d}" for i, pid in enumerate(pkg_ids)}
        for nid in node_ids:
            for _ in range(CVES_HOST_PER_NODE):
                cve = random.choice(cve_ids)
                pkg = random.choice(list(pkg_name_by_id.values()))
                key = (nid, cve, pkg)
                if key in seen_hp:
                    continue
                seen_hp.add(key)
                host_cves.append(
                    (
                        uuid.uuid4(),
                        nid,
                        cve,
                        random.choices(_SEVERITIES, _SEV_WEIGHTS)[0],
                        pkg,
                        "1.0.0",
                        "unfixed",
                        "open",
                        "trivy",
                    )
                )
        await conn.copy_records_to_table(
            "cve_host_packages",
            records=host_cves,
            columns=[
                "id",
                "node_id",
                "cve_id",
                "severity",
                "pkg_name",
                "installed_ver",
                "fix_status",
                "status",
                "source",
            ],
        )

        # cve_containers — unique on (node,cve,pkg_name,container)
        ctr_cves = []
        seen_cc: set[tuple] = set()
        for cid, nid in ctr_ids:
            for _ in range(CVES_CONTAINER_PER_NODE // CONTAINERS_PER_NODE + 1):
                cve = random.choice(cve_ids)
                pkg = f"lib-{random.randint(0, 29)}"
                key = (nid, cve, pkg, cid)
                if key in seen_cc:
                    continue
                seen_cc.add(key)
                ctr_cves.append(
                    (
                        uuid.uuid4(),
                        cid,
                        nid,
                        cve,
                        random.choices(_SEVERITIES, _SEV_WEIGHTS)[0],
                        pkg,
                        "1.0.0",
                        "unfixed",
                        "open",
                    )
                )
        await conn.copy_records_to_table(
            "cve_containers",
            records=ctr_cves,
            columns=[
                "id",
                "container_id",
                "node_id",
                "cve_id",
                "severity",
                "pkg_name",
                "installed_ver",
                "fix_status",
                "status",
            ],
        )

        # ANALYZE so the planner has stats for the bench queries
        await conn.execute("ANALYZE")
    finally:
        await conn.close()


def _fmt_ms(v: float) -> str:
    return f"{v * 1000:7.1f}ms"


async def _measure(
    client: AsyncClient, method: str, path: str, headers: dict
) -> list[float]:
    durations: list[float] = []
    for _ in range(BENCH_RUNS):
        t0 = time.perf_counter()
        r = await client.request(method, path, headers=headers)
        elapsed = time.perf_counter() - t0
        assert r.status_code == 200, f"{method} {path}: HTTP {r.status_code}"
        durations.append(elapsed)
    return durations


@pytest.mark.asyncio
async def test_bench_1k_nodes_views(capsys):
    """Seed 1k-node dataset and bench 5 hot endpoints."""
    await _ensure_schema()
    await _truncate_all()

    t0 = time.perf_counter()
    await _seed_bench_dataset()
    seed_elapsed = time.perf_counter() - t0

    # Defer the FastAPI import until after schema is applied.
    from api.app.main import app

    auth = {"Authorization": "Bearer test-secret-key"}
    transport = ASGITransport(app=app)

    with capsys.disabled():
        print(f"\n[bench] seed done in {seed_elapsed:.1f}s")
        print(
            f"[bench] dataset: {N_NODES} nodes, "
            f"{N_NODES * PKGS_PER_NODE} packages, "
            f"{N_NODES * CONTAINERS_PER_NODE} containers"
        )
        print(f"[bench] runs per endpoint: {BENCH_RUNS}")
        print()
        print(f"{'endpoint':<55}  {'min':>9}  {'med':>9}  {'p95':>9}  {'budget':>9}")
        print("-" * 100)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Warm once per endpoint (fill backend caches) — not counted.
            for path in (
                "/api/v1/stats",
                "/api/v1/cves?severity=critical&per_page=50",
                "/api/v1/nodes?per_page=50",
                "/api/v1/exposure",
                "/api/v1/compliance",
            ):
                await client.get(path, headers=auth)

            targets = [
                ("GET /stats", "GET", "/api/v1/stats"),
                (
                    "GET /cves?severity=critical&per_page=50",
                    "GET",
                    "/api/v1/cves?severity=critical&per_page=50",
                ),
                ("GET /nodes?per_page=50", "GET", "/api/v1/nodes?per_page=50"),
                ("GET /exposure", "GET", "/api/v1/exposure"),
                ("GET /compliance", "GET", "/api/v1/compliance"),
            ]

            failures: list[str] = []
            for label, method, path in targets:
                samples = await _measure(client, method, path, auth)
                smin = min(samples)
                smed = statistics.median(samples)
                # With 5 samples, p95 ≈ max (honest reporting, no fake smoothing).
                sp95 = max(samples)
                budget = BUDGET_MS[label]
                verdict = "OK" if sp95 * 1000 <= budget else "FAIL"
                print(
                    f"{label:<55}  {_fmt_ms(smin)}  {_fmt_ms(smed)}"
                    f"  {_fmt_ms(sp95)}  {budget:>6}ms  {verdict}"
                )
                if sp95 * 1000 > budget:
                    failures.append(
                        f"{label}: p95={sp95 * 1000:.0f}ms > budget {budget}ms"
                    )

            print()

    assert not failures, "Bench budget breached:\n  " + "\n  ".join(failures)
