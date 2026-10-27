"""Write-path bench — POST /backup/report and /cicd/pipelines/report.

Measures ingestion latency on the two remaining collect endpoints that were
not covered by test_bench_1k_nodes.py (reads) nor by the nodes/report bench.

Both endpoints are fed by the daily sync scripts (restic-backup.sh for backup,
sync_woodpecker.py for pipelines). A regression here slows down the whole
collect cycle — so we bench them like we bench the hot read endpoints.

Gated by RUN_BENCH=1 (weekly Woodpecker cron). Run locally :
    RUN_BENCH=1 pytest tests/test_bench_backup_cicd.py -s --timeout=600
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

N_NODES = 50  # hosts that send backup reports
BACKUP_RUNS = 200  # total POST /backup/report calls
PIPELINE_BATCHES = 20  # POST /cicd/pipelines/report calls (batched)
PIPELINES_PER_BATCH = 50  # runs per payload list

BENCH_RUNS = 5

# p95 budget per call (ms). Single-row upserts — generous but not sloppy.
BUDGET_MS = {
    "POST /backup/report": 200,
    "POST /cicd/pipelines/report (batch=50)": 500,
}


async def _seed_nodes() -> list[str]:
    """Seed N_NODES for backup hostname resolution."""
    random.seed(44)
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_ids = [uuid.uuid4() for _ in range(N_NODES)]
        nodes = [
            (
                nid,
                f"bench-bak-{i:03d}",
                "vm",
                "debian",
                "12",
                "amd64",
                "production",
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
        await conn.execute("ANALYZE")
        return [f"bench-bak-{i:03d}" for i in range(N_NODES)]
    finally:
        await conn.close()


def _fmt_ms(v: float) -> str:
    return f"{v * 1000:7.1f}ms"


def _backup_payload(hostname: str) -> dict:
    return {
        "hostname": hostname,
        "repo_name": "default",
        "repo_path": "/backup/restic",
        "sftp_host": "backup.internal",
        "sftp_user": "restic",
        "status": random.choices(
            ["ok", "warning", "error"], weights=[0.85, 0.10, 0.05]
        )[0],
        "files_new": random.randint(0, 5000),
        "files_changed": random.randint(0, 2000),
        "files_unmodified": random.randint(10000, 500000),
        "size_added": random.randint(0, 10**9),
        "size_total": random.randint(10**9, 10**11),
        "snapshots_total": random.randint(1, 100),
        "duration_secs": random.randint(10, 3600),
        "source": "script",
        "raw": {"bench": True},
    }


def _pipeline_run(repo: str, number: int) -> dict:
    status = random.choices(
        ["success", "failure", "running", "pending"],
        weights=[0.75, 0.10, 0.10, 0.05],
    )[0]
    return {
        "ci_system": "woodpecker",
        "repo_name": repo,
        "number": number,
        "status": status,
        "event": random.choice(["push", "pull_request", "cron"]),
        "branch": random.choice(["main", "dev", "feat/x"]),
        "commit_sha": uuid.uuid4().hex[:40],
        "commit_message": f"bench commit #{number}",
        "author": f"user-{random.randint(0, 9)}",
        "duration_secs": random.randint(5, 900),
        "link": f"https://ci.example/runs/{number}",
        "raw": {"bench": True},
    }


async def _measure_post(
    client: AsyncClient,
    path: str,
    headers: dict,
    payload_factory,
    n_calls: int,
) -> list[float]:
    """Run n_calls POSTs sequentially, return per-call durations."""
    durations: list[float] = []
    for _ in range(n_calls):
        body = payload_factory()
        t0 = time.perf_counter()
        r = await client.post(path, json=body, headers=headers)
        elapsed = time.perf_counter() - t0
        assert r.status_code == 200, f"POST {path}: HTTP {r.status_code} {r.text[:200]}"
        durations.append(elapsed)
    return durations


@pytest.mark.asyncio
async def test_bench_backup_cicd_write_path(capsys):
    """Bench /backup/report + /cicd/pipelines/report ingestion."""
    random.seed(44)
    await _ensure_schema()
    await _truncate_all()

    hostnames = await _seed_nodes()

    from api.app.main import app

    collect = {"Authorization": "Bearer test-collect-token"}
    transport = ASGITransport(app=app)

    with capsys.disabled():
        print(f"\n[bench-write] seeded {len(hostnames)} nodes")
        print(
            f"[bench-write] backup runs: {BACKUP_RUNS}, "
            f"pipeline batches: {PIPELINE_BATCHES} × {PIPELINES_PER_BATCH}"
        )
        print(f"[bench-write] runs per endpoint: {BENCH_RUNS}")
        print()
        print(f"{'endpoint':<45}  {'min':>9}  {'med':>9}  {'p95':>9}  {'budget':>9}")
        print("-" * 95)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Warm once per endpoint — fill any caches, prime asyncpg pool.
            await client.post(
                "/api/v1/backup/report",
                json=_backup_payload(hostnames[0]),
                headers=collect,
            )
            await client.post(
                "/api/v1/cicd/pipelines/report",
                json=[_pipeline_run("bench/warm", 1)],
                headers=collect,
            )

            # POST /backup/report — single-row upsert per call.
            # Sample BENCH_RUNS windows of ~BACKUP_RUNS/BENCH_RUNS calls each
            # and aggregate per-call medians per window to get p95 across windows.
            per_window = max(1, BACKUP_RUNS // BENCH_RUNS)
            backup_window_medians: list[float] = []
            for _ in range(BENCH_RUNS):
                durations = await _measure_post(
                    client,
                    "/api/v1/backup/report",
                    collect,
                    lambda: _backup_payload(random.choice(hostnames)),
                    per_window,
                )
                backup_window_medians.append(statistics.median(durations))

            # POST /cicd/pipelines/report — batch upsert (50 rows per call).
            repos = [f"bench/{chr(ord('a') + i)}" for i in range(10)]
            pipeline_window_medians: list[float] = []
            counter = [100]  # shared counter across closure calls

            def _batch() -> list[dict]:
                runs = []
                for _ in range(PIPELINES_PER_BATCH):
                    counter[0] += 1
                    runs.append(_pipeline_run(random.choice(repos), counter[0]))
                return runs

            per_window = max(1, PIPELINE_BATCHES // BENCH_RUNS)
            for _ in range(BENCH_RUNS):
                durations = await _measure_post(
                    client,
                    "/api/v1/cicd/pipelines/report",
                    collect,
                    _batch,
                    per_window,
                )
                pipeline_window_medians.append(statistics.median(durations))

            failures: list[str] = []
            for label, samples in (
                ("POST /backup/report", backup_window_medians),
                ("POST /cicd/pipelines/report (batch=50)", pipeline_window_medians),
            ):
                smin = min(samples)
                smed = statistics.median(samples)
                sp95 = max(samples)  # honest p95 across BENCH_RUNS windows
                budget = BUDGET_MS[label]
                verdict = "OK" if sp95 * 1000 <= budget else "FAIL"
                print(
                    f"{label:<45}  {_fmt_ms(smin)}  {_fmt_ms(smed)}"
                    f"  {_fmt_ms(sp95)}  {budget:>6}ms  {verdict}"
                )
                if sp95 * 1000 > budget:
                    failures.append(
                        f"{label}: p95={sp95 * 1000:.0f}ms > budget {budget}ms"
                    )

            print()

    assert not failures, "Bench write-path budget breached:\n  " + "\n  ".join(failures)
