"""Concurrent ingestion bench — iso-prod load on /collect endpoints.

Spawns uvicorn with 4 workers (production parity), then fires concurrent
clients via asyncio.gather to exercise pool contention, advisory locks
and lateral concurrency across workers. Splits the ingestion volume /4
to match the worker count (per feedback_bench_concurrency_protocol).

Why a dedicated bench: the existing test_bench_*.py files use
ASGITransport in-process — useful for latency budgets but they bypass
the worker pool entirely. This file is the ground truth for "does the
collect path scale across workers".

Gated by RUN_BENCH=1 (weekly Woodpecker cron). Run locally:
    RUN_BENCH=1 pytest tests/test_bench_concurrent_ingest.py -s --timeout=600
"""

import asyncio
import os
import random
import socket
import statistics
import subprocess
import sys
import time
import uuid

import asyncpg
import httpx
import pytest

from .conftest import ASYNCPG_DSN, _ensure_schema, _truncate_all

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_BENCH"),
    reason="bench gated by RUN_BENCH=1 (weekly Woodpecker cron)",
)

WORKERS = 4
N_NODES = 200            # hosts that send reports
TOTAL_BACKUP_CALLS = 400  # split /WORKERS across concurrent clients
TOTAL_PIPELINE_BATCHES = 80
PIPELINES_PER_BATCH = 50

# Throughput budgets (req/s aggregate across all concurrent clients).
# A regression here means worker contention or DB pool starvation.
BUDGET_RPS = {
    "POST /backup/report": 80,
    "POST /cicd/pipelines/report (batch=50)": 30,
}


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_health(base_url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=2) as client:
        while time.monotonic() < deadline:
            try:
                r = await client.get(f"{base_url}/api/v1/health")
                if r.status_code == 200:
                    return
            except httpx.TransportError:
                pass
            await asyncio.sleep(0.3)
    raise RuntimeError(f"uvicorn not ready at {base_url} after {timeout}s")


async def _seed_nodes() -> list[str]:
    random.seed(45)
    conn = await asyncpg.connect(ASYNCPG_DSN)
    try:
        node_ids = [uuid.uuid4() for _ in range(N_NODES)]
        nodes = [
            (nid, f"bench-cc-{i:03d}", "vm", "debian", "12", "amd64",
             "production", True)
            for i, nid in enumerate(node_ids)
        ]
        await conn.copy_records_to_table(
            "nodes",
            records=nodes,
            columns=["id", "hostname", "type", "os", "os_version", "arch",
                     "environment", "is_active"],
        )
        await conn.execute("ANALYZE")
        return [f"bench-cc-{i:03d}" for i in range(N_NODES)]
    finally:
        await conn.close()


def _backup_payload(hostname: str) -> dict:
    return {
        "hostname": hostname,
        "repo_name": "default",
        "repo_path": "/backup/restic",
        "sftp_host": "backup.internal",
        "sftp_user": "restic",
        "status": "ok",
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
    return {
        "ci_system": "woodpecker",
        "repo_name": repo,
        "number": number,
        "status": "success",
        "event": "push",
        "branch": "main",
        "commit_sha": uuid.uuid4().hex[:40],
        "commit_message": f"bench {number}",
        "author": "bench",
        "duration_secs": 60,
        "link": f"https://ci.example/runs/{number}",
        "raw": {"bench": True},
    }


async def _client_worker(
    base_url: str,
    headers: dict,
    path: str,
    payload_factory,
    n_calls: int,
) -> list[float]:
    """One concurrent client: fires n_calls POSTs sequentially, returns latencies."""
    durations: list[float] = []
    async with httpx.AsyncClient(base_url=base_url, timeout=30) as client:
        for _ in range(n_calls):
            body = payload_factory()
            t0 = time.perf_counter()
            r = await client.post(path, json=body, headers=headers)
            durations.append(time.perf_counter() - t0)
            assert r.status_code == 200, f"POST {path}: HTTP {r.status_code}"
    return durations


def _spawn_uvicorn(port: int) -> subprocess.Popen:
    env = os.environ.copy()
    env["UVICORN_WORKERS"] = str(WORKERS)
    return subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "api.app.main:app",
            "--host", "127.0.0.1", "--port", str(port),
            "--workers", str(WORKERS),
            "--log-level", "warning",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.mark.asyncio
async def test_bench_concurrent_ingestion(capsys):
    """Iso-prod ingestion bench: uvicorn 4 workers + 4 concurrent clients."""
    await _ensure_schema()
    await _truncate_all()
    hostnames = await _seed_nodes()

    port = _pick_free_port()
    base_url = f"http://127.0.0.1:{port}"
    proc = _spawn_uvicorn(port)
    try:
        await _wait_health(base_url)

        collect = {"Authorization": "Bearer test-collect-token"}

        # POST /backup/report — 4 concurrent clients × 100 calls each = 400
        per_client = TOTAL_BACKUP_CALLS // WORKERS
        t0 = time.perf_counter()
        results = await asyncio.gather(*[
            _client_worker(
                base_url, collect, "/api/v1/backup/report",
                lambda: _backup_payload(random.choice(hostnames)),
                per_client,
            )
            for _ in range(WORKERS)
        ])
        backup_total = time.perf_counter() - t0
        backup_durations = [d for r in results for d in r]
        backup_rps = TOTAL_BACKUP_CALLS / backup_total
        backup_p95 = statistics.quantiles(backup_durations, n=20)[18]

        # POST /cicd/pipelines/report — 4 concurrent × 20 batches each = 80
        repos = [f"bench/cc-{chr(ord('a') + i)}" for i in range(10)]
        counter = [10000]

        def _batch_factory():
            runs = []
            for _ in range(PIPELINES_PER_BATCH):
                counter[0] += 1
                runs.append(_pipeline_run(random.choice(repos), counter[0]))
            return runs

        per_client = TOTAL_PIPELINE_BATCHES // WORKERS
        t0 = time.perf_counter()
        results = await asyncio.gather(*[
            _client_worker(
                base_url, collect, "/api/v1/cicd/pipelines/report",
                _batch_factory, per_client,
            )
            for _ in range(WORKERS)
        ])
        pipeline_total = time.perf_counter() - t0
        pipeline_durations = [d for r in results for d in r]
        pipeline_rps = TOTAL_PIPELINE_BATCHES / pipeline_total
        pipeline_p95 = statistics.quantiles(pipeline_durations, n=20)[18]

        with capsys.disabled():
            print(f"\n[bench-cc] uvicorn workers: {WORKERS}, clients: {WORKERS}")
            print(f"[bench-cc] {'endpoint':<45}  {'rps':>8}  {'p95':>9}  {'budget':>10}")
            print("-" * 80)
            for label, rps, p95 in (
                ("POST /backup/report", backup_rps, backup_p95),
                ("POST /cicd/pipelines/report (batch=50)",
                 pipeline_rps, pipeline_p95),
            ):
                budget = BUDGET_RPS[label]
                verdict = "OK" if rps >= budget else "FAIL"
                print(f"  {label:<45}  {rps:>6.1f}/s  {p95 * 1000:>6.1f}ms"
                      f"  >= {budget}/s  {verdict}")

        failures = []
        if backup_rps < BUDGET_RPS["POST /backup/report"]:
            failures.append(
                f"backup rps={backup_rps:.1f} < budget {BUDGET_RPS['POST /backup/report']}"
            )
        if pipeline_rps < BUDGET_RPS["POST /cicd/pipelines/report (batch=50)"]:
            failures.append(
                f"pipeline rps={pipeline_rps:.1f} < budget "
                f"{BUDGET_RPS['POST /cicd/pipelines/report (batch=50)']}"
            )
        if failures:
            pytest.fail("Concurrent bench regressions:\n  " + "\n  ".join(failures))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
