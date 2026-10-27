#!/usr/bin/env python3
"""Stress the local iso-prod CMDB to flush out the pool leak.

Hammers /stats, /stats/trends, /heartbeat/check, /heartbeat/status,
/cves, /deployments/stats and prints a /health/pool snapshot every
N seconds. Run alongside the scheduler ticking through the seeded
http_request jobs.

    python local/stress.py
"""

import asyncio
import os
import time

import httpx

API = os.environ.get("CMDB_API", "http://127.0.0.1:8000")
TOKEN = os.environ.get(
    "API_SECRET_KEY",
    "local_secret_key_for_iso_prod_testing_only_change_me_if_needed",
)
CONCURRENCY = int(os.environ.get("CONCURRENCY", "10"))
SNAPSHOT_INTERVAL = float(os.environ.get("SNAPSHOT_INTERVAL", "5"))

# Endpoints to hit — same shape as a dashboard refresh wave.
ENDPOINTS = [
    "/api/v1/stats",
    "/api/v1/stats/trends?days=30",
    "/api/v1/heartbeat/status",
    "/api/v1/heartbeat/trends?hours=24",
    "/api/v1/cves?page=1&per_page=50",
    "/api/v1/deployments/stats",
    "/api/v1/scan/status",
    "/api/v1/exposure",
    "/api/v1/compliance",
    "/api/v1/cicd/stats",
    "/api/v1/automation/policies",
    "/api/v1/scheduler/jobs",
]


async def hammer(client: httpx.AsyncClient, idx: int, counters: dict):
    while True:
        ep = ENDPOINTS[idx % len(ENDPOINTS)]
        idx += len(ENDPOINTS)
        t0 = time.monotonic()
        try:
            r = await client.get(
                f"{API}{ep}",
                headers={"Authorization": f"Bearer {TOKEN}"},
                timeout=15,
            )
            counters[r.status_code] = counters.get(r.status_code, 0) + 1
            counters["latency_sum"] += time.monotonic() - t0
            counters["latency_count"] += 1
        except Exception as e:
            kind = type(e).__name__
            counters[f"err:{kind}"] = counters.get(f"err:{kind}", 0) + 1
        await asyncio.sleep(0.1)


async def heartbeat_loop(client: httpx.AsyncClient, counters: dict):
    """Periodically POST /heartbeat/check — slowest endpoint, big leak risk."""
    while True:
        try:
            r = await client.post(
                f"{API}/api/v1/heartbeat/check",
                headers={"Authorization": f"Bearer {TOKEN}"},
                timeout=60,
            )
            counters[f"hb:{r.status_code}"] = (
                counters.get(f"hb:{r.status_code}", 0) + 1
            )
        except Exception as e:
            counters[f"hb:err:{type(e).__name__}"] = (
                counters.get(f"hb:err:{type(e).__name__}", 0) + 1
            )
        await asyncio.sleep(15)


async def snapshotter(client: httpx.AsyncClient, counters: dict):
    """Print pool snapshot + counters every SNAPSHOT_INTERVAL seconds."""
    started = time.monotonic()
    while True:
        await asyncio.sleep(SNAPSHOT_INTERVAL)
        try:
            r = await client.get(f"{API}/api/v1/health/pool", timeout=5)
            pool = r.json()
        except Exception as e:
            pool = {"error": str(e)}
        latency_avg = (
            counters["latency_sum"] / counters["latency_count"]
            if counters.get("latency_count")
            else 0
        )
        elapsed = int(time.monotonic() - started)
        print(
            f"[{elapsed:5d}s] pool={pool} "
            f"avg_lat={latency_avg * 1000:.0f}ms "
            f"counters={ {k: v for k, v in counters.items() if not k.startswith('latency')} }",
            flush=True,
        )


async def main():
    counters = {"latency_sum": 0.0, "latency_count": 0}
    timeout = httpx.Timeout(15.0, connect=5.0)
    limits = httpx.Limits(max_connections=CONCURRENCY * 2, max_keepalive_connections=CONCURRENCY)
    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        tasks = [
            asyncio.create_task(hammer(client, i, counters))
            for i in range(CONCURRENCY)
        ]
        tasks.append(asyncio.create_task(heartbeat_loop(client, counters)))
        tasks.append(asyncio.create_task(snapshotter(client, counters)))
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            for t in tasks:
                t.cancel()


if __name__ == "__main__":
    asyncio.run(main())
