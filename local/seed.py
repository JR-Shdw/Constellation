#!/usr/bin/env python3
"""Seed the local iso-prod CMDB with enough data to mimic prod load.

Run AFTER the stack is up and /api/v1/health returns 200:

    python local/seed.py

Inserts (via API + direct PG):
  - 10 nodes (mix of types)
  - 500 packages
  - 50 vulnerable host CVEs
  - 5 scheduler jobs of type 'http_request' hitting /api/v1/health
    every minute, to keep the scheduler tick busy
"""

import os
import sys
import time
import uuid

import httpx

API = os.environ.get("CMDB_API", "http://127.0.0.1:8000")
TOKEN = os.environ.get(
    "API_SECRET_KEY",
    "local_secret_key_for_iso_prod_testing_only_change_me_if_needed",
)
COLLECT = os.environ.get(
    "COLLECT_TOKEN",
    "local_collect_token_iso_prod_testing_only_change_me_if_needed",
)


def wait_for_api():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{API}/api/v1/health", timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(1)
    print("API never came up", file=sys.stderr)
    sys.exit(1)


def post_collect(path, payload):
    r = httpx.post(
        f"{API}/api/v1/{path}",
        json=payload,
        headers={"Authorization": f"Bearer {COLLECT}"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def post_admin(path, payload):
    r = httpx.post(
        f"{API}/api/v1/{path}",
        json=payload,
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def seed_nodes():
    print("Seeding 10 nodes + packages...")
    for i in range(10):
        hostname = f"local-node-{i:02d}"
        packages = [
            {"name": f"pkg-{j:03d}", "version": f"1.{j}.0", "manager": "apt"}
            for j in range(50)
        ]
        post_collect(
            "nodes/report",
            {
                "hostname": hostname,
                "node_type": "vm",
                "os_family": "debian",
                "os_version": "12",
                "architecture": "x86_64",
                "environment": "lab",
                "ip_address": f"10.99.0.{i + 10}",
                "is_active": True,
                "packages": packages,
                "containers": [],
            },
        )
    print("  done.")


def seed_cves():
    print("Seeding host CVEs...")
    cves = []
    for i in range(50):
        cves.append(
            {
                "node_hostname": f"local-node-{i % 10:02d}",
                "package_name": f"pkg-{i:03d}",
                "package_version": f"1.{i}.0",
                "cve_id": f"CVE-2025-{1000 + i}",
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "cvss_score": 7.5,
                "fix_status": "fix_available",
                "source": "trivy",
            }
        )
    post_collect("cves/report", {"reports": cves})
    print(f"  inserted {len(cves)} CVE rows")


def seed_scheduler_jobs():
    print("Seeding 5 scheduler jobs (cron */1 → /api/v1/health)...")
    for i in range(5):
        payload = {
            "name": f"local-stress-job-{i}",
            "job_type": "http_request",
            "cron_expr": f"*/1 * * * *",
            "config": {
                "method": "GET",
                "url": "/api/v1/health",
                "expected_status": [200],
            },
            "enabled": True,
            "timeout_secs": 30,
        }
        try:
            post_admin("scheduler/jobs", payload)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409:
                print(f"  job {payload['name']} already exists")
            else:
                raise
    print("  done.")


if __name__ == "__main__":
    wait_for_api()
    seed_nodes()
    seed_cves()
    seed_scheduler_jobs()
    print("\nSeed complete. Now run: python local/stress.py")
