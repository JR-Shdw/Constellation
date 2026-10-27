#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Initial full import OpenCVE v2 → CMDB.

Unlike sync_opencve.py (incremental, last N hours, max 2000),
this script imports CVEs from OpenCVE with configurable filters.

Features:
  - Severity filter: --min-severity critical|high|medium|low
  - Time window: --hours 740 (last 30 days), 0 = no limit
  - CVE limit: --limit 100000 (max CVEs to fetch)
  - Resume: --resume (skip already-imported CVE IDs)
  - Concurrent detail fetching (thread pool)
  - Progress reporting every 10 pages

Usage:
    # Full import, no filter
    sync_opencve_full.py

    # Critical only, last 60 days
    sync_opencve_full.py --min-severity critical --hours 1440

    # High+critical, last 30 days, max 50k CVEs
    sync_opencve_full.py --min-severity high --hours 740 --limit 50000

    # Resume after interruption
    sync_opencve_full.py --resume

    # Test run: 100 CVEs max
    sync_opencve_full.py --limit 100

Environment:
    OPENCVE_URL        — OpenCVE base URL (default: http://172.20.0.26:8000)
    OPENCVE_USER       — OpenCVE API username
    OPENCVE_PASSWORD   — OpenCVE API password
    CMDB_API           — CMDB API URL (default: http://api:8000)
    CMDB_COLLECT_TOKEN — CMDB Bearer token
"""

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import requests

OPENCVE_URL = os.environ.get("OPENCVE_URL", "http://172.20.0.26:8000")
OPENCVE_USER = os.environ.get("OPENCVE_USER", "")
OPENCVE_PASSWORD = os.environ.get("OPENCVE_PASSWORD", "")
CMDB_API = os.environ.get("CMDB_API", "http://api:8000")
CMDB_TOKEN = os.environ.get("CMDB_COLLECT_TOKEN", "")
# Ingestion CMDB peut etre longue sur un gros batch.
CMDB_INGEST_TIMEOUT = int(os.environ.get("CMDB_INGEST_TIMEOUT", "1200"))

SESSION = requests.Session()
SESSION.auth = (OPENCVE_USER, OPENCVE_PASSWORD)
SESSION.timeout = 30

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _extract_cvss(metrics: dict) -> float | None:
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        entry = metrics.get(key, {})
        if isinstance(entry, dict):
            data = entry.get("data", {})
            if isinstance(data, dict) and "score" in data:
                return float(data["score"])
    return None


def get_existing_cve_ids() -> set[str]:
    """Fetch already-imported CVE IDs from CMDB to support resume."""
    ids = set()
    page = 1
    while True:
        r = requests.get(
            f"{CMDB_API}/api/v1/opencve/alerts",
            headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
            params={"page": page, "per_page": 200},
            timeout=CMDB_INGEST_TIMEOUT,
        )
        if r.status_code != 200:
            break
        data = r.json()
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            ids.add(item.get("cve_id", ""))
        if page * 200 >= data.get("total", 0):
            break
        page += 1
    return ids


def get_cve_detail(cve_id: str) -> dict | None:
    """Fetch detail for a single CVE."""
    try:
        r = SESSION.get(f"{OPENCVE_URL}/api/cve/{cve_id}", timeout=30)
        if r.status_code == 200:
            return r.json()
        print(f"    detail {cve_id}: HTTP {r.status_code}", file=sys.stderr)
    except requests.RequestException as e:
        print(f"    detail {cve_id}: {e}", file=sys.stderr)
    return None


def enrich_cve(cve: dict) -> tuple[str, float | None, list[dict]]:
    """Fetch detail and expand into per-vendor/product alerts.

    Returns (severity, cvss, alerts) so caller can filter by severity.
    """
    cve_id = cve.get("cve_id", "")
    if not cve_id:
        return ("unknown", None, [])

    detail = get_cve_detail(cve_id)

    cvss_v3 = None
    severity = "unknown"
    vendors_dict = {}
    title = ""
    kev = False

    if detail:
        cvss_v3 = _extract_cvss(detail.get("metrics", {}))
        severity = _severity_from_cvss(cvss_v3)
        vendors_dict = detail.get("vendors", {})
        title = detail.get("title", "")
        kev = bool(detail.get("kev") or detail.get("cisaExploitAdd"))

    base = {
        "cve_id": cve_id,
        "title": (title or cve.get("description", ""))[:200],
        "description": cve.get("description", ""),
        "cvss_v3": cvss_v3,
        "severity": severity,
        "kev": kev,
        "updated_at": cve.get("updated_at", cve.get("created_at", "")),
    }

    alerts: list[dict] = []
    if isinstance(vendors_dict, dict) and vendors_dict:
        for vendor, products in vendors_dict.items():
            prod_list = products if isinstance(products, list) else [products]
            for product in prod_list:
                alerts.append({**base, "vendor": vendor, "product": product})
    elif isinstance(vendors_dict, list) and vendors_dict:
        for entry in vendors_dict:
            if not isinstance(entry, dict):
                continue
            vendor = (
                entry.get("vendor")
                or entry.get("name")
                or entry.get("vendor_name")
            )
            products = entry.get("products") or entry.get("product") or []
            if isinstance(products, str):
                products = [products]
            elif not isinstance(products, list):
                products = [str(products)] if products else []
            if products:
                for product in products:
                    alerts.append({**base, "vendor": vendor, "product": product})
            else:
                alerts.append({**base, "vendor": vendor, "product": None})
        if not alerts:
            alerts.append({**base, "vendor": None, "product": None})
    else:
        alerts.append({**base, "vendor": None, "product": None})

    return (severity, cvss_v3, alerts)


def push_to_cmdb(alerts: list[dict]) -> int:
    """Push alerts to CMDB API in batches of 500."""
    if not alerts:
        return 0
    total = 0
    for i in range(0, len(alerts), 500):
        batch = alerts[i: i + 500]
        try:
            r = requests.post(
                f"{CMDB_API}/api/v1/opencve/webhook/batch",
                headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
                json=batch,
                timeout=CMDB_INGEST_TIMEOUT,
            )
            if r.status_code == 200:
                total += r.json().get("imported", 0)
            else:
                print(
                    f"  CMDB push error: {r.status_code} {r.text[:200]}",
                    file=sys.stderr,
                )
        except requests.RequestException as e:
            print(f"  CMDB push error: {e}", file=sys.stderr)
    return total


def main():
    parser = argparse.ArgumentParser(
        description="Full import OpenCVE v2 → CMDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s                                        # all CVEs, no filter
  %(prog)s --min-severity critical                 # critical only
  %(prog)s --min-severity high --hours 1440        # high+ last 60 days
  %(prog)s --limit 50000 --resume                  # 50k max, skip existing
  %(prog)s --min-severity high --hours 740 --limit 100000""",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Minimum severity to import (e.g. high = high+critical)",
    )
    parser.add_argument(
        "--hours", type=int, default=0,
        help="Time window in hours (0 = no limit, 740 ~30d, 1480 ~60d)",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Max CVEs to import (0 = unlimited)",
    )
    parser.add_argument(
        "--workers", type=int, default=4,
        help="Parallel detail fetch threads (default: 4)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip CVE IDs already in CMDB",
    )
    parser.add_argument(
        "--batch-push", type=int, default=200,
        help="Push to CMDB every N CVEs (default: 200)",
    )
    args = parser.parse_args()

    if not OPENCVE_USER or not OPENCVE_PASSWORD:
        print("OPENCVE_USER and OPENCVE_PASSWORD required", file=sys.stderr)
        sys.exit(1)

    min_rank = SEVERITY_RANK.get(args.min_severity, 0) if args.min_severity else 0
    since = None
    if args.hours > 0:
        since = datetime.now(timezone.utc) - timedelta(hours=args.hours)

    # Resume: load existing IDs
    existing = set()
    if args.resume:
        print("Loading existing CVE IDs from CMDB...")
        existing = get_existing_cve_ids()
        print(f"  {len(existing)} CVEs already imported, will skip them")

    # Print config
    filters = []
    if args.min_severity:
        filters.append(f"severity >= {args.min_severity}")
    if since:
        filters.append(f"last {args.hours}h (since {since.strftime('%Y-%m-%d %H:%M')})")
    if args.limit:
        filters.append(f"limit {args.limit}")
    if args.resume:
        filters.append("resume")
    filter_str = ", ".join(filters) if filters else "none"

    ts = datetime.now().isoformat()
    print(
        f"[{ts}] Starting OpenCVE import "
        f"(workers={args.workers}, filters: {filter_str})"
    )

    page = 1
    total_fetched = 0
    total_pushed = 0
    total_skipped = 0
    total_filtered = 0
    pending_alerts = []
    start = time.time()

    while True:
        # Check CVE limit
        if args.limit and total_fetched >= args.limit:
            print(f"  Reached CVE limit ({args.limit})")
            break

        r = SESSION.get(f"{OPENCVE_URL}/api/cve", params={"page": page})
        if r.status_code != 200:
            print(f"  OpenCVE API error page {page}: {r.status_code}", file=sys.stderr)
            break

        data = r.json()
        results = data.get("results", []) if isinstance(data, dict) else data
        if not results:
            break

        # Time filter: check if we've gone past the window
        time_stop = False
        to_enrich = []
        for cve in results:
            cve_id = cve.get("cve_id", "")

            # Time filter
            if since:
                updated = cve.get("updated_at", cve.get("created_at", ""))
                if updated:
                    try:
                        dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                        if dt < since:
                            time_stop = True
                            break
                    except (ValueError, TypeError):
                        pass

            # Skip already-imported
            if cve_id in existing:
                total_skipped += 1
                continue

            to_enrich.append(cve)

        # Parallel detail fetch + severity filter
        if to_enrich:
            remaining = args.limit - total_fetched if args.limit else len(to_enrich)
            batch = to_enrich[:remaining]

            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {
                    pool.submit(enrich_cve, cve): cve for cve in batch
                }
                for future in as_completed(futures):
                    try:
                        severity, cvss, alerts = future.result()

                        # Severity filter (applied after detail fetch)
                        if min_rank and SEVERITY_RANK.get(severity, 0) < min_rank:
                            total_filtered += 1
                            continue

                        pending_alerts.extend(alerts)
                        total_fetched += 1
                    except Exception as e:
                        cve = futures[future]
                        print(
                            f"    Error enriching {cve.get('cve_id')}: {e}",
                            file=sys.stderr,
                        )

        # Push batch to CMDB periodically
        if len(pending_alerts) >= args.batch_push:
            pushed = push_to_cmdb(pending_alerts)
            total_pushed += pushed
            pending_alerts = []

        # Progress
        if page % 10 == 0:
            elapsed = time.time() - start
            rate = total_fetched / elapsed * 60 if elapsed > 0 else 0
            print(
                f"  page {page} | fetched {total_fetched} | "
                f"pushed {total_pushed} | skipped {total_skipped} | "
                f"filtered {total_filtered} | {rate:.0f} CVE/min"
            )

        if time_stop:
            print(f"  Reached time window boundary ({args.hours}h)")
            break

        # No next page?
        if isinstance(data, dict) and not data.get("next"):
            break

        page += 1

    # Push remaining
    if pending_alerts:
        pushed = push_to_cmdb(pending_alerts)
        total_pushed += pushed

    elapsed = time.time() - start
    print(
        f"\nDone in {elapsed:.0f}s | "
        f"pages: {page} | fetched: {total_fetched} | "
        f"pushed: {total_pushed} | skipped: {total_skipped} | "
        f"filtered: {total_filtered}"
    )


if __name__ == "__main__":
    main()
