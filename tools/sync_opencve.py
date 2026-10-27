#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Sync OpenCVE v2 alerts → CMDB API.

Polls the OpenCVE v2 API (Django REST Framework) for recent CVE alerts
and pushes them to the CMDB API for correlation with infrastructure assets.

OpenCVE v2 API differences from v1:
  - Pagination: DRF format {"count", "next", "previous", "results"}
  - Page size fixed at 10 (per_page param is ignored)
  - List endpoint only returns: cve_id, description, created_at, updated_at
  - Detail endpoint needed for: metrics (CVSS), vendors, weaknesses

Usage:
    # En cron toutes les heures
    sync_opencve.py

    # Forcer un sync complet (dernier jour)
    sync_opencve.py --hours 24

Environment:
    OPENCVE_URL       — OpenCVE base URL (default: http://172.20.0.26:8000)
    OPENCVE_USER      — OpenCVE API username
    OPENCVE_PASSWORD  — OpenCVE API password
    CMDB_API          — CMDB API URL (default: http://api:8000)
    CMDB_COLLECT_TOKEN — CMDB Bearer token
"""

import argparse
import os
import sys
import time
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


def _severity_from_cvss(score: float | None) -> str:
    """Derive severity from CVSS v3 score."""
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
    """Extract best CVSS v3 score from OpenCVE v2 metrics object.

    v2 format: {"cvssV3_1": {"data": {"score": 7.5, ...}}, ...}
    Fallback order: cvssV4_0 → cvssV3_1 → cvssV3_0 → cvssV2_0
    """
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        entry = metrics.get(key, {})
        if isinstance(entry, dict):
            data = entry.get("data", {})
            if isinstance(data, dict) and "score" in data:
                return float(data["score"])
    return None


def get_cve_detail(cve_id: str) -> dict | None:
    """Fetch detail for a single CVE (metrics, vendors, weaknesses)."""
    r = SESSION.get(f"{OPENCVE_URL}/api/cve/{cve_id}")
    if r.status_code != 200:
        print(f"    detail {cve_id}: HTTP {r.status_code}", file=sys.stderr)
        return None
    return r.json()


def get_opencve_alerts(since_hours: int = 6) -> list[dict]:
    """Fetch recent CVE alerts from OpenCVE v2 API with detail enrichment."""
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    alerts = []
    page = 1
    max_pages = 200  # v2 page size is 10, so 200 pages = 2000 CVEs max

    while page <= max_pages:
        r = SESSION.get(
            f"{OPENCVE_URL}/api/cve",
            params={"page": page},
        )
        if r.status_code != 200:
            print(f"OpenCVE API error: {r.status_code}", file=sys.stderr)
            break

        data = r.json()
        results = data.get("results", []) if isinstance(data, dict) else data

        if not results:
            break

        stop = False
        for cve in results:
            updated = cve.get("updated_at", cve.get("created_at", ""))
            if updated:
                try:
                    dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                    if dt < since:
                        stop = True
                        break
                except (ValueError, TypeError):
                    pass

            cve_id = cve.get("cve_id", "")
            if not cve_id:
                continue

            # Fetch detail to get CVSS, vendors, weaknesses
            detail = get_cve_detail(cve_id)
            time.sleep(0.1)  # rate limit

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
                # KEV: OpenCVE stores it as kev=true or via cisaExploitAdd date
                kev = bool(
                    detail.get("kev")
                    or detail.get("cisaExploitAdd")
                    or detail.get("exploitabilityScore") == 3.9
                    and detail.get("kev")
                )

            base = {
                "cve_id": cve_id,
                "title": title or cve.get("description", "")[:200],
                "description": cve.get("description", ""),
                "cvss_v3": cvss_v3,
                "severity": severity,
                "kev": kev,
                "updated_at": updated,
            }

            # One alert per vendor/product pair, or one generic if no vendors
            if vendors_dict:
                if isinstance(vendors_dict, dict):
                    for vendor, products in vendors_dict.items():
                        prod_list = (
                            products if isinstance(products, list) else [products]
                        )
                        for product in prod_list:
                            alerts.append(
                                {**base, "vendor": vendor, "product": product}
                            )

                elif isinstance(vendors_dict, list):
                    added = False
                    for entry in vendors_dict:
                        if not isinstance(entry, dict):
                            continue

                        vendor = (
                            entry.get("vendor")
                            or entry.get("name")
                            or entry.get("vendor_name")
                        )

                        products = (
                            entry.get("products")
                            or entry.get("product")
                            or entry.get("product_name")
                            or []
                        )

                        if isinstance(products, str):
                            products = [products]
                        elif not isinstance(products, list):
                            products = [str(products)] if products else []

                        if products:
                            for product in products:
                                alerts.append(
                                    {
                                        **base,
                                        "vendor": vendor,
                                        "product": product,
                                    }
                                )
                                added = True
                        else:
                            alerts.append({**base, "vendor": vendor, "product": None})
                            added = True

                    if not added:
                        alerts.append({**base, "vendor": None, "product": None})

                else:
                    alerts.append({**base, "vendor": None, "product": None})
            else:
                alerts.append({**base, "vendor": None, "product": None})

        if stop:
            break

        # Check if there's a next page
        if isinstance(data, dict) and not data.get("next"):
            break

        page += 1

    return alerts


def push_to_cmdb(alerts: list[dict]) -> int:
    """Push alerts to CMDB API (batch)."""
    if not alerts:
        return 0

    # Push in batches of 100
    total = 0
    for i in range(0, len(alerts), 100):
        batch = alerts[i : i + 100]
        r = requests.post(
            f"{CMDB_API}/api/v1/opencve/webhook/batch",
            headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
            json=batch,
            timeout=CMDB_INGEST_TIMEOUT,
        )
        if r.status_code == 200:
            total += r.json().get("imported", 0)
        else:
            print(f"CMDB API error: {r.status_code} {r.text}", file=sys.stderr)

    return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync OpenCVE v2 → CMDB")
    parser.add_argument(
        "--hours", type=int, default=6, help="Fetch CVEs from the last N hours"
    )
    args = parser.parse_args()

    if not OPENCVE_USER or not OPENCVE_PASSWORD:
        print("OPENCVE_USER and OPENCVE_PASSWORD required", file=sys.stderr)
        sys.exit(1)

    ts = datetime.now().isoformat()
    print(f"[{ts}] Fetching OpenCVE v2 alerts (last {args.hours}h)...")
    alerts = get_opencve_alerts(args.hours)
    print(f"  Found {len(alerts)} alerts")

    if alerts:
        imported = push_to_cmdb(alerts)
        print(f"  Pushed {imported} to CMDB")

    print("Done.")
