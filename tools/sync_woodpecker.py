#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Sync Woodpecker CI + Gitea repos → CMDB API.

Polls the Woodpecker API for pipeline runs and the Gitea API for
repository metadata, then pushes everything to the CMDB CI/CD endpoints.

Usage:
    # Sync last 50 pipelines per repo (default)
    sync_woodpecker.py

    # Sync last 200 pipelines per repo
    sync_woodpecker.py --pipelines 200

    # Repos only (no pipelines)
    sync_woodpecker.py --repos-only

Environment:
    WOODPECKER_URL      — Woodpecker base URL (default: https://ci.example.com)
    WOODPECKER_TOKEN    — Woodpecker API token (personal access token)
    GITEA_URL           — Gitea base URL (default: https://gitea.example.com)
    GITEA_TOKEN         — Gitea API token
    CMDB_API            — CMDB API URL (default: http://api:8000)
    CMDB_COLLECT_TOKEN  — CMDB Bearer token
"""

import argparse
import os
import sys
from datetime import datetime, timezone

import requests

WOODPECKER_URL = os.environ.get("WOODPECKER_URL", "https://ci.example.com")
WOODPECKER_TOKEN = os.environ.get("WOODPECKER_TOKEN", "")
GITEA_URL = os.environ.get("GITEA_URL", "https://gitea.example.com")
GITEA_TOKEN = os.environ.get("GITEA_TOKEN", "")
CMDB_API = os.environ.get("CMDB_API", "http://api:8000")
CMDB_TOKEN = os.environ.get("CMDB_COLLECT_TOKEN", "")
# Ingestion CMDB peut etre longue sur un gros batch.
CMDB_INGEST_TIMEOUT = int(os.environ.get("CMDB_INGEST_TIMEOUT", "1200"))

WP_SESSION = requests.Session()
WP_SESSION.headers["Authorization"] = f"Bearer {WOODPECKER_TOKEN}"
WP_SESSION.timeout = 30

GT_SESSION = requests.Session()
GT_SESSION.headers["Authorization"] = f"token {GITEA_TOKEN}"
GT_SESSION.timeout = 30

# Woodpecker status codes → human-readable
_WP_STATUS = {
    "success": "success",
    "failure": "failure",
    "error": "error",
    "killed": "killed",
    "running": "running",
    "pending": "pending",
    "blocked": "blocked",
    "skipped": "skipped",
    "declined": "declined",
}


def _ts(epoch: int | None) -> str | None:
    """Convert Unix epoch to ISO8601 string."""
    if not epoch or epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


# Gitea


def _has_woodpecker_config(owner: str, repo: str) -> bool:
    """Check if a Gitea repo has .woodpecker/ dir."""
    r = GT_SESSION.get(
        f"{GITEA_URL}/api/v1/repos/{owner}/{repo}"
        f"/contents/.woodpecker",
    )
    return r.status_code == 200


def _get_branches(owner: str, repo: str) -> list[str]:
    """Fetch branch names from Gitea."""
    r = GT_SESSION.get(
        f"{GITEA_URL}/api/v1/repos/{owner}/{repo}/branches",
        params={"limit": 50},
    )
    if r.status_code != 200:
        return []
    return [b.get("name", "") for b in (r.json() or [])]


def fetch_gitea_repos() -> list[dict]:
    """Fetch all repos from Gitea API with CI/CD detection."""
    repos = []
    page = 1
    while True:
        r = GT_SESSION.get(
            f"{GITEA_URL}/api/v1/repos/search",
            params={"page": page, "limit": 50},
        )
        if r.status_code != 200:
            print(
                f"Gitea API error: {r.status_code}",
                file=sys.stderr,
            )
            break
        data = r.json().get("data", [])
        if not data:
            break
        for repo in data:
            full = repo.get("full_name", "")
            owner = repo.get("owner", {}).get("login", "")
            name = repo.get("name", "")
            has_ci = _has_woodpecker_config(owner, name)
            branches = _get_branches(owner, name)
            repos.append({
                "forge": "gitea",
                "full_name": full,
                "owner": owner,
                "description": repo.get("description", ""),
                "default_branch": repo.get(
                    "default_branch", "main"
                ),
                "html_url": repo.get("html_url", ""),
                "private": repo.get("private", False),
                "language": repo.get("language", ""),
                "topics": repo.get("topics") or [],
                "stars_count": repo.get("stars_count", 0),
                "updated_at": repo.get("updated", ""),
                "has_pipeline": has_ci,
                "branches": branches,
            })
        page += 1
    return repos


# Woodpecker


def fetch_wp_agents() -> list[dict]:
    """Fetch agents from Woodpecker API."""
    r = WP_SESSION.get(f"{WOODPECKER_URL}/api/agents")
    if r.status_code != 200:
        print(
            f"Woodpecker agents error: {r.status_code}",
            file=sys.stderr,
        )
        return []
    agents = []
    for a in r.json() or []:
        # Parse labels (may be dict, list, or string)
        labels = {}
        raw_labels = a.get("custom_labels") or {}
        if isinstance(raw_labels, dict):
            labels = raw_labels
        elif isinstance(raw_labels, list):
            for item in raw_labels:
                if "=" in str(item):
                    k, v = str(item).split("=", 1)
                    labels[k] = v
        hostname = labels.get("host", a.get("name", ""))
        agents.append({
            "id": a.get("id"),
            "name": a.get("name", ""),
            "hostname": hostname,
            "platform": a.get("platform", ""),
            "labels": labels,
            "capacity": a.get("capacity", 1),
            "last_contact": _ts(a.get("last_contact")),
        })
    return agents


def push_workers(agents: list[dict]) -> int:
    """Push workers to CMDB."""
    if not agents:
        return 0
    r = requests.post(
        f"{CMDB_API}/api/v1/cicd/workers/report",
        headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
        json=agents,
        timeout=CMDB_INGEST_TIMEOUT,
    )
    if r.status_code == 200:
        return r.json().get("upserted", 0)
    print(
        f"CMDB workers push error: {r.status_code} {r.text}",
        file=sys.stderr,
    )
    return 0


def fetch_wp_repos() -> list[dict]:
    """Fetch repos from Woodpecker API."""
    r = WP_SESSION.get(f"{WOODPECKER_URL}/api/repos")
    if r.status_code != 200:
        print(
            f"Woodpecker repos error: {r.status_code}",
            file=sys.stderr,
        )
        return []
    return r.json() or []


def fetch_wp_pipelines(repo_id: int, full_name: str, limit: int = 50) -> list[dict]:
    """Fetch pipeline runs for a Woodpecker repo."""
    pipelines = []
    page = 1
    per_page = min(limit, 50)

    while len(pipelines) < limit:
        r = WP_SESSION.get(
            f"{WOODPECKER_URL}/api/repos/{repo_id}/pipelines",
            params={"page": page, "per_page": per_page},
        )
        if r.status_code != 200:
            print(
                f"  pipelines {full_name} page {page}: HTTP {r.status_code}",
                file=sys.stderr,
            )
            break

        data = r.json() or []
        if not data:
            break

        for p in data:
            status_raw = p.get("status", "pending")
            pipelines.append({
                "repo_name": full_name,
                "number": p.get("number"),
                "status": _WP_STATUS.get(status_raw, status_raw),
                "event": p.get("event"),
                "branch": p.get("branch"),
                "commit": p.get("commit", ""),
                "commit_message": (p.get("message") or "")[:500],
                "author": p.get("author") or p.get("author_login", ""),
                "started_at": _ts(p.get("started_at")),
                "finished_at": _ts(p.get("finished_at")),
                "duration_secs": None,
                "link": (
                    f"{WOODPECKER_URL}/repos/{full_name}"
                    f"/pipeline/{p.get('number', '')}"
                ),
                "raw": {},
            })

        page += 1
        if len(data) < per_page:
            break

    return pipelines[:limit]


# Push to CMDB


def push_repos(repos: list[dict]) -> int:
    """Push repos to CMDB."""
    if not repos:
        return 0
    r = requests.post(
        f"{CMDB_API}/api/v1/cicd/repos/report",
        headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
        json=repos,
        timeout=CMDB_INGEST_TIMEOUT,
    )
    if r.status_code == 200:
        return r.json().get("upserted", 0)
    print(f"CMDB repos push error: {r.status_code} {r.text}", file=sys.stderr)
    return 0


def push_pipelines(pipelines: list[dict]) -> int:
    """Push pipelines to CMDB in batches."""
    if not pipelines:
        return 0
    total = 0
    for i in range(0, len(pipelines), 100):
        batch = pipelines[i : i + 100]
        r = requests.post(
            f"{CMDB_API}/api/v1/cicd/pipelines/report",
            headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
            json=batch,
            timeout=CMDB_INGEST_TIMEOUT,
        )
        if r.status_code == 200:
            total += r.json().get("upserted", 0)
        else:
            print(
                f"CMDB pipelines push error: {r.status_code} {r.text}",
                file=sys.stderr,
            )
    return total


# Main


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Woodpecker CI + Gitea → CMDB")
    parser.add_argument(
        "--pipelines", type=int, default=50,
        help="Max pipelines per repo to fetch (default: 50)",
    )
    parser.add_argument(
        "--repos-only", action="store_true",
        help="Only sync repos, skip pipelines",
    )
    parser.add_argument(
        "--no-workers", action="store_true",
        help="Skip worker/agent sync",
    )
    args = parser.parse_args()

    if not CMDB_TOKEN:
        print("CMDB_COLLECT_TOKEN required", file=sys.stderr)
        sys.exit(1)

    ts = datetime.now().isoformat()

    # Woodpecker agents
    if not args.no_workers and WOODPECKER_TOKEN:
        print(f"[{ts}] Fetching Woodpecker agents...")
        agents = fetch_wp_agents()
        print(f"  Found {len(agents)} agents")
        if agents:
            n = push_workers(agents)
            print(f"  Pushed {n} workers to CMDB")
    elif not WOODPECKER_TOKEN:
        print("[SKIP] WOODPECKER_TOKEN not set, skipping agents")

    # Gitea repos
    if GITEA_TOKEN:
        print(f"[{ts}] Fetching Gitea repos...")
        gitea_repos = fetch_gitea_repos()
        print(f"  Found {len(gitea_repos)} repos")
        if gitea_repos:
            n = push_repos(gitea_repos)
            print(f"  Pushed {n} repos to CMDB")
    else:
        print("[SKIP] GITEA_TOKEN not set, skipping Gitea repos")

    # Woodpecker pipelines
    if not args.repos_only and WOODPECKER_TOKEN:
        print(f"[{ts}] Fetching Woodpecker pipelines...")
        wp_repos = fetch_wp_repos()
        print(f"  Found {len(wp_repos)} Woodpecker repos")

        all_pipelines = []
        for repo in wp_repos:
            repo_id = repo.get("id")
            full_name = repo.get("full_name", "")
            if not repo_id or not full_name:
                continue
            pipes = fetch_wp_pipelines(repo_id, full_name, args.pipelines)
            print(f"  {full_name}: {len(pipes)} pipelines")
            all_pipelines.extend(pipes)

        if all_pipelines:
            n = push_pipelines(all_pipelines)
            print(f"  Pushed {n} pipelines to CMDB")
    elif not WOODPECKER_TOKEN:
        print("[SKIP] WOODPECKER_TOKEN not set, skipping pipelines")

    print("Done.")
