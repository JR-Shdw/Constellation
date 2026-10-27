#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Sync Forgejo repositories → CMDB.

Forgejo API is compatible with Gitea v1.
No pipelines/runners — Forgejo does not have built-in CI.
"""

import os
import sys
import time

import requests

# Config

FORGEJO_URL = os.environ.get("FORGEJO_URL", "")
FORGEJO_TOKEN = os.environ.get("FORGEJO_TOKEN", "")
CMDB_API = os.environ.get("CMDB_API", "http://api:8000")
CMDB_TOKEN = os.environ.get("CMDB_COLLECT_TOKEN", "")
# Ingestion CMDB peut etre longue sur un gros batch.
CMDB_INGEST_TIMEOUT = int(os.environ.get("CMDB_INGEST_TIMEOUT", "1200"))

if not FORGEJO_URL or not FORGEJO_TOKEN:
    print("[sync_forgejo] FORGEJO_URL and FORGEJO_TOKEN required")
    sys.exit(1)

FJ_SESSION = requests.Session()
FJ_SESSION.headers.update({"Authorization": f"token {FORGEJO_TOKEN}"})
FJ_SESSION.timeout = 30

CMDB_HEADERS = {"Authorization": f"Bearer {CMDB_TOKEN}"}


# Fetch helpers


def _has_ci_config(owner: str, repo: str) -> bool:
    """Check if repo has .woodpecker/ or .forgejo/ CI config."""
    for path in (".woodpecker", ".forgejo/workflows", ".github/workflows"):
        r = FJ_SESSION.get(f"{FORGEJO_URL}/api/v1/repos/{owner}/{repo}/contents/{path}")
        if r.status_code == 200:
            return True
    return False


def _get_branches(owner: str, repo: str) -> list[str]:
    """Fetch branch names."""
    try:
        r = FJ_SESSION.get(
            f"{FORGEJO_URL}/api/v1/repos/{owner}/{repo}/branches",
            params={"limit": 50},
        )
        r.raise_for_status()
        return [b["name"] for b in r.json()]
    except Exception:
        return []


def fetch_repos() -> list[dict]:
    """Fetch all accessible Forgejo repos."""
    repos = []
    page = 1
    while True:
        r = FJ_SESSION.get(
            f"{FORGEJO_URL}/api/v1/repos/search",
            params={"page": page, "limit": 50},
        )
        r.raise_for_status()
        data = r.json().get("data", []) or r.json()
        if not data:
            break
        for repo in data:
            owner = repo.get("owner", {}).get("login", "")
            name = repo.get("name", "")
            full_name = repo.get("full_name", f"{owner}/{name}")
            has_ci = _has_ci_config(owner, name)
            branches = _get_branches(owner, name)
            repos.append(
                {
                    "forge": "forgejo",
                    "repo_name": full_name,
                    "owner": owner,
                    "description": (repo.get("description") or "")[:500],
                    "default_branch": repo.get("default_branch", "main"),
                    "url": repo.get("html_url", ""),
                    "private": repo.get("private", False),
                    "language": repo.get("language", ""),
                    "topics": repo.get("topics", []) or [],
                    "stars": repo.get("stars_count", 0),
                    "has_pipeline": has_ci,
                    "branches": branches,
                    "last_commit_at": repo.get("updated_at"),
                }
            )
            time.sleep(0.02)
        page += 1
    return repos


# Push helpers


def push_repos(repos: list[dict]) -> int:
    r = requests.post(
        f"{CMDB_API}/api/v1/cicd/repos/report",
        headers=CMDB_HEADERS,
        json=repos,
        timeout=CMDB_INGEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json().get("upserted", 0)


# Main


def main():
    print(f"[sync_forgejo] Fetching repos from {FORGEJO_URL}...")
    repos = fetch_repos()
    print(f"  Found {len(repos)} repos")

    if repos:
        n = push_repos(repos)
        print(f"  Pushed {n} repos to CMDB")

    print("[sync_forgejo] Done")


if __name__ == "__main__":
    main()
