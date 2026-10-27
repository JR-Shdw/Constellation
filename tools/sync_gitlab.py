#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Sync GitLab projects, pipelines, and runners → CMDB."""

import os
import sys
import time

import requests

# Config

GITLAB_URL = os.environ.get("GITLAB_URL", "")
GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN", "")
CMDB_API = os.environ.get("CMDB_API", "http://api:8000")
CMDB_TOKEN = os.environ.get("CMDB_COLLECT_TOKEN", "")
# Ingestion CMDB peut etre longue sur un gros batch.
CMDB_INGEST_TIMEOUT = int(os.environ.get("CMDB_INGEST_TIMEOUT", "1200"))

if not GITLAB_URL or not GITLAB_TOKEN:
    print("[sync_gitlab] GITLAB_URL and GITLAB_TOKEN required")
    sys.exit(1)

GL_SESSION = requests.Session()
GL_SESSION.headers.update({"PRIVATE-TOKEN": GITLAB_TOKEN})
GL_SESSION.timeout = 30

CMDB_HEADERS = {"Authorization": f"Bearer {CMDB_TOKEN}"}

# Status mapping

_STATUS_MAP = {
    "created": "pending",
    "waiting_for_resource": "pending",
    "preparing": "pending",
    "pending": "pending",
    "running": "running",
    "success": "success",
    "failed": "failure",
    "canceled": "killed",
    "skipped": "skipped",
    "manual": "blocked",
}

_EVENT_MAP = {
    "push": "push",
    "web": "manual",
    "trigger": "manual",
    "api": "manual",
    "schedule": "cron",
    "merge_request_event": "pull_request",
    "external_pull_request_event": "pull_request",
}

_RUNNER_STATUS = {
    "online": "connected",
    "offline": "offline",
    "paused": "idle",
    "stale": "offline",
}


# Fetch helpers


def fetch_projects(per_page: int = 100) -> list[dict]:
    """Fetch all accessible GitLab projects."""
    projects = []
    page = 1
    while True:
        r = GL_SESSION.get(
            f"{GITLAB_URL}/api/v4/projects",
            params={
                "membership": "true",
                "per_page": per_page,
                "page": page,
                "order_by": "last_activity_at",
                "sort": "desc",
            },
        )
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        for p in batch:
            has_ci = _has_ci_config(p["id"])
            projects.append(
                {
                    "forge": "gitlab",
                    "repo_name": p.get("path_with_namespace", ""),
                    "owner": p.get("namespace", {}).get("path", ""),
                    "description": (p.get("description") or "")[:500],
                    "default_branch": p.get("default_branch", "main"),
                    "url": p.get("web_url", ""),
                    "private": p.get("visibility") != "public",
                    "language": "",
                    "topics": p.get("topics", []) or p.get("tag_list", []) or [],
                    "stars": p.get("star_count", 0),
                    "has_pipeline": has_ci,
                    "branches": _get_branches(p["id"]),
                    "last_commit_at": p.get("last_activity_at"),
                    "_gitlab_id": p["id"],
                }
            )
        page += 1
        time.sleep(0.05)
    return projects


def _has_ci_config(project_id: int) -> bool:
    """Check if project has .gitlab-ci.yml."""
    r = GL_SESSION.head(
        f"{GITLAB_URL}/api/v4/projects/{project_id}/repository/files/.gitlab-ci.yml",
        params={"ref": "HEAD"},
    )
    return r.status_code == 200


def _get_branches(project_id: int) -> list[str]:
    """Fetch branch names for a project."""
    try:
        r = GL_SESSION.get(
            f"{GITLAB_URL}/api/v4/projects/{project_id}/repository/branches",
            params={"per_page": 50},
        )
        r.raise_for_status()
        return [b["name"] for b in r.json()]
    except Exception:
        return []


def fetch_pipelines(project_id: int, full_name: str, limit: int = 50) -> list[dict]:
    """Fetch recent pipelines for a project."""
    pipelines = []
    r = GL_SESSION.get(
        f"{GITLAB_URL}/api/v4/projects/{project_id}/pipelines",
        params={"per_page": min(limit, 100), "order_by": "id", "sort": "desc"},
    )
    r.raise_for_status()
    for p in r.json():
        pipelines.append(
            {
                "ci_system": "gitlab",
                "repo_name": full_name,
                "number": p.get("id"),
                "pipeline_number": p.get("id"),
                "status": _STATUS_MAP.get(p.get("status", ""), p.get("status", "")),
                "event": _EVENT_MAP.get(p.get("source", ""), None),
                "branch": p.get("ref", ""),
                "commit_sha": (p.get("sha") or "")[:12],
                "commit_message": "",
                "author": p.get("user", {}).get("username", ""),
                "duration_secs": p.get("duration"),
                "started_at": p.get("started_at") or p.get("created_at"),
                "finished_at": p.get("finished_at") or p.get("updated_at"),
                "link": p.get("web_url", ""),
            }
        )
    return pipelines[:limit]


def fetch_runners() -> list[dict]:
    """Fetch all GitLab runners."""
    runners = []
    r = GL_SESSION.get(
        f"{GITLAB_URL}/api/v4/runners/all",
        params={"per_page": 100},
    )
    r.raise_for_status()
    for runner in r.json():
        tags = runner.get("tag_list", [])
        runners.append(
            {
                "ci_system": "gitlab",
                "external_id": str(runner.get("id", "")),
                "name": runner.get("description", "") or f"runner-{runner.get('id')}",
                "hostname": "",
                "platform": (
                    runner.get("architecture", "") or runner.get("platform", "")
                ),
                "labels": {t: "true" for t in tags} if tags else {},
                "capacity": 1,
                "status": _RUNNER_STATUS.get(runner.get("status", ""), "offline"),
                "last_contact": runner.get("contacted_at"),
            }
        )
    return runners


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


def push_pipelines(pipelines: list[dict]) -> int:
    total = 0
    for i in range(0, len(pipelines), 100):
        batch = pipelines[i : i + 100]
        r = requests.post(
            f"{CMDB_API}/api/v1/cicd/pipelines/report",
            headers=CMDB_HEADERS,
            json=batch,
            timeout=CMDB_INGEST_TIMEOUT,
        )
        r.raise_for_status()
        total += r.json().get("upserted", 0)
    return total


def push_workers(workers: list[dict]) -> int:
    r = requests.post(
        f"{CMDB_API}/api/v1/cicd/workers/report",
        headers=CMDB_HEADERS,
        json=workers,
        timeout=CMDB_INGEST_TIMEOUT,
    )
    r.raise_for_status()
    return r.json().get("upserted", 0)


# Main


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Sync GitLab → CMDB")
    parser.add_argument("--pipelines", type=int, default=50, help="Pipelines per repo")
    parser.add_argument(
        "--repos-only", action="store_true", help="Skip pipelines/runners"
    )
    parser.add_argument("--no-workers", action="store_true", help="Skip runners sync")
    args = parser.parse_args()

    print(f"[sync_gitlab] Fetching projects from {GITLAB_URL}...")
    projects = fetch_projects()
    print(f"  Found {len(projects)} projects")

    if projects:
        n = push_repos(projects)
        print(f"  Pushed {n} repos to CMDB")

    if not args.repos_only:
        all_pipelines = []
        for proj in projects:
            if proj.get("has_pipeline"):
                gid = proj.get("_gitlab_id")
                if gid:
                    pipes = fetch_pipelines(gid, proj["repo_name"], args.pipelines)
                    all_pipelines.extend(pipes)
                    time.sleep(0.05)
        if all_pipelines:
            n = push_pipelines(all_pipelines)
            print(f"  Pushed {n} pipelines to CMDB")

    if not args.no_workers:
        print("[sync_gitlab] Fetching runners...")
        try:
            runners = fetch_runners()
            if runners:
                n = push_workers(runners)
                print(f"  Pushed {n} runners to CMDB")
        except Exception as e:
            print(f"  Runner sync failed (need admin token?): {e}")

    print("[sync_gitlab] Done")


if __name__ == "__main__":
    main()
