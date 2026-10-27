# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""GitLab CI connector — pipelines, runners, trigger via REST API v4."""

from urllib.parse import quote_plus

import httpx

from .ci import CIConnector

_TIMEOUT = 15.0

# GitLab → normalized status mapping
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

_RUNNER_STATUS_MAP = {
    "online": "connected",
    "offline": "offline",
    "paused": "idle",
    "stale": "offline",
}


class GitLabCI(CIConnector):
    ci_name = "gitlab"

    def _headers(self) -> dict:
        return {"PRIVATE-TOKEN": self.token}

    def _project_id(self, path: str) -> str:
        return quote_plus(path)

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{self.base}/api/v4/user", headers=self._headers())
            r.raise_for_status()
            user = r.json()
            return {"username": user.get("username", "?"), "status": "connected"}

    async def list_pipelines(self, repo_id: str | int, limit: int = 50) -> list[dict]:
        pid = self._project_id(str(repo_id))
        pipelines = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(
                f"{self.base}/api/v4/projects/{pid}/pipelines",
                headers=self._headers(),
                params={"per_page": min(limit, 100), "order_by": "id", "sort": "desc"},
            )
            r.raise_for_status()
            for p in r.json():
                pipelines.append(
                    {
                        "number": p.get("id"),
                        "status": _STATUS_MAP.get(
                            p.get("status", ""), p.get("status", "")
                        ),
                        "event": _map_event(p.get("source")),
                        "branch": p.get("ref", ""),
                        "commit_sha": p.get("sha", "")[:12],
                        "commit_message": "",
                        "author": p.get("user", {}).get("username", ""),
                        "duration_secs": p.get("duration"),
                        "started_at": p.get("started_at") or p.get("created_at"),
                        "finished_at": p.get("finished_at") or p.get("updated_at"),
                        "link": p.get("web_url", ""),
                    }
                )
        return pipelines[:limit]

    async def list_runners(self) -> list[dict]:
        runners = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(
                f"{self.base}/api/v4/runners/all",
                headers=self._headers(),
                params={"per_page": 100},
            )
            r.raise_for_status()
            for runner in r.json():
                runners.append(
                    {
                        "external_id": str(runner.get("id", "")),
                        "name": (
                            runner.get("description", "")
                            or f"runner-{runner.get('id')}"
                        ),
                        "hostname": "",
                        "platform": (
                            runner.get("architecture", "") or runner.get("platform", "")
                        ),
                        "labels": _parse_runner_tags(runner.get("tag_list", [])),
                        "capacity": 1,
                        "status": _RUNNER_STATUS_MAP.get(
                            runner.get("status", ""), "offline"
                        ),
                        "last_contact": runner.get("contacted_at"),
                    }
                )
        return runners

    async def trigger_pipeline(
        self, repo_id: str | int, branch: str, variables: dict | None = None
    ) -> dict:
        pid = self._project_id(str(repo_id))
        body: dict = {"ref": branch}
        if variables:
            body["variables"] = [
                {"key": k, "value": str(v)} for k, v in variables.items()
            ]
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(
                f"{self.base}/api/v4/projects/{pid}/pipeline",
                headers=self._headers(),
                json=body,
            )
            r.raise_for_status()
            data = r.json()
            return {
                "number": data.get("id"),
                "link": data.get("web_url", ""),
            }


def _map_event(source: str | None) -> str | None:
    """Map GitLab pipeline source to normalized event type."""
    mapping = {
        "push": "push",
        "web": "manual",
        "trigger": "manual",
        "api": "manual",
        "schedule": "cron",
        "merge_request_event": "pull_request",
        "external_pull_request_event": "pull_request",
    }
    return mapping.get(source or "", None)


def _parse_runner_tags(tags: list) -> dict:
    """Convert GitLab runner tags list to dict format."""
    return {tag: "true" for tag in tags} if tags else {}
