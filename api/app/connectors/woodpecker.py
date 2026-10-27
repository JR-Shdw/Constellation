# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Woodpecker CI connector — replaces api/app/utils/woodpecker.py."""

import logging

import httpx

from .ci import CIConnector

logger = logging.getLogger(__name__)

_TIMEOUT = 15.0


class WoodpeckerCI(CIConnector):
    ci_name = "woodpecker"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{self.base}/api/user", headers=self._headers())
            r.raise_for_status()
            user = r.json()
            return {"username": user.get("login", "?"), "status": "connected"}

    # Runners (Woodpecker calls them agents)

    async def list_runners(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{self.base}/api/agents", headers=self._headers())
            r.raise_for_status()
            agents = r.json() or []

        runners = []
        for a in agents:
            # Parse labels — Woodpecker returns dict, list, or "key=val,..." string
            labels = a.get("custom_labels", {})
            if isinstance(labels, list):
                labels = dict(item.split("=", 1) for item in labels if "=" in item)
            elif isinstance(labels, str):
                labels = dict(
                    item.split("=", 1) for item in labels.split(",") if "=" in item
                )
            runners.append(
                {
                    "external_id": str(a.get("id", "")),
                    "name": a.get("name", ""),
                    "hostname": a.get("platform", ""),
                    "platform": a.get("platform", ""),
                    "labels": labels or {},
                    "capacity": a.get("capacity", 1),
                    "status": "connected" if a.get("last_contact") else "offline",
                    "last_contact": a.get("last_contact"),
                }
            )
        return runners

    # ── Repos (Woodpecker-specific, for repo_name→id mapping) ─

    async def list_repos(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{self.base}/api/repos", headers=self._headers())
            r.raise_for_status()
            return r.json() or []

    async def get_repo(self, owner: str, name: str) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(
                f"{self.base}/api/repos/{owner}/{name}", headers=self._headers()
            )
            r.raise_for_status()
            return r.json()

    # Pipelines

    async def list_pipelines(self, repo_id: str | int, limit: int = 50) -> list[dict]:
        pipelines = []
        page = 1
        per_page = min(limit, 50)
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            while len(pipelines) < limit:
                r = await c.get(
                    f"{self.base}/api/repos/{repo_id}/pipelines",
                    headers=self._headers(),
                    params={"page": page, "perPage": per_page},
                )
                r.raise_for_status()
                batch = r.json() or []
                if not batch:
                    break
                for p in batch:
                    pipelines.append(self._normalize_pipeline(p, repo_id))
                page += 1
        return pipelines[:limit]

    async def trigger_pipeline(
        self, repo_id: str | int, branch: str, variables: dict | None = None
    ) -> dict:
        body: dict = {"branch": branch}
        if variables:
            body["variables"] = variables
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(
                f"{self.base}/api/repos/{repo_id}/pipelines",
                headers=self._headers(),
                json=body,
            )
            r.raise_for_status()
            data = r.json()
            pnum = data.get("number")
            return {
                "number": pnum,
                "link": f"{self.base}/repos/{repo_id}/pipeline/{pnum}",
            }

    async def get_pipeline(self, repo_id: int, number: int) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(
                f"{self.base}/api/repos/{repo_id}/pipelines/{number}",
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()

    # Helpers

    _STATUS_MAP = {
        "success": "success",
        "failure": "failure",
        "error": "error",
        "running": "running",
        "pending": "pending",
        "blocked": "blocked",
        "killed": "killed",
        "skipped": "skipped",
        "declined": "declined",
    }

    def _normalize_pipeline(self, p: dict, repo_id: str | int) -> dict:
        from datetime import datetime, timezone

        started = p.get("started_at") or p.get("created_at")
        finished = p.get("finished_at")
        if isinstance(started, int | float) and started > 0:
            started = datetime.fromtimestamp(started, tz=timezone.utc).isoformat()
        if isinstance(finished, int | float) and finished > 0:
            finished = datetime.fromtimestamp(finished, tz=timezone.utc).isoformat()

        return {
            "number": p.get("number"),
            "status": self._STATUS_MAP.get(p.get("status", ""), p.get("status", "")),
            "event": p.get("event"),
            "branch": p.get("branch"),
            "commit_sha": p.get("commit", ""),
            "commit_message": (p.get("message") or "")[:500],
            "author": p.get("author", ""),
            "duration_secs": None,
            "started_at": started,
            "finished_at": finished,
            "link": (
                p.get("link")
                or f"{self.base}/repos/{repo_id}/pipeline/{p.get('number')}"
            ),
        }
