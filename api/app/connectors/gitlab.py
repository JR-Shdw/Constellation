# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""GitLab forge connector — REST API v4."""

import logging
from urllib.parse import quote_plus

import httpx

from .forge import ForgeConnector

logger = logging.getLogger(__name__)

_TIMEOUT = 15.0


class GitLabForge(ForgeConnector):
    forge_name = "gitlab"

    def _headers(self) -> dict:
        return {"PRIVATE-TOKEN": self.token}

    def _project_id(self, path: str) -> str:
        """URL-encode a project path (owner/repo) for GitLab API."""
        return quote_plus(path)

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{self.base}/api/v4/user", headers=self._headers())
            r.raise_for_status()
            user = r.json()
            return {"username": user.get("username", "?"), "status": "connected"}

    async def list_repos(self, page: int = 1, per_page: int = 50) -> list[dict]:
        repos: list[dict] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(
                f"{self.base}/api/v4/projects",
                headers=self._headers(),
                params={
                    "membership": "true",
                    "page": page,
                    "per_page": per_page,
                    "order_by": "last_activity_at",
                    "sort": "desc",
                },
            )
            r.raise_for_status()
            for proj in r.json():
                repos.append(
                    {
                        "name": proj.get("path_with_namespace", ""),
                        "owner": proj.get("namespace", {}).get("path", ""),
                        "description": proj.get("description", "") or "",
                        "default_branch": proj.get("default_branch", "main"),
                        "url": proj.get("web_url", ""),
                        "private": proj.get("visibility") != "public",
                        "language": "",
                        "topics": proj.get("topics", [])
                        or proj.get("tag_list", [])
                        or [],
                        "stars": proj.get("star_count", 0),
                        "has_pipeline": False,
                        "branches": [],
                        "last_commit_at": proj.get("last_activity_at"),
                        "_gitlab_id": proj.get("id"),
                    }
                )
        return repos

    async def get_branches(self, owner: str, repo: str) -> list[str]:
        pid = self._project_id(f"{owner}/{repo}")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(
                    f"{self.base}/api/v4/projects/{pid}/repository/branches",
                    headers=self._headers(),
                    params={"per_page": 100},
                )
                r.raise_for_status()
                return [b["name"] for b in r.json()]
        except Exception as e:
            logger.warning("[gitlab] list_branches %s/%s failed: %s", owner, repo, e)
            return []

    async def has_ci_config(self, owner: str, repo: str) -> bool:
        pid = self._project_id(f"{owner}/{repo}")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.head(
                    f"{self.base}/api/v4/projects/{pid}/repository/files/.gitlab-ci.yml",
                    headers=self._headers(),
                    params={"ref": "HEAD"},
                )
                return r.status_code == 200
        except Exception as e:
            logger.warning("[gitlab] has_ci_config %s/%s failed: %s", owner, repo, e)
            return False
