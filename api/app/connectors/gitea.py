# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Gitea forge connector."""

import logging

import httpx

from .forge import ForgeConnector

logger = logging.getLogger(__name__)

_TIMEOUT = 15.0


class GiteaForge(ForgeConnector):
    forge_name = "gitea"

    def _headers(self) -> dict:
        return {"Authorization": f"token {self.token}"}

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{self.base}/api/v1/user", headers=self._headers())
            r.raise_for_status()
            user = r.json()
            return {"username": user.get("login", "?"), "status": "connected"}

    async def list_repos(self, page: int = 1, per_page: int = 50) -> list[dict]:
        repos: list[dict] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(
                f"{self.base}/api/v1/repos/search",
                headers=self._headers(),
                params={"page": page, "limit": per_page},
            )
            r.raise_for_status()
            # /repos/search returns {"ok": true, "data": [...]}. The old
            # `.get("data", []) or r.json()` fallback iterated the whole dict
            # (its string keys) on an empty result → AttributeError. Read the
            # body once and unwrap either shape.
            body = r.json()
            items = body.get("data", []) if isinstance(body, dict) else body
            for repo in items or []:
                owner = repo.get("owner", {}).get("login", "")
                name = repo.get("full_name", f"{owner}/{repo.get('name', '')}")
                repos.append(
                    {
                        "name": name,
                        "owner": owner,
                        "description": repo.get("description", ""),
                        "default_branch": repo.get("default_branch", "main"),
                        "url": repo.get("html_url", ""),
                        "private": repo.get("private", False),
                        "language": repo.get("language", ""),
                        "topics": repo.get("topics", []) or [],
                        "stars": repo.get("stars_count", 0),
                        "has_pipeline": False,
                        "branches": [],
                        "last_commit_at": repo.get("updated_at"),
                    }
                )
        return repos

    async def get_branches(self, owner: str, repo: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(
                    f"{self.base}/api/v1/repos/{owner}/{repo}/branches",
                    headers=self._headers(),
                    params={"limit": 50},
                )
                r.raise_for_status()
                return [b["name"] for b in r.json()]
        except Exception as e:
            logger.warning("[gitea] list_branches %s/%s failed: %s", owner, repo, e)
            return []

    async def has_ci_config(self, owner: str, repo: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(
                    f"{self.base}/api/v1/repos/{owner}/{repo}/contents/.woodpecker",
                    headers=self._headers(),
                )
                return r.status_code == 200
        except Exception as e:
            logger.warning("[gitea] has_ci_config %s/%s failed: %s", owner, repo, e)
            return False
