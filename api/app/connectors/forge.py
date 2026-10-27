# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Base forge connector — abstract interface for Git forges."""

from abc import ABC, abstractmethod


class ForgeConnector(ABC):
    """Interface commune pour les forges Git (Gitea, Forgejo, GitLab...)."""

    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/")
        self.token = token

    @property
    def available(self) -> bool:
        return bool(self.base and self.token)

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test connection. Returns {"username": "...", "status": "connected"}."""

    @abstractmethod
    async def list_repos(self, page: int = 1, per_page: int = 50) -> list[dict]:
        """List repos in normalized format:
        {"name": "owner/repo", "owner": "...", "description": "...",
         "default_branch": "main", "url": "...", "private": false,
         "language": "Python", "topics": [], "stars": 0,
         "has_pipeline": true, "branches": [...], "last_commit_at": "..."}
        """

    @abstractmethod
    async def get_branches(self, owner: str, repo: str) -> list[str]:
        """List branches of a repo."""

    @abstractmethod
    async def has_ci_config(self, owner: str, repo: str) -> bool:
        """Detect if repo has CI config (.woodpecker/, .gitlab-ci.yml...)."""

    @property
    @abstractmethod
    def forge_name(self) -> str:
        """Identifier: 'gitea', 'forgejo', 'gitlab'."""
