# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Base CI/CD connector — abstract interface for CI systems."""

from abc import ABC, abstractmethod


class CIConnector(ABC):
    """Interface commune pour les systèmes CI/CD (Woodpecker, GitLab CI...)."""

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
    async def list_pipelines(self, repo_id: str | int, limit: int = 50) -> list[dict]:
        """List pipelines in normalized format:
        {"number": 42, "status": "success", "event": "push", "branch": "main",
         "commit_sha": "abc", "commit_message": "...", "author": "...",
         "duration_secs": 120, "started_at": "...", "finished_at": "...",
         "link": "https://..."}
        """

    @abstractmethod
    async def list_runners(self) -> list[dict]:
        """List runners/agents in normalized format:
        {"external_id": "123", "name": "...", "hostname": "...",
         "platform": "linux/amd64", "labels": {}, "capacity": 1,
         "status": "connected", "last_contact": "..."}
        """

    @abstractmethod
    async def trigger_pipeline(
        self, repo_id: str | int, branch: str, variables: dict | None = None
    ) -> dict:
        """Trigger a pipeline. Returns {"number": ..., "link": "..."}."""

    @property
    @abstractmethod
    def ci_name(self) -> str:
        """Identifier: 'woodpecker', 'gitlab'."""
