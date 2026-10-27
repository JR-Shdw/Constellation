# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Base ITSM connector — abstract interface for ticket systems."""

from abc import ABC, abstractmethod


class ITSMConnector(ABC):
    """Interface commune pour les ITSM (GLPI, Zammad, Jira)."""

    def __init__(self, base_url: str, auth: dict, project_key: str | None = None):
        self.base = base_url.rstrip("/")
        self.auth = auth or {}
        self.project_key = project_key

    @abstractmethod
    async def test_connection(self) -> dict:
        """Returns {"status": "ok", "info": "..."} or raises."""

    @abstractmethod
    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        labels: list[str] | None = None,
    ) -> tuple[str, str]:
        """Create a ticket. Returns (external_id, external_url)."""

    @abstractmethod
    def parse_inbound_status(self, payload: dict) -> tuple[str | None, str | None]:
        """Extract (external_id, external_status) from platform webhook payload."""

    @property
    @abstractmethod
    def platform(self) -> str:
        """Identifier: 'glpi', 'zammad', 'jira'."""
