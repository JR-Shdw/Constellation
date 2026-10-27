# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Jira Cloud ITSM connector — Basic auth (email:API_token)."""

import base64

import httpx

from .itsm import ITSMConnector

_PRIORITY_MAP = {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}


class JiraConnector(ITSMConnector):
    """Jira connector. auth dict: {email, api_token}."""

    @property
    def platform(self) -> str:
        return "jira"

    def _headers(self) -> dict:
        creds = f"{self.auth.get('email', '')}:{self.auth.get('api_token', '')}"
        encoded = base64.b64encode(creds.encode()).decode()
        return {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.base}/rest/api/3/myself", headers=self._headers())
            r.raise_for_status()
            data = r.json()
            return {"status": "ok", "info": data.get("emailAddress") or "connected"}

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        labels: list[str] | None = None,
    ) -> tuple[str, str]:
        if not self.project_key:
            raise ValueError("Jira requires project_key")
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": title,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                },
                "issuetype": {"name": "Incident"},
                "priority": {"name": _PRIORITY_MAP.get(priority, "Medium")},
                "labels": labels or [],
            }
        }
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                f"{self.base}/rest/api/3/issue",
                headers=self._headers(),
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
            key = data.get("key", "")
        url = f"{self.base}/browse/{key}"
        return key, url

    def parse_inbound_status(self, payload: dict) -> tuple[str | None, str | None]:
        # Jira webhook: {"issue": {"key": ..., "fields": {"status": {"name": ...}}}}
        issue = payload.get("issue") or payload
        key = issue.get("key") or issue.get("id")
        status = None
        fields = issue.get("fields") or {}
        if isinstance(fields.get("status"), dict):
            status = fields["status"].get("name")
        elif isinstance(fields.get("status"), str):
            status = fields.get("status")
        return (str(key) if key else None, status)
