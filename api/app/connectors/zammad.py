# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Zammad ITSM connector — Bearer token authentication."""

import httpx

from .itsm import ITSMConnector

# CMDB P1..P4 → Zammad priority id (1=low .. 3=high); 2 urgent/blocker as high
_PRIORITY_MAP = {"P1": 3, "P2": 3, "P3": 2, "P4": 1}


class ZammadConnector(ITSMConnector):
    """Zammad connector. auth dict: {token, group}."""

    @property
    def platform(self) -> str:
        return "zammad"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.auth.get('token', '')}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.base}/api/v1/users/me", headers=self._headers())
            r.raise_for_status()
            data = r.json()
            return {"status": "ok", "info": data.get("login") or "connected"}

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        labels: list[str] | None = None,
    ) -> tuple[str, str]:
        payload = {
            "title": title,
            "group": self.auth.get("group", "Users"),
            "customer_id": self.auth.get("customer_id", "guess:cmdb@local"),
            "priority_id": _PRIORITY_MAP.get(priority, 2),
            "article": {
                "subject": title,
                "body": description,
                "type": "note",
                "internal": False,
            },
        }
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                f"{self.base}/api/v1/tickets",
                headers=self._headers(),
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
            tid = str(data.get("id"))
        url = f"{self.base}/#ticket/zoom/{tid}"
        return tid, url

    def parse_inbound_status(self, payload: dict) -> tuple[str | None, str | None]:
        # Zammad: {"ticket": {"id": 42, "state": "closed"}} or flat
        ticket = payload.get("ticket") or payload
        tid = ticket.get("id")
        status = ticket.get("state") or ticket.get("state_id")
        return (str(tid) if tid else None, str(status) if status is not None else None)
