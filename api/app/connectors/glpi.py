# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""GLPI ITSM connector — App-Token + User-Token authentication."""

import httpx

from .itsm import ITSMConnector

# CMDB P1..P4 → GLPI priority (1=very low .. 6=major)
_PRIORITY_MAP = {"P1": 5, "P2": 4, "P3": 3, "P4": 2}


class GLPIConnector(ITSMConnector):
    """GLPI connector. auth dict: {app_token, user_token}."""

    @property
    def platform(self) -> str:
        return "glpi"

    def _headers(self) -> dict:
        return {
            "App-Token": self.auth.get("app_token", ""),
            "Authorization": f"user_token {self.auth.get('user_token', '')}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"{self.base}/apirest.php/initSession", headers=self._headers()
            )
            r.raise_for_status()
            return {"status": "ok", "info": "GLPI session opened"}

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: str,
        labels: list[str] | None = None,
    ) -> tuple[str, str]:
        payload = {
            "input": {
                "name": title,
                "content": description,
                "priority": _PRIORITY_MAP.get(priority, 3),
                "urgency": _PRIORITY_MAP.get(priority, 3),
                "type": 1,  # incident
            }
        }
        async with httpx.AsyncClient(timeout=15) as c:
            # GLPI requires a session for write operations: initSession (App-Token
            # + user_token) returns a session_token that every subsequent call
            # must carry as a Session-Token header. Posting /Ticket without it is
            # rejected with ERROR_SESSION_TOKEN_MISSING (verified against GLPI
            # 10.0.25). The old code sent only App-Token + Authorization and so
            # could never create a ticket.
            init = await c.get(
                f"{self.base}/apirest.php/initSession",
                headers=self._headers(),
            )
            init.raise_for_status()
            session_token = init.json().get("session_token", "")
            if not session_token:
                raise RuntimeError("GLPI initSession returned no session_token")

            session_headers = {
                "App-Token": self.auth.get("app_token", ""),
                "Session-Token": session_token,
                "Content-Type": "application/json",
            }
            try:
                r = await c.post(
                    f"{self.base}/apirest.php/Ticket",
                    headers=session_headers,
                    json=payload,
                )
                r.raise_for_status()
                data = r.json()
                if isinstance(data, list) and data:
                    tid = str(data[0].get("id", ""))
                else:
                    tid = str(data.get("id", ""))
            finally:
                # Best-effort: close the server-side session so we don't leak
                # GLPI sessions on every ticket. Failure here must not mask the
                # create result.
                try:
                    await c.get(
                        f"{self.base}/apirest.php/killSession",
                        headers=session_headers,
                    )
                except Exception:
                    pass
        url = f"{self.base}/front/ticket.form.php?id={tid}"
        return tid, url

    def parse_inbound_status(self, payload: dict) -> tuple[str | None, str | None]:
        # GLPI webhook: {"items_id": 42, "status": 5, ...}
        tid = payload.get("items_id") or payload.get("id")
        status = payload.get("status")
        return (str(tid) if tid else None, str(status) if status is not None else None)
