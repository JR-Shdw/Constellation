# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Portainer API client — async httpx wrapper."""

import json
import logging

import httpx

from .image_verify import verify_image

logger = logging.getLogger(__name__)

_TIMEOUT = 20.0


def _docker_stream_error(body: str) -> str | None:
    """Find a Docker pull error in a streamed /images/create response.

    The Docker Engine API streams progress as JSON objects and reports pull
    failures IN-BAND with a 200 status — e.g. {"error":"manifest unknown"} —
    so HTTP status alone says nothing. Walk the (newline-delimited or
    concatenated) objects and return the first error message, if any.
    """
    decoder = json.JSONDecoder()
    idx, n = 0, len(body)
    while idx < n:
        while idx < n and body[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            evt, idx = decoder.raw_decode(body, idx)
        except ValueError:
            break
        if isinstance(evt, dict) and evt.get("error"):
            return str(evt["error"])
    return None


class PortainerClient:
    """Async client for a single Portainer instance."""

    def __init__(
        self, url: str, token: str, endpoint_id: int = 1, tls_skip_verify: bool = False
    ):
        self.base = url.rstrip("/")
        self.token = token
        self.endpoint_id = endpoint_id
        self.verify = not tls_skip_verify

    def _headers(self) -> dict:
        return {"X-API-Key": self.token}

    def _ep(self, path: str) -> str:
        """Build endpoint-scoped Docker API URL."""
        return f"{self.base}/api/endpoints/{self.endpoint_id}/docker{path}"

    # Connection test

    async def test_connection(self) -> dict:
        """Test connectivity — returns Portainer status."""
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self.verify) as c:
            r = await c.get(
                f"{self.base}/api/status",
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()

    # Endpoints

    async def list_endpoints(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self.verify) as c:
            r = await c.get(
                f"{self.base}/api/endpoints",
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json() or []

    # Images

    async def list_images(self) -> list[dict]:
        """List Docker images on the endpoint."""
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self.verify) as c:
            r = await c.get(
                self._ep("/images/json"),
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json() or []

    async def pull_image(self, image: str, tag: str = "latest") -> dict:
        """Pull an image from a registry to the endpoint.

        Refuses to pull when the image is in a trusted namespace
        (see api/app/utils/image_verify.py) and its cosign signature
        doesn't verify against the pinned key in trust/. Untrusted
        namespaces pass through unchanged — the gate is opt-in by
        prefix, not a global denylist.
        """
        await verify_image(image, tag)
        async with httpx.AsyncClient(timeout=120.0, verify=self.verify) as c:
            r = await c.post(
                self._ep("/images/create"),
                headers=self._headers(),
                params={"fromImage": image, "tag": tag},
            )
            r.raise_for_status()
            # Docker reports pull failures in the streamed body with a 200
            # status, so raise_for_status would let a failed pull masquerade
            # as success (a false "remediation done" signal).
            err = _docker_stream_error(r.text)
            if err:
                raise RuntimeError(f"pull failed for {image}:{tag}: {err}"[:300])
            return {"status": "ok", "image": f"{image}:{tag}"}

    async def inspect_image(self, image_id: str) -> dict:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self.verify) as c:
            r = await c.get(
                self._ep(f"/images/{image_id}/json"),
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()
