# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Registry connectors — resolve latest tags from container registries."""

import logging
import re
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0

# Tag sorting

_SKIP_TAGS = {"latest", "main", "master", "edge", "stable"}
_SKIP_FRAGMENTS = ("sha256", "alpha", "beta", "rc", "nightly", "dev")

# A pre-release fragment counts only when it isn't preceded by a letter — so it
# starts a token ('-rc1', '.dev0') or follows a version digit ('1.0rc1'). A bare
# substring match wrongly drops stable tags like '1.0-source' ('rc' inside
# 'source') or '...-mariadb' (no fragment, but the principle is the same).
_PRERELEASE_RE = re.compile(
    r"(?<![a-z])(?:" + "|".join(_SKIP_FRAGMENTS) + r")", re.IGNORECASE
)

# Matches version-like strings: 1.2.3, v3.13, 24.0-alpine, 3.6.8-alpine
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)")


def tag_sortkey(tag: str) -> tuple:
    """Numeric sort key for version tags like 12.2.0, v3.13, 3.6.8-alpine."""
    m = _VERSION_RE.match(tag)
    if not m:
        return (0,)
    parts = []
    for part in m.group(1).split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    # Drop trailing zeros so 1.2 and 1.2.0 compare equal — otherwise the
    # tuple (1, 2) sorts below (1, 2, 0) and a repo on '1.2' is reported as
    # having a bogus '1.2 -> 1.2.0' update. Keep at least one component.
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def tag_suffix(tag: str) -> str:
    """Extract non-numeric suffix: '3.6.8-alpine' → 'alpine', 'v2.4.27' → ''."""
    m = _VERSION_RE.match(tag)
    if not m:
        return tag.lower()
    rest = tag[m.end() :]
    return rest.lstrip("-").lower()


def is_version_tag(tag: str) -> bool:
    """Return True if tag looks like a version (has at least one digit group)."""
    return bool(_VERSION_RE.match(tag))


def tags_comparable(current: str, latest: str) -> bool:
    """Check if two tags can be meaningfully compared.

    Tags are comparable if both have version numbers and share the same suffix.
    e.g. '3.6.8-alpine' and '3.7.0-alpine' are comparable.
    'latest' and 'v2.4.27' are NOT comparable.
    'bookworm-slim' and '12.13' are NOT comparable.
    """
    if not current or not latest:
        return False
    if not is_version_tag(current) or not is_version_tag(latest):
        return False
    return tag_suffix(current) == tag_suffix(latest)


def _filter_tags(tags: list[str]) -> list[str]:
    """Remove non-version tags (latest, alpha, rc, sha256…)."""
    return [
        t
        for t in tags
        if t not in _SKIP_TAGS and not _PRERELEASE_RE.search(t) and is_version_tag(t)
    ]


# ABC


class RegistryConnector(ABC):
    """Interface commune pour les registries Docker."""

    @abstractmethod
    async def resolve_latest(self, image: str) -> str | None:
        """Find latest stable tag (excludes latest, alpha, rc…)."""

    @abstractmethod
    async def list_tags(self, image: str) -> list[str]:
        """List all available tags."""

    @property
    @abstractmethod
    def registry_name(self) -> str:
        """Identifier: 'dockerhub', 'ghcr', 'gitlab', 'harbor'."""


# DockerHub


class DockerHubRegistry(RegistryConnector):
    registry_name = "dockerhub"

    async def list_tags(self, image: str) -> list[str]:
        parts = image.split("/")
        if len(parts) == 1:
            namespace, repo = "library", parts[0]
        else:
            namespace, repo = parts[0], "/".join(parts[1:])
        url = (
            f"https://hub.docker.com/v2/repositories/{namespace}/{repo}"
            f"/tags/?page_size=50&ordering=-last_updated"
        )
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(url, headers={"Accept": "application/json"})
                r.raise_for_status()
                return [t["name"] for t in r.json().get("results", [])]
        except Exception as e:
            logger.warning("[registry] %s failed: %s", self.registry_name, e)
            return []

    async def resolve_latest(self, image: str) -> str | None:
        tags = _filter_tags(await self.list_tags(image))
        return sorted(tags, key=tag_sortkey, reverse=True)[0] if tags else None


# GHCR


class GHCRRegistry(RegistryConnector):
    registry_name = "ghcr"

    async def list_tags(self, image: str) -> list[str]:
        parts = image.split("/")
        if len(parts) < 2:
            return []
        owner, repo = "/".join(parts[:-1]), parts[-1]
        url = f"https://ghcr.io/v2/{owner}/{repo}/tags/list"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(url, headers={"Accept": "application/json"})
                if r.status_code == 401:
                    auth_url = (
                        f"https://ghcr.io/token?scope=repository:{owner}/{repo}:pull"
                    )
                    token_r = await c.get(auth_url)
                    token = token_r.json().get("token", "")
                    r = await c.get(
                        url,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/json",
                        },
                    )
                r.raise_for_status()
                return r.json().get("tags", [])
        except Exception as e:
            logger.warning("[registry] %s failed: %s", self.registry_name, e)
            return []

    async def resolve_latest(self, image: str) -> str | None:
        tags = _filter_tags(await self.list_tags(image))
        return sorted(tags, key=tag_sortkey, reverse=True)[0] if tags else None


# GitLab Registry


class GitLabRegistry(RegistryConnector):
    """GitLab container registry — uses OCI Distribution API behind GitLab auth."""

    registry_name = "gitlab"

    def __init__(self, url: str = "", token: str = ""):
        self.base = url.rstrip("/") if url else ""
        self.token = token

    async def list_tags(self, image: str) -> list[str]:
        if not self.base:
            return []
        # GitLab registry uses /v2/{image}/tags/list
        url = f"{self.base}/v2/{image}/tags/list"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                headers: dict = {"Accept": "application/json"}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                r = await c.get(url, headers=headers)
                r.raise_for_status()
                return r.json().get("tags", [])
        except Exception as e:
            logger.warning("[registry] %s failed: %s", self.registry_name, e)
            return []

    async def resolve_latest(self, image: str) -> str | None:
        tags = _filter_tags(await self.list_tags(image))
        return sorted(tags, key=tag_sortkey, reverse=True)[0] if tags else None


# Harbor


class HarborRegistry(RegistryConnector):
    """Harbor v2 API — list artifacts and their tags."""

    registry_name = "harbor"

    def __init__(self, url: str = "", token: str = ""):
        self.base = url.rstrip("/") if url else ""
        self.token = token

    async def list_tags(self, image: str) -> list[str]:
        if not self.base:
            return []
        parts = image.split("/", 1)
        if len(parts) < 2:
            return []
        project, repo = parts[0], parts[1]
        url = f"{self.base}/api/v2.0/projects/{project}/repositories/{repo}/artifacts"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                headers: dict = {"Accept": "application/json"}
                if self.token:
                    headers["Authorization"] = f"Basic {self.token}"
                r = await c.get(url, headers=headers, params={"page_size": 50})
                r.raise_for_status()
                tags = []
                for artifact in r.json():
                    for t in artifact.get("tags", []):
                        tags.append(t["name"])
                return tags
        except Exception as e:
            logger.warning("[registry] %s failed: %s", self.registry_name, e)
            return []

    async def resolve_latest(self, image: str) -> str | None:
        tags = _filter_tags(await self.list_tags(image))
        return sorted(tags, key=tag_sortkey, reverse=True)[0] if tags else None
