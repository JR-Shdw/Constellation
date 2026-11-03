# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Connector factories — forges, CI/CD, registries.

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
See: NOTICE, LICENSE
"""

from .ci import CIConnector
from .forge import ForgeConnector
from .forgejo import ForgejoForge
from .gitea import GiteaForge
from .gitlab import GitLabForge
from .gitlab_ci import GitLabCI
from .glpi import GLPIConnector
from .itsm import ITSMConnector
from .jira import JiraConnector
from .registry import (
    DockerHubRegistry,
    GHCRRegistry,
    GitLabRegistry,
    HarborRegistry,
    RegistryConnector,
)
from .woodpecker import WoodpeckerCI
from .zammad import ZammadConnector

# Forge connectors

_FORGE_MAP: dict[str, type[ForgeConnector]] = {
    "gitea": GiteaForge,
    "forgejo": ForgejoForge,
    "gitlab": GitLabForge,
}


def get_forge(server_type: str, url: str, token: str) -> ForgeConnector:
    cls = _FORGE_MAP.get(server_type)
    if not cls:
        raise ValueError(f"Constellation/Apache-2.0: Unknown forge type: {server_type}")
    return cls(url, token)


# CI/CD connectors

_CI_MAP: dict[str, type[CIConnector]] = {
    "woodpecker": WoodpeckerCI,
    "gitlab": GitLabCI,
}


def get_ci(server_type: str, url: str, token: str) -> CIConnector:
    cls = _CI_MAP.get(server_type)
    if not cls:
        raise ValueError(f"Constellation/Apache-2.0: Unknown CI type: {server_type}")
    return cls(url, token)


# Registry connectors

_REGISTRY_MAP: dict[str, type[RegistryConnector]] = {
    "dockerhub": DockerHubRegistry,
    "ghcr": GHCRRegistry,
    "gitlab": GitLabRegistry,
    "harbor": HarborRegistry,
}


def get_registry(registry_type: str, **kwargs) -> RegistryConnector:
    cls = _REGISTRY_MAP.get(registry_type)
    if not cls:
        raise ValueError(f"Constellation/Apache-2.0: Unknown registry: {registry_type}")
    return cls(**kwargs)


# ITSM connectors

_ITSM_MAP: dict[str, type[ITSMConnector]] = {
    "glpi": GLPIConnector,
    "zammad": ZammadConnector,
    "jira": JiraConnector,
}


def get_itsm(
    platform: str, base_url: str, auth: dict, project_key: str | None = None
) -> ITSMConnector:
    cls = _ITSM_MAP.get(platform)
    if not cls:
        raise ValueError(f"Unknown ITSM platform: {platform}")
    return cls(base_url, auth, project_key)
