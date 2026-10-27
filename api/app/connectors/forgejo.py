# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Forgejo forge connector — API compatible with Gitea v1."""

from .gitea import GiteaForge


class ForgejoForge(GiteaForge):
    """Forgejo — inherits GiteaForge since API v1 is identical."""

    forge_name = "forgejo"
