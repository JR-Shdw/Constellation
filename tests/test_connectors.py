"""Connector factories coverage — get_forge, get_ci, get_registry."""

import pytest


def test_get_forge_gitea():
    """get_forge returns GiteaForge for gitea."""
    from api.app.connectors import get_forge
    from api.app.connectors.gitea import GiteaForge

    forge = get_forge("gitea", "https://gitea.example.com", "token")
    assert isinstance(forge, GiteaForge)


def test_get_forge_forgejo():
    """get_forge returns ForgejoForge for forgejo."""
    from api.app.connectors import get_forge
    from api.app.connectors.forgejo import ForgejoForge

    forge = get_forge("forgejo", "https://forgejo.example.com", "token")
    assert isinstance(forge, ForgejoForge)


def test_get_forge_gitlab():
    """get_forge returns GitLabForge for gitlab."""
    from api.app.connectors import get_forge
    from api.app.connectors.gitlab import GitLabForge

    forge = get_forge("gitlab", "https://gitlab.example.com", "token")
    assert isinstance(forge, GitLabForge)


def test_get_forge_invalid():
    """get_forge raises ValueError for unknown type."""
    from api.app.connectors import get_forge

    with pytest.raises(ValueError, match="Unknown forge type"):
        get_forge("github", "https://github.com", "token")


def test_get_ci_woodpecker():
    """get_ci returns WoodpeckerCI for woodpecker."""
    from api.app.connectors import get_ci
    from api.app.connectors.woodpecker import WoodpeckerCI

    ci = get_ci("woodpecker", "https://ci.example.com", "token")
    assert isinstance(ci, WoodpeckerCI)


def test_get_ci_gitlab():
    """get_ci returns GitLabCI for gitlab."""
    from api.app.connectors import get_ci
    from api.app.connectors.gitlab_ci import GitLabCI

    ci = get_ci("gitlab", "https://gitlab.example.com", "token")
    assert isinstance(ci, GitLabCI)


def test_get_ci_invalid():
    """get_ci raises ValueError for unknown type."""
    from api.app.connectors import get_ci

    with pytest.raises(ValueError, match="Unknown CI type"):
        get_ci("jenkins", "https://jenkins.com", "token")


def test_get_registry_dockerhub():
    """get_registry returns DockerHubRegistry for dockerhub."""
    from api.app.connectors import get_registry

    reg = get_registry("dockerhub")
    assert reg is not None


def test_get_registry_ghcr():
    """get_registry returns GHCRRegistry for ghcr."""
    from api.app.connectors import get_registry

    reg = get_registry("ghcr")
    assert reg is not None


def test_get_registry_invalid():
    """get_registry raises ValueError for unknown type."""
    from api.app.connectors import get_registry

    with pytest.raises(ValueError, match="Unknown registry"):
        get_registry("ecr")


# ABC interface tests


def test_forge_abc_methods():
    """ForgeConnector ABC has required method signatures."""
    from api.app.connectors.forge import ForgeConnector

    assert hasattr(ForgeConnector, "list_repos")
    assert hasattr(ForgeConnector, "get_branches")
    assert hasattr(ForgeConnector, "has_ci_config")


def test_ci_abc_methods():
    """CIConnector ABC has required method signatures."""
    from api.app.connectors.ci import CIConnector

    assert hasattr(CIConnector, "list_runners")
    assert hasattr(CIConnector, "list_pipelines")
    assert hasattr(CIConnector, "trigger_pipeline")
