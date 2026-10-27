# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Static plugin catalogue — capabilities × providers inventory.

Phase 1: read-only snapshot of what Constellation can talk to today.
Each category lists the providers that are wired in (`supported`) and the
ones on the roadmap (`planned`). The route layer augments each provider
with a live `configured_count` queried from the instance tables.
"""

from __future__ import annotations

CATEGORIES: list[dict] = [
    {
        "id": "forge",
        "name": "Git Forge",
        "description": "Source code hosting — repos, branches, webhooks.",
        "providers": [
            {"id": "gitea", "name": "Gitea", "status": "supported"},
            {"id": "forgejo", "name": "Forgejo", "status": "supported"},
            {"id": "gitlab", "name": "GitLab", "status": "supported"},
            {"id": "github", "name": "GitHub", "status": "planned"},
        ],
    },
    {
        "id": "ci",
        "name": "CI/CD",
        "description": "Pipeline execution — runners, triggers, status.",
        "providers": [
            {"id": "woodpecker", "name": "Woodpecker", "status": "supported"},
            {"id": "gitlab_ci", "name": "GitLab CI", "status": "supported"},
            {"id": "drone", "name": "Drone CI", "status": "planned"},
            {"id": "github_actions", "name": "GitHub Actions", "status": "planned"},
        ],
    },
    {
        "id": "registry",
        "name": "Container Registry",
        "description": "Image storage — tags, digests, version checks.",
        "providers": [
            {"id": "dockerhub", "name": "DockerHub", "status": "supported"},
            {"id": "ghcr", "name": "GHCR", "status": "supported"},
            {"id": "gitlab", "name": "GitLab Registry", "status": "supported"},
            {"id": "harbor", "name": "Harbor", "status": "supported"},
            {"id": "quay", "name": "Quay.io", "status": "planned"},
        ],
    },
    {
        "id": "container_manager",
        "name": "Container Manager",
        "description": "Orchestrator API — image pull, stack restart.",
        "providers": [
            {"id": "portainer", "name": "Portainer", "status": "supported"},
            {"id": "docker", "name": "Docker Engine (direct)", "status": "planned"},
            {"id": "kubernetes", "name": "Kubernetes", "status": "planned"},
        ],
    },
    {
        "id": "itsm",
        "name": "ITSM / Ticketing",
        "description": "Incident tickets — outbound push, inbound status sync.",
        "providers": [
            {"id": "glpi", "name": "GLPI", "status": "supported"},
            {"id": "zammad", "name": "Zammad", "status": "supported"},
            {"id": "jira", "name": "Jira Service Management", "status": "supported"},
            {"id": "servicenow", "name": "ServiceNow", "status": "planned"},
        ],
    },
    {
        "id": "notification",
        "name": "Notifications",
        "description": "Chat + webhook channels for alerts and automation.",
        "providers": [
            {"id": "matrix", "name": "Matrix", "status": "supported"},
            {"id": "email", "name": "Email (SMTP)", "status": "supported"},
            {"id": "mattermost", "name": "Mattermost", "status": "supported"},
            {"id": "rocketchat", "name": "Rocket.Chat", "status": "supported"},
            {"id": "slack", "name": "Slack", "status": "supported"},
            {"id": "discord", "name": "Discord", "status": "supported"},
            {"id": "ntfy", "name": "ntfy", "status": "supported"},
        ],
    },
    {
        "id": "cve_intel",
        "name": "CVE Intelligence",
        "description": "Vulnerability feeds + KEV enrichment.",
        "providers": [
            {"id": "opencve", "name": "OpenCVE", "status": "supported"},
            {"id": "cisa_kev", "name": "CISA KEV", "status": "supported"},
            {"id": "nvd", "name": "NVD (direct)", "status": "planned"},
        ],
    },
    {
        "id": "scanner",
        "name": "Vulnerability Scanners",
        "description": "CVE + misconfig + secret discovery on hosts and images.",
        "providers": [
            {"id": "trivy", "name": "Trivy", "status": "supported"},
            {"id": "wazuh", "name": "Wazuh", "status": "supported"},
            {"id": "grype", "name": "Grype", "status": "planned"},
        ],
    },
    {
        "id": "vault",
        "name": "Secrets Vault",
        "description": "Runtime secrets backend — sealed-by-default enforcement.",
        "providers": [
            {"id": "rhorizon", "name": "rhorizon", "status": "supported"},
        ],
    },
    {
        "id": "sso",
        "name": "SSO / Auth Proxy",
        "description": "Header-based identity via trusted reverse proxy.",
        "providers": [
            {"id": "authelia", "name": "Authelia", "status": "supported"},
            {"id": "authentik", "name": "Authentik", "status": "supported"},
            {"id": "keycloak", "name": "Keycloak", "status": "supported"},
        ],
    },
    {
        "id": "backup",
        "name": "Backup",
        "description": "Snapshot monitoring + alerting on failures.",
        "providers": [
            {"id": "restic", "name": "Restic", "status": "supported"},
            {"id": "borg", "name": "BorgBackup", "status": "planned"},
        ],
    },
    {
        "id": "secrets_detection",
        "name": "Secrets Detection",
        "description": "Leaked credentials in repos and containers.",
        "providers": [
            {
                "id": "trivy_secrets",
                "name": "Trivy (secret scan)",
                "status": "supported",
            },
            {"id": "trufflehog", "name": "TruffleHog", "status": "planned"},
            {"id": "gitleaks", "name": "Gitleaks", "status": "planned"},
        ],
    },
    {
        "id": "sbom",
        "name": "SBOM",
        "description": "Software bill of materials — component inventory.",
        "providers": [
            {"id": "trivy_sbom", "name": "Trivy (SBOM)", "status": "supported"},
            {"id": "syft", "name": "Syft", "status": "planned"},
        ],
    },
    {
        "id": "sca",
        "name": "SCA / Compliance",
        "description": "Security configuration assessment — CIS benchmarks.",
        "providers": [
            {"id": "wazuh_sca", "name": "Wazuh SCA", "status": "supported"},
            {"id": "openscap", "name": "OpenSCAP", "status": "planned"},
        ],
    },
    {
        "id": "misconfiguration",
        "name": "Misconfigurations",
        "description": (
            "IaC + runtime misconfig rules (Kubernetes, Dockerfile, Terraform…)."
        ),
        "providers": [
            {"id": "trivy_config", "name": "Trivy (config)", "status": "supported"},
            {"id": "kubescape", "name": "Kubescape", "status": "planned"},
            {"id": "checkov", "name": "Checkov", "status": "planned"},
        ],
    },
]


# Map (category_id, provider_id) → SQL count query. Tables/filters that don't
# exist return 0; the count query runs only when the row is reached.
# Shape: lambda db -> awaitable[int]
_COUNT_QUERIES: dict[tuple[str, str], tuple[str, dict]] = {
    ("forge", "gitea"): (
        "SELECT count(*) FROM cicd_servers WHERE server_type = 'gitea'",
        {},
    ),
    ("forge", "forgejo"): (
        "SELECT count(*) FROM cicd_servers WHERE server_type = 'forgejo'",
        {},
    ),
    ("forge", "gitlab"): (
        "SELECT count(*) FROM cicd_servers WHERE server_type = 'gitlab'",
        {},
    ),
    ("ci", "woodpecker"): (
        "SELECT count(*) FROM cicd_servers WHERE server_type = 'woodpecker'",
        {},
    ),
    ("ci", "gitlab_ci"): (
        "SELECT count(*) FROM cicd_servers WHERE server_type = 'gitlab'",
        {},
    ),
    ("registry", "dockerhub"): (
        "SELECT count(DISTINCT registry) FROM repositories"
        " WHERE registry = 'dockerhub'",
        {},
    ),
    ("registry", "ghcr"): (
        "SELECT count(DISTINCT registry) FROM repositories WHERE registry = 'ghcr'",
        {},
    ),
    ("registry", "gitlab"): (
        "SELECT count(DISTINCT registry) FROM repositories WHERE registry = 'gitlab'",
        {},
    ),
    ("registry", "harbor"): (
        "SELECT count(DISTINCT registry) FROM repositories WHERE registry = 'harbor'",
        {},
    ),
    ("container_manager", "portainer"): (
        "SELECT count(*) FROM container_managers",
        {},
    ),
    ("itsm", "glpi"): (
        "SELECT count(*) FROM itsm_integrations WHERE platform = 'glpi'",
        {},
    ),
    ("itsm", "zammad"): (
        "SELECT count(*) FROM itsm_integrations WHERE platform = 'zammad'",
        {},
    ),
    ("itsm", "jira"): (
        "SELECT count(*) FROM itsm_integrations WHERE platform = 'jira'",
        {},
    ),
    ("notification", "mattermost"): (
        "SELECT count(*) FROM notification_webhooks WHERE platform = 'mattermost'",
        {},
    ),
    ("notification", "rocketchat"): (
        "SELECT count(*) FROM notification_webhooks WHERE platform = 'rocketchat'",
        {},
    ),
    ("notification", "slack"): (
        "SELECT count(*) FROM notification_webhooks WHERE platform = 'slack'",
        {},
    ),
    ("notification", "discord"): (
        "SELECT count(*) FROM notification_webhooks WHERE platform = 'discord'",
        {},
    ),
    ("notification", "ntfy"): (
        "SELECT count(*) FROM notification_webhooks WHERE platform = 'ntfy'",
        {},
    ),
}


def catalogue() -> list[dict]:
    """Return a deep-copyable snapshot of the static catalogue."""
    return [
        {**cat, "providers": [dict(p) for p in cat["providers"]]} for cat in CATEGORIES
    ]


def count_query(category_id: str, provider_id: str) -> tuple[str, dict] | None:
    """Return the (sql, params) pair for a provider, or None if not tracked."""
    return _COUNT_QUERIES.get((category_id, provider_id))


def summary(cats: list[dict]) -> dict:
    """Aggregate counts across the catalogue for the UI header."""
    total = 0
    supported = 0
    planned = 0
    configured = 0
    for cat in cats:
        for p in cat["providers"]:
            total += 1
            if p["status"] == "supported":
                supported += 1
            elif p["status"] == "planned":
                planned += 1
            if p.get("configured_count", 0) > 0:
                configured += 1
    return {
        "categories": len(cats),
        "providers_total": total,
        "providers_supported": supported,
        "providers_planned": planned,
        "providers_configured": configured,
    }
