# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from datetime import datetime

from pydantic import BaseModel

# Collect (Ansible → API)


class NodeReport(BaseModel):
    hostname: str
    type: str | list[str] = "vm"
    os: str = ""
    os_version: str = ""
    arch: str = ""
    kernel: str = ""
    os_raw: str = ""
    hw_info: dict | str = "{}"
    ip_address: str | None = None
    packages: list[str] = []
    containers: list[str | dict] = []
    host_geoip: str | None = None
    host_firewall: str | None = None


class NodesBatchReport(BaseModel):
    items: list[NodeReport]


# Backup


class BackupReport(BaseModel):
    hostname: str
    node_hostname: str | None = None  # CMDB hostname if different from backup hostname
    repo_name: str = "default"
    repo_path: str = ""
    sftp_host: str | None = None
    sftp_user: str | None = None
    status: str = "unknown"
    files_new: int = 0
    files_changed: int = 0
    files_unmodified: int = 0
    size_added: int = 0
    size_total: int = 0
    snapshots_total: int = 0
    duration_secs: int = 0
    source: str = "script"
    error_msg: str | None = None
    started_at: str | None = None
    raw: dict = {}


# CVE Report


class CVEReport(BaseModel):
    hostname: str
    source: str = "trivy"
    target_type: str = "package"
    target_name: str = ""
    image: str | None = None
    vulnerabilities: list[dict] = []


# Responses


class NodeOut(BaseModel):
    id: str
    hostname: str
    type: str
    os: str | None = None
    os_version: str | None = None
    kernel: str | None = None
    last_seen: datetime | None = None
    is_active: bool = True
    package_count: int = 0
    container_count: int = 0
    cve_package_count: int = 0
    cve_package_critical: int = 0
    cve_container_count: int = 0
    cve_container_critical: int = 0
    cve_critical_count: int = 0


class PaginatedResponse(BaseModel):
    items: list = []
    total: int = 0
    page: int = 1
    per_page: int = 50


class StatsOut(BaseModel):
    nodes_total: int = 0
    nodes_active: int = 0
    packages_total: int = 0
    containers_total: int = 0
    cves_critical: int = 0
    cves_high: int = 0
    cves_total: int = 0
    backups_ok: int = 0
    backups_failed: int = 0
    backups_overdue: int = 0


# Findings PATCH

_STATUSES = ("open", "mitigated", "ignored", "resolved")
_FIX_STATUSES = (
    "fixed_available",
    "unfixed",
    "not_affected",
    "under_investigation",
)
_CONTEXTS = (
    "likely_exploitable",
    "requires_auth",
    "requires_local_access",
    "requires_user_interaction",
    "unclear",
)
_ENVIRONMENTS = ("production", "staging", "development", "lab")
_WORKFLOW = (
    "open",
    "acknowledged",
    "in_progress",
    "mitigated",
    "resolved",
    "false_positive",
    "accepted_risk",
)
_LISTEN = ("internet", "private_network", "localhost", "docker_internal")
_TRIGGERS = (
    "cve_detected",
    "update_available",
    "backup_overdue",
    "scan_stale",
    "exposure_change",
    "misconf_detected",
    "pipeline_failure",
    "deploy_requested",
    "worker_offline",
    "image_update_available",
    "drift_detected",
)
_ACTIONS = (
    "notify",
    "auto_update",
    "manual_validation",
    "rescan",
    "ignore",
    "create_deployment",
    "pull_image",
)
_DEPLOY_TYPES = (
    "package_upgrade",
    "container_build",
    "container_deploy",
    "ansible_playbook",
    "image_pull",
)
_DEPLOY_STATUSES = (
    "draft",
    "pending",
    "approved",
    "running",
    "success",
    "failure",
    "cancelled",
)


class FindingPatch(BaseModel):
    status: str | None = None
    fix_status: str | None = None
    exploited: bool | None = None
    exploitability_context: str | None = None


class EnvironmentPatch(BaseModel):
    environment: str


class WorkflowPatch(BaseModel):
    node_id: str
    status: str
    note: str | None = None
    justification: str | None = None


class RepoPatch(BaseModel):
    listen: str | None = None
    auto_update_candidate: bool | None = None
    project_name: str | None = None
    latest_tag_available: str | None = None
    registry: str | None = None
    image_name: str | None = None


class RepoCreate(BaseModel):
    project_name: str | None = None
    image_name: str
    registry: str = "dockerhub"
    current_tag: str | None = None
    auto_update_candidate: bool = False
    listen: str = "docker_internal"


class PolicyCreate(BaseModel):
    name: str
    trigger_type: str
    action: str
    description: str | None = None
    priority: int = 0
    enabled: bool = True
    match_hostname: str | None = None
    match_container: str | None = None
    match_image: str | None = None
    match_package: str | None = None
    match_cve_id: str | None = None
    match_severity: list[str] | None = None
    match_environment: list[str] | None = None
    match_exposure: list[str] | None = None
    notify_channels: list[str] = ["matrix"]
    notify_room: str | None = None
    auto_execute: bool = False
    config: dict = {}


class PolicyPatch(BaseModel):
    name: str | None = None
    trigger_type: str | None = None
    action: str | None = None
    description: str | None = None
    priority: int | None = None
    enabled: bool | None = None
    match_hostname: str | None = None
    match_container: str | None = None
    match_image: str | None = None
    match_package: str | None = None
    match_cve_id: str | None = None
    match_severity: list[str] | None = None
    match_environment: list[str] | None = None
    match_exposure: list[str] | None = None
    notify_channels: list[str] | None = None
    notify_room: str | None = None
    auto_execute: bool | None = None
    config: dict | None = None


class PolicyTest(BaseModel):
    trigger_type: str
    hostname: str | None = None
    container: str | None = None
    image: str | None = None
    package: str | None = None
    cve_id: str | None = None
    severity: str | None = None
    environment: str | None = None
    exposure: str | None = None


class SubscriptionCreate(BaseModel):
    vendor: str
    product: str


# Drift


class DriftReport(BaseModel):
    hostname: str
    items: list[dict] = []
    source: str = "ansible"


class DriftPatch(BaseModel):
    status: str


# CI/CD Deployments


class DeploymentCreate(BaseModel):
    title: str
    deploy_type: str
    worker_hostname: str | None = None
    repo_name: str | None = None
    branch: str = "main"
    manager_id: str | None = None
    config: dict = {}


class DeploymentPatch(BaseModel):
    title: str | None = None
    worker_hostname: str | None = None
    repo_name: str | None = None
    branch: str | None = None
    manager_id: str | None = None
    config: dict | None = None


class PipelineTrigger(BaseModel):
    repo_name: str
    branch: str = "main"
    variables: dict = {}


# Container Managers


class ManagerCreate(BaseModel):
    name: str
    manager_type: str = "portainer"
    url: str
    token: str | None = None
    endpoint_id: int = 1
    tls_skip_verify: bool = False
    node_id: str | None = None


class ManagerPatch(BaseModel):
    name: str | None = None
    url: str | None = None
    token: str | None = None
    endpoint_id: int | None = None
    tls_skip_verify: bool | None = None
    node_id: str | None = None


class ImagePull(BaseModel):
    image: str
    tag: str = "latest"


# CVE Cleanup


class CleanupExecute(BaseModel):
    action: str  # resolve, ignore, delete
    severity: str | None = None
    target_type: str | None = None
    fix_status: str | None = None
    older_than_days: int | None = None
    exploited: bool | None = None
    status: str = "open"
    os: str | None = None
    arch: str | None = None
    node_id: str | None = None
    pkg_name: str | None = None
    ids: list[str] | None = None  # specific finding IDs to act on


# Scheduler

_JOB_TYPES = ("woodpecker_pipeline", "gitlab_pipeline", "http_request")
_RUN_STATUSES = ("running", "success", "failure", "timeout", "skipped")


class SchedulerJobCreate(BaseModel):
    name: str
    description: str | None = None
    job_type: str
    cron_expr: str
    timezone: str = "UTC"
    config: dict = {}
    timeout_secs: int = 300
    max_retries: int = 0
    retry_delay_secs: int = 60
    allow_overlap: bool = False
    enabled: bool = False


class SchedulerJobPatch(BaseModel):
    name: str | None = None
    description: str | None = None
    job_type: str | None = None
    cron_expr: str | None = None
    timezone: str | None = None
    config: dict | None = None
    timeout_secs: int | None = None
    max_retries: int | None = None
    retry_delay_secs: int | None = None
    allow_overlap: bool | None = None
    enabled: bool | None = None


# Notification Webhooks

_WEBHOOK_PLATFORMS = (
    "mattermost",
    "rocketchat",
    "slack",
    "discord",
    "ntfy",
    "gotify",
    "generic",
)


class WebhookCreate(BaseModel):
    name: str
    platform: str = "generic"
    webhook_url: str
    enabled: bool = True
    route_cve: bool = True
    route_security: bool = True
    route_cicd: bool = True
    route_backup: bool = True
    default_channel: str | None = None
    channel_cve: str | None = None
    channel_security: str | None = None
    channel_cicd: str | None = None
    channel_backup: str | None = None


# Incidents


class IncidentCreate(BaseModel):
    title: str
    description: str | None = None
    cve_id: str | None = None
    affected_asset: str | None = None
    affected_package: str | None = None
    severity: str | None = None
    environment: str | None = None
    exposure: str | None = None
    cvss: float | None = None
    in_kev: bool | None = None
    assignee: str | None = None


class IncidentPatch(BaseModel):
    status: str | None = None
    priority: str | None = None
    assignee: str | None = None
    description: str | None = None
    close_reason: str | None = None


class IncidentCommentBody(BaseModel):
    body: str


class PriorityRule(BaseModel):
    name: str
    priority: str
    conditions: dict = {}


class PriorityRuleSetCreate(BaseModel):
    name: str
    description: str | None = None
    rules: list[PriorityRule]


class WebhookPatch(BaseModel):
    name: str | None = None
    platform: str | None = None
    webhook_url: str | None = None
    enabled: bool | None = None
    route_cve: bool | None = None
    route_security: bool | None = None
    route_cicd: bool | None = None
    route_backup: bool | None = None
    default_channel: str | None = None
    channel_cve: str | None = None
    channel_security: str | None = None
    channel_cicd: str | None = None
    channel_backup: str | None = None


# ITSM integrations


class ITSMIntegrationCreate(BaseModel):
    name: str
    platform: str
    base_url: str
    auth_config: dict = {}
    project_key: str | None = None
    enabled: bool = True
    sync_outbound: bool = True
    sync_inbound: bool = False
    webhook_secret: str | None = None
    status_map: dict = {}


class ITSMIntegrationPatch(BaseModel):
    name: str | None = None
    platform: str | None = None
    base_url: str | None = None
    auth_config: dict | None = None
    project_key: str | None = None
    enabled: bool | None = None
    sync_outbound: bool | None = None
    sync_inbound: bool | None = None
    webhook_secret: str | None = None
    status_map: dict | None = None


# Settings — typed payloads for /settings/* endpoints.
# Fields stay optional with their pre-existing defaults so the routes'
# manual validation (HTTPException 400 on missing required fields) still
# fires — no behavioural change versus the bare-`dict` signatures.


class SsoGroupsPayload(BaseModel):
    """PUT /settings/sso-groups."""

    mappings: dict[str, str] = {}


class FeatureTogglePayload(BaseModel):
    """POST /settings/features/toggle."""

    feature: str = ""
    enabled: bool | None = None
    confirm: str = ""


class VaultCheckPayload(BaseModel):
    """POST /settings/vault-check."""

    vault_url: str = ""


class VaultBootstrapPayload(BaseModel):
    """POST /settings/vault/bootstrap."""

    vault_url: str | None = None
    vault_token: str | None = None
    namespace: str = "cmdb"
