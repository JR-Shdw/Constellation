-- DO NOT REMOVE: SPDX header + copyright are part of the Apache-2.0 license terms.
-- Stripping or rewriting these notices on redistribution is a license violation.
-- Project: Constellation · Author: shdw <contact@resurgamus.com> · License: Apache-2.0
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
-- CMDB — Schema PostgreSQL
-- Idempotent: safe to run on fresh or existing DB
-- Order: DROP all views → CREATE tables → CREATE indexes → CREATE views

-- ══════════════════════════════════════════════════════════════
-- DROP ALL VIEWS (clean slate for column changes)
-- ══════════════════════════════════════════════════════════════
DROP VIEW IF EXISTS v_scheduler_summary CASCADE;
DROP VIEW IF EXISTS v_deployment_summary CASCADE;
DROP VIEW IF EXISTS v_cicd_workers_status CASCADE;
DROP VIEW IF EXISTS v_cicd_stats_30d CASCADE;
DROP VIEW IF EXISTS v_cicd_latest CASCADE;
DROP VIEW IF EXISTS v_opencve_impact CASCADE;
DROP VIEW IF EXISTS v_compliance_summary CASCADE;
DROP VIEW IF EXISTS v_exposure_summary CASCADE;
DROP VIEW IF EXISTS v_backup_alerts CASCADE;
DROP VIEW IF EXISTS v_backup_missing CASCADE;
DROP VIEW IF EXISTS v_backup_stats_30d CASCADE;
DROP VIEW IF EXISTS v_backup_latest CASCADE;
DROP VIEW IF EXISTS v_scan_status CASCADE;
DROP VIEW IF EXISTS v_node_summary CASCADE;
-- v_all_cves may exist as a materialized view from a previous upgrade — drop it that way
DO $do$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'v_all_cves') THEN
        EXECUTE 'DROP MATERIALIZED VIEW v_all_cves CASCADE';
    ELSE
        EXECUTE 'DROP VIEW IF EXISTS v_all_cves CASCADE';
    END IF;
END $do$;

-- 2026-05-13: available_ver moves from packages (per-node) to
-- package_availability (per OS profile). Drop the legacy column if it
-- still exists from a pre-mutualisation DB.
ALTER TABLE IF EXISTS packages DROP COLUMN IF EXISTS available_ver;

-- ══════════════════════════════════════════════════════════════
-- NODES
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS nodes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname    TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL DEFAULT 'vm',
    os          TEXT,
    os_version  TEXT,
    arch        TEXT,
    kernel      TEXT,
    os_raw      TEXT,
    hw_info     JSONB DEFAULT '{}',
    tags        TEXT[] DEFAULT '{}',
    first_seen  TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ DEFAULT NOW(),
    is_active   BOOLEAN DEFAULT true,
    environment TEXT DEFAULT 'production'
        CHECK (environment IN ('production','staging','development','lab')),
    last_trivy_host_scan  TIMESTAMPTZ,
    last_trivy_image_scan TIMESTAMPTZ,
    last_trivy_config_scan TIMESTAMPTZ,
    last_wazuh_scan       TIMESTAMPTZ,
    ip_address            TEXT,
    check_address         TEXT,
    last_heartbeat        TIMESTAMPTZ,
    heartbeat_status      TEXT DEFAULT 'unknown'
        CHECK (heartbeat_status IN ('up','down','unknown'))
);

-- Migration: add scan tracking columns to existing nodes table
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_trivy_host_scan  TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_trivy_image_scan TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_trivy_config_scan TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_wazuh_scan       TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS ip_address            TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS check_address         TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_heartbeat        TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS heartbeat_status      TEXT DEFAULT 'unknown';

CREATE INDEX IF NOT EXISTS idx_nodes_hostname ON nodes (hostname);
CREATE INDEX IF NOT EXISTS idx_nodes_type     ON nodes (type);
CREATE INDEX IF NOT EXISTS idx_nodes_active   ON nodes (is_active);
CREATE INDEX IF NOT EXISTS idx_nodes_env      ON nodes (environment);

-- ══════════════════════════════════════════════════════════════
-- PACKAGES
-- ══════════════════════════════════════════════════════════════

-- ══════════════════════════════════════════════════════════════
-- PACKAGE CATALOG — reference table (one row per name:version)
-- openssl 3.0.11 stored once instead of N×hosts
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS package_catalog (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    version      TEXT NOT NULL,
    arch         TEXT,
    manager      TEXT DEFAULT 'apt',
    first_seen   TIMESTAMPTZ DEFAULT NOW(),
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(name, version)
);

CREATE INDEX IF NOT EXISTS idx_pkgcat_name ON package_catalog (name);

-- ══════════════════════════════════════════════════════════════
-- PACKAGES — per-node instances (references package_catalog)
-- Pure (node ↔ catalog) link table. Available versions live in
-- package_availability below, mutualised at the OS-profile level.
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS packages (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id      UUID REFERENCES nodes(id) ON DELETE CASCADE,
    package_id   UUID NOT NULL REFERENCES package_catalog(id) ON DELETE CASCADE,
    collected_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_id, package_id)
);

CREATE INDEX IF NOT EXISTS idx_packages_node    ON packages (node_id);
CREATE INDEX IF NOT EXISTS idx_packages_pkg     ON packages (package_id);

-- ══════════════════════════════════════════════════════════════
-- PACKAGE_AVAILABILITY — mutualised "available version" per OS profile.
-- One row per (package, os_family, os_version, arch) regardless of how
-- many nodes share that profile. Replaces the pre-2026-05-13 per-node
-- packages.available_ver, which caused N×M UPDATE storms during
-- check-updates and the saturation incident that motivated this change.
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS package_availability (
    package_id    UUID NOT NULL REFERENCES package_catalog(id) ON DELETE CASCADE,
    os_family     TEXT NOT NULL,
    os_version    TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    available_ver TEXT NOT NULL,
    checked_at    TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (package_id, os_family, os_version, arch)
);

CREATE INDEX IF NOT EXISTS idx_pkgavail_pkg
    ON package_availability (package_id);
CREATE INDEX IF NOT EXISTS idx_pkgavail_profile
    ON package_availability (os_family, os_version, arch);

-- Shared OS family normaliser — keeps Python (_detect_os_family) and SQL
-- joins in sync. IMMUTABLE so the planner can use it in indexes/joins.
CREATE OR REPLACE FUNCTION cmdb_os_family(os_name TEXT) RETURNS TEXT AS $$
    SELECT CASE
        WHEN os_name IS NULL THEN NULL
        WHEN lower(os_name) LIKE '%debian%'   THEN 'debian'
        WHEN lower(os_name) LIKE '%ubuntu%'   THEN 'ubuntu'
        WHEN lower(os_name) LIKE '%arch%'
          OR lower(os_name) LIKE '%manjaro%'  THEN 'archlinux'
        WHEN lower(os_name) LIKE '%rocky%'    THEN 'rocky'
        WHEN lower(os_name) LIKE '%centos%'   THEN 'centos'
        WHEN lower(os_name) LIKE '%fedora%'   THEN 'fedora'
        WHEN lower(os_name) LIKE '%rhel%'     THEN 'rhel'
        WHEN lower(os_name) LIKE '%aix%'      THEN 'aix'
        ELSE NULL
    END;
$$ LANGUAGE SQL IMMUTABLE;

-- ══════════════════════════════════════════════════════════════
-- CONTAINER IMAGES — reference table (one row per image:tag)
-- traefik:v3.0 stored once instead of N×hosts
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS container_images (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image        TEXT NOT NULL,
    tag          TEXT NOT NULL DEFAULT 'latest',
    first_seen   TIMESTAMPTZ DEFAULT NOW(),
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(image, tag)
);

CREATE INDEX IF NOT EXISTS idx_cimg_image ON container_images (image);

-- ══════════════════════════════════════════════════════════════
-- CONTAINERS — per-node instances (references container_images)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS containers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id       UUID REFERENCES nodes(id) ON DELETE CASCADE,
    image_id      UUID NOT NULL REFERENCES container_images(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    status        TEXT,
    ports         TEXT,
    digest        TEXT,
    networks      JSONB DEFAULT '[]',
    port_bindings JSONB DEFAULT '[]',
    labels        JSONB DEFAULT '{}',
    exposure      TEXT DEFAULT 'unknown'
        CHECK (exposure IN ('internet','vpn','private','wireguard','docker_internal','localhost','none','unknown')),
    traefik       BOOLEAN DEFAULT false,
    authelia      BOOLEAN DEFAULT false,
    geoip         BOOLEAN DEFAULT false,
    firewall      BOOLEAN DEFAULT false,
    collected_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_id, name)
);

-- Manual override timestamps: when non-NULL, /nodes/report keeps the manual value.
-- exposure_manual_at locks `exposure`; flags_manual_at locks the 4 booleans.
ALTER TABLE containers ADD COLUMN IF NOT EXISTS exposure_manual_at TIMESTAMPTZ;
ALTER TABLE containers ADD COLUMN IF NOT EXISTS flags_manual_at    TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_containers_node     ON containers (node_id);
CREATE INDEX IF NOT EXISTS idx_containers_image_id ON containers (image_id);
CREATE INDEX IF NOT EXISTS idx_containers_exposure ON containers (exposure);

-- ══════════════════════════════════════════════════════════════
-- CVE CATALOG — reference table (one row per CVE worldwide)
-- Eliminates duplication: CVE-2024-1234 metadata stored once
-- instead of N×hosts × M×packages
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cve_catalog (
    cve_id                TEXT PRIMARY KEY,
    cvss_score            NUMERIC(4,1),
    description           TEXT,
    exploited             BOOLEAN DEFAULT false,
    exploitability_context TEXT DEFAULT 'unclear'
        CHECK (exploitability_context IN (
            'likely_exploitable','requires_auth','requires_local_access',
            'requires_user_interaction','unclear'
        )),
    kev                   BOOLEAN DEFAULT false,
    cwe_ids               TEXT[],
    first_seen            TIMESTAMPTZ DEFAULT NOW(),
    last_updated          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cvecat_exploited ON cve_catalog (cve_id) WHERE exploited = true;
CREATE INDEX IF NOT EXISTS idx_cvecat_kev       ON cve_catalog (cve_id) WHERE kev = true;

-- ══════════════════════════════════════════════════════════════
-- CVE FINDINGS — per-node, per-package detections
-- Severity kept here (distro-specific, may differ from NVD)
-- CVE-level metadata (cvss, description, exploited) → cve_catalog
-- ══════════════════════════════════════════════════════════════

-- CVE paquets OS (source : Wazuh Syscollector / Trivy)
CREATE TABLE IF NOT EXISTS cve_host_packages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         UUID REFERENCES nodes(id) ON DELETE CASCADE,
    cve_id          TEXT NOT NULL REFERENCES cve_catalog(cve_id) ON DELETE CASCADE,
    severity        TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    pkg_name        TEXT NOT NULL,
    installed_ver   TEXT NOT NULL DEFAULT '',
    fixed_ver       TEXT,
    fix_status      TEXT DEFAULT 'unfixed'
        CHECK (fix_status IN ('fixed_available','unfixed','not_affected','under_investigation','will_not_fix')),
    status          TEXT DEFAULT 'open'
        CHECK (status IN ('open','mitigated','ignored','resolved')),
    source          TEXT DEFAULT 'wazuh',
    raw             JSONB,
    scanned_at      TIMESTAMPTZ DEFAULT NOW(),
    -- Score contextuel materialise (cve_score), maintenu a l'ecriture —
    -- voir api/app/utils/scoring.py pour les invalidations.
    score           SMALLINT,
    UNIQUE(node_id, cve_id, pkg_name)
);
ALTER TABLE cve_host_packages ADD COLUMN IF NOT EXISTS score SMALLINT;

CREATE INDEX IF NOT EXISTS idx_cve_hp_node     ON cve_host_packages (node_id);
CREATE INDEX IF NOT EXISTS idx_cve_hp_cve      ON cve_host_packages (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_hp_severity ON cve_host_packages (severity);
CREATE INDEX IF NOT EXISTS idx_cve_hp_pkg      ON cve_host_packages (pkg_name, installed_ver);
CREATE INDEX IF NOT EXISTS idx_cve_hp_status     ON cve_host_packages (status);
CREATE INDEX IF NOT EXISTS idx_cve_hp_fix_status ON cve_host_packages (fix_status);
CREATE INDEX IF NOT EXISTS idx_cve_hp_source     ON cve_host_packages (source);
CREATE INDEX IF NOT EXISTS idx_cve_hp_src_scan ON cve_host_packages (source, node_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_hp_scan     ON cve_host_packages (node_id, scanned_at DESC);
-- Composite for v_node_summary chp-aggregate (COUNT per node filtered by severity).
-- Without this, 10k nodes × 30 pkgs × severity filter = full table scan at stats refresh.
CREATE INDEX IF NOT EXISTS idx_cve_hp_node_severity ON cve_host_packages (node_id, severity);
-- Serves /cves default sort (ORDER BY score DESC LIMIT n) as an index walk.
CREATE INDEX IF NOT EXISTS idx_cve_hp_status_score ON cve_host_packages (status, score DESC);
-- Partial index: makes the startup backfill probe (WHERE score IS NULL) O(1)
-- once the backfill has run — empty index, no seq scan per boot.
CREATE INDEX IF NOT EXISTS idx_cve_hp_score_null ON cve_host_packages (id) WHERE score IS NULL;

-- Snapshot churn: collect delete/reinserts the open findings every scan, and
-- write-side rescore (scoring.py) updates the indexed `score` column (non-HOT).
-- Default autovacuum (20% dead) lags at scale -> table + (status,score) index
-- bloat and stale planner stats. Tighten thresholds for this table only.
ALTER TABLE cve_host_packages SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.05,
    autovacuum_vacuum_cost_limit = 1000
);

-- CVE containers (source : Trivy)
CREATE TABLE IF NOT EXISTS cve_containers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id    UUID REFERENCES containers(id) ON DELETE CASCADE,
    node_id         UUID REFERENCES nodes(id) ON DELETE CASCADE,
    cve_id          TEXT NOT NULL REFERENCES cve_catalog(cve_id) ON DELETE CASCADE,
    severity        TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    pkg_name        TEXT NOT NULL,
    pkg_type        TEXT,
    installed_ver   TEXT NOT NULL DEFAULT '',
    fixed_ver       TEXT,
    fix_status      TEXT DEFAULT 'unfixed'
        CHECK (fix_status IN ('fixed_available','unfixed','not_affected','under_investigation','will_not_fix')),
    status          TEXT DEFAULT 'open'
        CHECK (status IN ('open','mitigated','ignored','resolved')),
    image           TEXT,
    secret_type     TEXT,
    secret_match    TEXT,
    sbom_ref        TEXT,
    layer_digest    TEXT,
    target          TEXT,
    raw             JSONB,
    scanned_at      TIMESTAMPTZ DEFAULT NOW(),
    -- Score contextuel materialise (cve_score), maintenu a l'ecriture —
    -- voir api/app/utils/scoring.py pour les invalidations.
    score           SMALLINT
);
ALTER TABLE cve_containers ADD COLUMN IF NOT EXISTS score SMALLINT;

-- Unique fonctionnel : meme CVE + meme paquet + meme image + meme container (ou NULL).
-- 2026-06-12: image ajoutee a la cle — sans elle, la meme CVE+paquet sur deux
-- images distinctes d'un node s'ecrasait en une seule ligne (la 2e etait perdue
-- par le ON CONFLICT). L'ancien index plus strict est droppe explicitement.
DROP INDEX IF EXISTS idx_cve_ct_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_ct_unique_img
    ON cve_containers (node_id, cve_id, pkg_name, COALESCE(image, ''),
                       COALESCE(container_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE INDEX IF NOT EXISTS idx_cve_ct_node     ON cve_containers (node_id);
CREATE INDEX IF NOT EXISTS idx_cve_ct_cve      ON cve_containers (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_ct_severity ON cve_containers (severity);
CREATE INDEX IF NOT EXISTS idx_cve_ct_pkg      ON cve_containers (pkg_name, installed_ver);
CREATE INDEX IF NOT EXISTS idx_cve_ct_type     ON cve_containers (pkg_type);
CREATE INDEX IF NOT EXISTS idx_cve_ct_image    ON cve_containers (image);
CREATE INDEX IF NOT EXISTS idx_cve_ct_status     ON cve_containers (status);
CREATE INDEX IF NOT EXISTS idx_cve_ct_fix_status ON cve_containers (fix_status);
CREATE INDEX IF NOT EXISTS idx_cve_ct_scan       ON cve_containers (node_id, scanned_at DESC);
-- Serves /cves default sort (ORDER BY score DESC LIMIT n) as an index walk.
CREATE INDEX IF NOT EXISTS idx_cve_ct_status_score ON cve_containers (status, score DESC);
-- Partial index: makes the startup backfill probe (WHERE score IS NULL) O(1).
CREATE INDEX IF NOT EXISTS idx_cve_ct_score_null ON cve_containers (id) WHERE score IS NULL;

-- Same snapshot churn as cve_host_packages (see note above) — tighten autovacuum.
ALTER TABLE cve_containers SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.05,
    autovacuum_vacuum_cost_limit = 1000
);

-- ══════════════════════════════════════════════════════════════
-- MISCONFIGURATION RULES — reference table (one row per rule)
-- DS001 "Don't use root" metadata stored once instead of N×hosts
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS misconf_rules (
    rule_id     TEXT PRIMARY KEY,
    rule_title  TEXT,
    severity    TEXT CHECK (severity IN ('critical','high','medium','low','unknown')),
    message     TEXT,
    resolution  TEXT,
    source      TEXT DEFAULT 'trivy',
    first_seen  TIMESTAMPTZ DEFAULT NOW(),
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_misconf_rules_sev ON misconf_rules (severity);

-- ══════════════════════════════════════════════════════════════
-- MISCONFIGURATIONS — per-node findings (references misconf_rules)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS misconfigurations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     UUID REFERENCES nodes(id) ON DELETE CASCADE,
    container_id UUID REFERENCES containers(id) ON DELETE SET NULL,
    rule_id     TEXT NOT NULL REFERENCES misconf_rules(rule_id) ON DELETE CASCADE,
    target      TEXT,
    status      TEXT DEFAULT 'open'
        CHECK (status IN ('open','acknowledged','mitigated','resolved','false_positive','accepted_risk')),
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_misconf_node     ON misconfigurations (node_id);
CREATE INDEX IF NOT EXISTS idx_misconf_status   ON misconfigurations (status);
CREATE INDEX IF NOT EXISTS idx_misconf_rule     ON misconfigurations (rule_id);
-- Partial index for compliance/stats (open misconfigs with severity via JOIN)
CREATE INDEX IF NOT EXISTS idx_misconf_node_open ON misconfigurations (node_id) WHERE status = 'open';

-- ══════════════════════════════════════════════════════════════
-- DRIFT REPORTS (Ansible --check --diff)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS drift_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         UUID REFERENCES nodes(id) ON DELETE CASCADE,
    drift_type      TEXT NOT NULL
        CHECK (drift_type IN ('file','package','service','config','user','permission')),
    resource_name   TEXT NOT NULL,
    expected        TEXT,
    actual          TEXT,
    severity        TEXT DEFAULT 'medium'
        CHECK (severity IN ('critical','high','medium','low')),
    status          TEXT DEFAULT 'open'
        CHECK (status IN ('open','acknowledged','resolved','accepted')),
    source          TEXT DEFAULT 'ansible',
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    UNIQUE(node_id, drift_type, resource_name)
);

CREATE INDEX IF NOT EXISTS idx_drift_node     ON drift_reports (node_id);
CREATE INDEX IF NOT EXISTS idx_drift_status   ON drift_reports (status);
CREATE INDEX IF NOT EXISTS idx_drift_severity ON drift_reports (severity);

-- ══════════════════════════════════════════════════════════════
-- CVE WORKFLOW
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cve_status (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     UUID REFERENCES nodes(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','acknowledged','in_progress','mitigated','resolved','false_positive','accepted_risk')),
    note        TEXT,
    justification TEXT,
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_id, cve_id)
);
ALTER TABLE cve_status ADD COLUMN IF NOT EXISTS justification TEXT;

-- Migration: add 'resolved' to cve_status.status CHECK constraint
DO $$ BEGIN
    ALTER TABLE cve_status
        DROP CONSTRAINT IF EXISTS cve_status_status_check;
    ALTER TABLE cve_status
        ADD CONSTRAINT cve_status_status_check
        CHECK (status IN ('open','acknowledged','in_progress','mitigated','resolved','false_positive','accepted_risk'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_cvest_node   ON cve_status (node_id);
CREATE INDEX IF NOT EXISTS idx_cvest_cve    ON cve_status (cve_id);
CREATE INDEX IF NOT EXISTS idx_cvest_status ON cve_status (status);
-- Composite for v_compliance_summary NOT EXISTS (node_id, cve_id)
CREATE INDEX IF NOT EXISTS idx_cvest_node_cve ON cve_status (node_id, cve_id);
-- Partial: only non-open status (resolved/mitigated) for fast NOT EXISTS lookup
CREATE INDEX IF NOT EXISTS idx_cvest_resolved ON cve_status (node_id, cve_id) WHERE status != 'open';

-- ══════════════════════════════════════════════════════════════
-- HEARTBEAT
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS node_heartbeats (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    status      TEXT NOT NULL CHECK (status IN ('up','down')),
    latency_ms  INTEGER,
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_heartbeats_node
    ON node_heartbeats (node_id, checked_at DESC);

-- ══════════════════════════════════════════════════════════════
-- BACKUP
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS backup_repositories (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     UUID REFERENCES nodes(id) ON DELETE SET NULL,
    name        TEXT NOT NULL,
    repo_path   TEXT NOT NULL,
    backend     TEXT DEFAULT 'restic',
    sftp_host   TEXT,
    sftp_user   TEXT,
    tags        TEXT[] DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_id, name)
);
-- Prevent duplicate orphan repos (node_id NULL) with same name
CREATE UNIQUE INDEX IF NOT EXISTS idx_backup_repo_name_null_node
    ON backup_repositories (name) WHERE node_id IS NULL;

CREATE TABLE IF NOT EXISTS backup_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id         UUID REFERENCES backup_repositories(id) ON DELETE CASCADE,
    node_id         UUID REFERENCES nodes(id) ON DELETE SET NULL,
    hostname        TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('success', 'failure', 'partial', 'running', 'error', 'warning')),
    files_new       INT DEFAULT 0,
    files_changed   INT DEFAULT 0,
    files_unmodified INT DEFAULT 0,
    files_total     INT DEFAULT 0,
    size_added      BIGINT DEFAULT 0,
    size_total      BIGINT DEFAULT 0,
    snapshots_total INT DEFAULT 0,
    duration_secs   INT DEFAULT 0,
    source          TEXT DEFAULT 'script',
    error_msg       TEXT,
    raw             JSONB,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure status allows error/warning for existing databases
DO $$ BEGIN
    ALTER TABLE backup_runs DROP CONSTRAINT IF EXISTS backup_runs_status_check;
    ALTER TABLE backup_runs ADD CONSTRAINT backup_runs_status_check
        CHECK (status IN ('success', 'failure', 'partial', 'running', 'error', 'warning'));
END $$;

-- Deduplicate by day: one run per repo per date
-- timestamptz::date is STABLE (timezone-dependent), so we wrap in IMMUTABLE (pinned to UTC)
CREATE OR REPLACE FUNCTION utc_date(ts timestamptz) RETURNS date AS $$
    SELECT (ts AT TIME ZONE 'UTC')::date;
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_br_repo_day
    ON backup_runs (repo_id, (utc_date(started_at)))
    WHERE started_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_br_repo     ON backup_runs (repo_id);
CREATE INDEX IF NOT EXISTS idx_br_node     ON backup_runs (node_id);
CREATE INDEX IF NOT EXISTS idx_br_status   ON backup_runs (status);
CREATE INDEX IF NOT EXISTS idx_br_finished ON backup_runs (finished_at DESC);
-- Composite for v_backup_latest DISTINCT ON (repo_id) ORDER BY finished_at DESC
CREATE INDEX IF NOT EXISTS idx_br_repo_finished ON backup_runs (repo_id, finished_at DESC NULLS LAST);

-- ══════════════════════════════════════════════════════════════
-- SECRETS DETECTION
-- ══════════════════════════════════════════════════════════════

-- ══════════════════════════════════════════════════════════════
-- SECRET RULES — reference table (one row per secret type)
-- "aws-access-key-id" metadata stored once instead of N×findings
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS secret_rules (
    secret_type  TEXT PRIMARY KEY,
    title        TEXT,
    severity     TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    source       TEXT DEFAULT 'trivy',
    first_seen   TIMESTAMPTZ DEFAULT NOW(),
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secret_rules_sev ON secret_rules (severity);

-- ══════════════════════════════════════════════════════════════
-- SECRETS DETECTED — per-node findings (references secret_rules)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS secrets_detected (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     UUID REFERENCES nodes(id) ON DELETE CASCADE,
    secret_type TEXT NOT NULL REFERENCES secret_rules(secret_type) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    match       TEXT,
    image       TEXT,
    target_type TEXT DEFAULT 'host',
    status      TEXT DEFAULT 'open'
        CHECK (status IN ('open', 'false_positive', 'resolved', 'accepted_risk')),
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secrets_node ON secrets_detected (node_id);
CREATE INDEX IF NOT EXISTS idx_secrets_open ON secrets_detected (status) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets_detected (secret_type);

CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_unique
    ON secrets_detected (node_id, file_path, secret_type, COALESCE(image, ''));

-- ══════════════════════════════════════════════════════════════
-- OPENCVE — veille CVE (threat intelligence)
-- ══════════════════════════════════════════════════════════════

-- Produits/vendors surveilles
CREATE TABLE IF NOT EXISTS opencve_subscriptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor      TEXT NOT NULL,
    product     TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(vendor, product)
);

-- Alertes recues depuis OpenCVE (webhook ou polling)
CREATE TABLE IF NOT EXISTS opencve_alerts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id      TEXT NOT NULL,
    vendor      TEXT,
    product     TEXT,
    title       TEXT,
    description TEXT,
    cvss_v3     NUMERIC(4,1),
    severity    TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    cwe_ids     TEXT[],
    kev         BOOLEAN DEFAULT false,
    updated_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    raw         JSONB
);

-- Unique fonctionnel : meme CVE + meme produit (ou NULL)
CREATE UNIQUE INDEX IF NOT EXISTS idx_ocve_alert_unique
    ON opencve_alerts (cve_id, COALESCE(product, ''));

CREATE INDEX IF NOT EXISTS idx_ocve_cve      ON opencve_alerts (cve_id);
CREATE INDEX IF NOT EXISTS idx_ocve_vendor   ON opencve_alerts (vendor);
CREATE INDEX IF NOT EXISTS idx_ocve_severity ON opencve_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_ocve_created  ON opencve_alerts (created_at DESC);

-- ══════════════════════════════════════════════════════════════
-- CVE FEEDS (CERT-FR / user-supplied RSS / Atom)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cve_feeds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    url             TEXT NOT NULL UNIQUE,
    feed_type       TEXT NOT NULL DEFAULT 'rss'
        CHECK (feed_type IN ('rss', 'atom')),
    source_label    TEXT NOT NULL DEFAULT 'custom',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_fetched_at TIMESTAMPTZ,
    last_status     TEXT,
    last_error      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_feeds_enabled ON cve_feeds (enabled);

-- Advisories ingested from feeds. Each entry maps to one feed item, with
-- the CVE IDs referenced in its body so we can correlate later.
CREATE TABLE IF NOT EXISTS cve_advisories (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id            UUID NOT NULL REFERENCES cve_feeds(id) ON DELETE CASCADE,
    advisory_ref       TEXT NOT NULL,
    title              TEXT NOT NULL,
    url                TEXT,
    summary            TEXT,
    published_at       TIMESTAMPTZ,
    cve_ids            TEXT[] NOT NULL DEFAULT '{}',
    severity           TEXT,
    matched_cve_count  INT NOT NULL DEFAULT 0,
    matched_node_count INT NOT NULL DEFAULT 0,
    fetched_at         TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(feed_id, advisory_ref)
);

CREATE INDEX IF NOT EXISTS idx_cve_adv_feed       ON cve_advisories (feed_id);
CREATE INDEX IF NOT EXISTS idx_cve_adv_published  ON cve_advisories (published_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_cve_adv_matched    ON cve_advisories (matched_cve_count DESC);
CREATE INDEX IF NOT EXISTS idx_cve_adv_cve_gin    ON cve_advisories USING GIN (cve_ids);

-- Built-in CERT-FR advisory feed — idempotent seed.
INSERT INTO cve_feeds (name, url, feed_type, source_label, enabled)
VALUES (
    'CERT-FR Avis',
    'https://www.cert.ssi.gouv.fr/avis/feed/',
    'rss',
    'cert-fr',
    true
) ON CONFLICT (url) DO NOTHING;

-- ══════════════════════════════════════════════════════════════
-- SCA (Security Configuration Assessment — Wazuh)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS sca_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         UUID REFERENCES nodes(id) ON DELETE CASCADE,
    source          TEXT DEFAULT 'wazuh',
    policy_id       TEXT NOT NULL,
    policy_name     TEXT,
    score           INT,
    total_checks    INT,
    passed          INT,
    failed          INT,
    end_scan        TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_id, policy_id)
);

CREATE INDEX IF NOT EXISTS idx_sca_node   ON sca_results (node_id);
CREATE INDEX IF NOT EXISTS idx_sca_policy ON sca_results (policy_id);
CREATE INDEX IF NOT EXISTS idx_sca_score  ON sca_results (score);

-- ══════════════════════════════════════════════════════════════
-- REPOSITORIES (image tracking)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS repositories (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_name        TEXT NOT NULL,
    image_name          TEXT NOT NULL,
    registry            TEXT NOT NULL DEFAULT 'dockerhub',
    current_tag         TEXT,
    current_digest      TEXT,
    latest_tag_available TEXT,
    latest_digest       TEXT,
    update_available    BOOLEAN DEFAULT false,
    auto_update_candidate BOOLEAN DEFAULT false,
    listen              TEXT DEFAULT 'docker_internal'
        CHECK (listen IN ('internet','private_network','localhost','docker_internal')),
    last_checked        TIMESTAMPTZ,
    node_id             UUID REFERENCES nodes(id) ON DELETE SET NULL,
    manager_id          UUID,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(image_name, current_tag, node_id)
);

-- Live migration: digest-based update detection for latest-pinned images
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS latest_digest TEXT;

CREATE INDEX IF NOT EXISTS idx_repo_project    ON repositories (project_name);
CREATE INDEX IF NOT EXISTS idx_repo_image      ON repositories (image_name);
CREATE INDEX IF NOT EXISTS idx_repo_image_node ON repositories (image_name, node_id);
CREATE INDEX IF NOT EXISTS idx_repo_update     ON repositories (update_available);
CREATE INDEX IF NOT EXISTS idx_repo_node       ON repositories (node_id);

-- ══════════════════════════════════════════════════════════════
-- PACKAGE REPOSITORIES (OS repos — APT, DNF, Pacman, etc.)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS package_repositories (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    os_family   TEXT NOT NULL
        CHECK (os_family IN ('debian','ubuntu','centos','rocky','rhel','archlinux','aix','fedora','generic')),
    url         TEXT NOT NULL,
    repo_type   TEXT NOT NULL DEFAULT 'official'
        CHECK (repo_type IN ('official','custom')),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    description TEXT,
    components  TEXT,
    distribution TEXT,
    gpg_key_url TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(name, os_family)
);

CREATE INDEX IF NOT EXISTS idx_pkg_repo_os ON package_repositories (os_family);

-- Seed: standard OS package repositories
INSERT INTO package_repositories (name, os_family, url, repo_type, description, components, distribution) VALUES
-- Debian 12 (Bookworm)
('debian-bookworm',          'debian', 'https://deb.debian.org/debian',          'official', 'Debian 12 Bookworm — main repository',          'main contrib non-free non-free-firmware', 'bookworm'),
('debian-bookworm-security', 'debian', 'https://security.debian.org/debian-security', 'official', 'Debian 12 Bookworm — security updates',    'main contrib non-free non-free-firmware', 'bookworm-security'),
('debian-bookworm-updates',  'debian', 'https://deb.debian.org/debian',          'official', 'Debian 12 Bookworm — stable updates',           'main contrib non-free non-free-firmware', 'bookworm-updates'),
-- Debian 13 (Trixie)
('debian-trixie',            'debian', 'https://deb.debian.org/debian',          'official', 'Debian 13 Trixie — main repository',            'main contrib non-free non-free-firmware', 'trixie'),
('debian-trixie-security',   'debian', 'https://security.debian.org/debian-security', 'official', 'Debian 13 Trixie — security updates',      'main contrib non-free non-free-firmware', 'trixie-security'),
-- Ubuntu (Noble 24.04)
('ubuntu-noble',             'ubuntu', 'https://archive.ubuntu.com/ubuntu',      'official', 'Ubuntu 24.04 Noble — main repository',          'main restricted universe multiverse',     'noble'),
('ubuntu-noble-security',    'ubuntu', 'https://security.ubuntu.com/ubuntu',     'official', 'Ubuntu 24.04 Noble — security updates',         'main restricted universe multiverse',     'noble-security'),
('ubuntu-noble-updates',     'ubuntu', 'https://archive.ubuntu.com/ubuntu',      'official', 'Ubuntu 24.04 Noble — stable updates',           'main restricted universe multiverse',     'noble-updates'),
-- RHEL 8/9/10
('rhel-8-baseos',            'rhel',   'https://cdn.redhat.com/content/dist/rhel8/8/x86_64/baseos/os', 'official', 'RHEL 8 — BaseOS',       NULL, NULL),
('rhel-8-appstream',         'rhel',   'https://cdn.redhat.com/content/dist/rhel8/8/x86_64/appstream/os', 'official', 'RHEL 8 — AppStream', NULL, NULL),
('rhel-9-baseos',            'rhel',   'https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os', 'official', 'RHEL 9 — BaseOS',       NULL, NULL),
('rhel-9-appstream',         'rhel',   'https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os', 'official', 'RHEL 9 — AppStream', NULL, NULL),
('rhel-10-baseos',           'rhel',   'https://cdn.redhat.com/content/dist/rhel10/10/x86_64/baseos/os', 'official', 'RHEL 10 — BaseOS',   NULL, NULL),
('rhel-10-appstream',        'rhel',   'https://cdn.redhat.com/content/dist/rhel10/10/x86_64/appstream/os', 'official', 'RHEL 10 — AppStream', NULL, NULL),
-- Rocky Linux 8/9/10
('rocky-8-baseos',           'rocky',  'https://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/',    'official', 'Rocky Linux 8 — BaseOS',    NULL, NULL),
('rocky-8-appstream',        'rocky',  'https://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/', 'official', 'Rocky Linux 8 — AppStream', NULL, NULL),
('rocky-9-baseos',           'rocky',  'https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/',    'official', 'Rocky Linux 9 — BaseOS',    NULL, NULL),
('rocky-9-appstream',        'rocky',  'https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/', 'official', 'Rocky Linux 9 — AppStream', NULL, NULL),
('rocky-10-baseos',          'rocky',  'https://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/',   'official', 'Rocky Linux 10 — BaseOS',   NULL, NULL),
('rocky-10-appstream',       'rocky',  'https://dl.rockylinux.org/pub/rocky/10/AppStream/x86_64/os/','official', 'Rocky Linux 10 — AppStream',NULL, NULL),
-- Arch Linux
('archlinux-core',           'archlinux', 'https://geo.mirror.pkgbuild.com/core/os/x86_64',         'official', 'Arch Linux — core',         NULL, NULL),
('archlinux-extra',          'archlinux', 'https://geo.mirror.pkgbuild.com/extra/os/x86_64',        'official', 'Arch Linux — extra',        NULL, NULL),
('archlinux-multilib',       'archlinux', 'https://geo.mirror.pkgbuild.com/multilib/os/x86_64',     'official', 'Arch Linux — multilib',     NULL, NULL),
-- AIX
('aix-toolbox',              'aix',    'https://public.dhe.ibm.com/aix/freeSoftware/aixtoolbox/RPMS/ppc/', 'official', 'AIX Toolbox for Open Source Software', NULL, NULL)
ON CONFLICT (name, os_family) DO NOTHING;

-- ══════════════════════════════════════════════════════════════
-- FONCTIONS
-- ══════════════════════════════════════════════════════════════

-- Score contextuel CVE (0-100) — IMMUTABLE pour etre utilisable dans les index/vues
CREATE OR REPLACE FUNCTION cve_score(
    cvss numeric,
    exploited boolean,
    listen text,
    fix_status text,
    exploit_ctx text,
    severity text DEFAULT NULL
) RETURNS integer AS $$
DECLARE
    s numeric := COALESCE(cvss, 0) * 5;
BEGIN
    -- Distro severity adjustment: when the distro (Debian, RHEL...) evaluates
    -- a CVE as low/medium despite a high NVD CVSS, trust the distro assessment.
    -- This handles backported fixes and disputed/not-affected CVEs.
    IF severity = 'low' THEN s := LEAST(s, 15); END IF;
    IF severity = 'medium' AND s > 35 THEN s := 35; END IF;

    IF exploited THEN s := s + 25; END IF;
    s := s + CASE listen
        WHEN 'internet' THEN 20
        WHEN 'private_network' THEN 10
        WHEN 'docker_internal' THEN 5
        WHEN 'localhost' THEN 2
        ELSE 5 END;
    IF fix_status = 'fixed_available' THEN s := s + 8; END IF;
    IF fix_status = 'will_not_fix' THEN s := LEAST(s, 10); END IF;
    IF fix_status = 'not_affected' THEN s := 0; END IF;
    s := s + CASE exploit_ctx
        WHEN 'requires_auth' THEN -10
        WHEN 'requires_local_access' THEN -15
        WHEN 'requires_user_interaction' THEN -8
        WHEN 'likely_exploitable' THEN 5
        ELSE 0 END;
    RETURN GREATEST(0, LEAST(100, s::integer));
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ══════════════════════════════════════════════════════════════
-- VUES
-- ══════════════════════════════════════════════════════════════

-- Drop views that depend on v_all_cves first (CASCADE would also work
-- but explicit ordering is safer for documentation).
-- Views are all dropped at the top of this file

-- 2026-06-12: backfill du score materialise — une passe sur les lignes
-- jamais scorees (upgrade depuis le score calcule a la lecture). Idempotent :
-- apres le premier passage l'index partiel score_null est vide et la requete
-- ne coute rien au demarrage.
UPDATE cve_host_packages hp
SET score = sub.new_score
FROM (
    SELECT hp2.id,
           cve_score(cat.cvss_score, COALESCE(cat.exploited, false),
                     'private_network', hp2.fix_status,
                     COALESCE(cat.exploitability_context, 'unclear'),
                     hp2.severity) AS new_score
    FROM cve_host_packages hp2
    JOIN cve_catalog cat ON cat.cve_id = hp2.cve_id
    WHERE hp2.score IS NULL
) sub
WHERE sub.id = hp.id;

UPDATE cve_containers cc
SET score = sub.new_score
FROM (
    SELECT cc2.id,
           cve_score(cat.cvss_score, COALESCE(cat.exploited, false),
                     COALESCE((SELECT r.listen FROM repositories r
                               WHERE r.image_name
                                     = regexp_replace(cc2.image, ':[^:]*$', '')
                                 AND r.node_id = cc2.node_id LIMIT 1),
                              'docker_internal'),
                     cc2.fix_status,
                     COALESCE(cat.exploitability_context, 'unclear'),
                     cc2.severity) AS new_score
    FROM cve_containers cc2
    JOIN cve_catalog cat ON cat.cve_id = cc2.cve_id
    WHERE cc2.score IS NULL
) sub
WHERE sub.id = cc.id;

-- Toutes les CVEs unifiees (packages host + containers) avec score.
-- Le score est la colonne materialisee (maintenue a l'ecriture par
-- api/app/utils/scoring.py) — plus d'appel plpgsql par ligne a la lecture,
-- ORDER BY score est servi par idx_cve_*_status_score.
CREATE OR REPLACE VIEW v_all_cves AS
    SELECT
        hp.id, hp.node_id, hp.cve_id, hp.severity,
        cat.cvss_score,
        hp.pkg_name AS target, hp.installed_ver, hp.fixed_ver,
        'package' AS target_type,
        hp.fix_status, hp.status,
        COALESCE(cat.exploited, false) AS exploited,
        hp.source, hp.scanned_at AS detected_at,
        n.environment,
        COALESCE(cs.status, 'open') AS workflow_status,
        cs.justification,
        hp.score::int AS score
    FROM cve_host_packages hp
    JOIN cve_catalog cat ON cat.cve_id = hp.cve_id
    JOIN nodes n ON n.id = hp.node_id
    LEFT JOIN cve_status cs ON cs.node_id = hp.node_id AND cs.cve_id = hp.cve_id
    UNION ALL
    SELECT
        cc.id, cc.node_id, cc.cve_id, cc.severity,
        cat.cvss_score,
        cc.pkg_name AS target, cc.installed_ver, cc.fixed_ver,
        COALESCE(cc.pkg_type, 'container') AS target_type,
        cc.fix_status, cc.status,
        COALESCE(cat.exploited, false) AS exploited,
        'trivy' AS source, cc.scanned_at AS detected_at,
        n.environment,
        COALESCE(cs.status, 'open') AS workflow_status,
        cs.justification,
        cc.score::int AS score
    FROM cve_containers cc
    JOIN cve_catalog cat ON cat.cve_id = cc.cve_id
    JOIN nodes n ON n.id = cc.node_id
    LEFT JOIN cve_status cs ON cs.node_id = cc.node_id AND cs.cve_id = cc.cve_id;

-- Resume par node (precomputed aggregates — no correlated subqueries)
CREATE OR REPLACE VIEW v_node_summary AS
    SELECT
        n.id,
        n.hostname,
        n.type,
        n.os,
        n.os_version,
        n.arch,
        n.kernel,
        n.hw_info,
        n.last_seen,
        n.is_active,
        n.environment,
        COALESCE(pkg.cnt, 0)  AS package_count,
        COALESCE(ctr.cnt, 0)  AS container_count,
        COALESCE(chp.cnt, 0)  AS cve_package_count,
        COALESCE(chp.crit, 0) AS cve_package_critical,
        COALESCE(cc.cnt, 0)   AS cve_container_count,
        COALESCE(cc.crit, 0)  AS cve_container_critical,
        COALESCE(chp.crit, 0) + COALESCE(cc.crit, 0) AS cve_critical_count
    FROM nodes n
    LEFT JOIN (SELECT node_id, COUNT(*) AS cnt FROM packages GROUP BY node_id) pkg
        ON pkg.node_id = n.id
    LEFT JOIN (SELECT node_id, COUNT(*) AS cnt FROM containers GROUP BY node_id) ctr
        ON ctr.node_id = n.id
    LEFT JOIN (
        SELECT node_id,
               COUNT(*) FILTER (WHERE severity != 'low'
                   AND fix_status NOT IN ('will_not_fix', 'not_affected')) AS cnt,
               COUNT(*) FILTER (WHERE severity = 'critical') AS crit
        FROM cve_host_packages
        WHERE status = 'open'
        GROUP BY node_id
    ) chp ON chp.node_id = n.id
    LEFT JOIN (
        SELECT node_id,
               COUNT(*) FILTER (WHERE severity != 'low'
                   AND fix_status NOT IN ('will_not_fix', 'not_affected')) AS cnt,
               COUNT(*) FILTER (WHERE severity = 'critical') AS crit
        FROM cve_containers
        WHERE status = 'open'
        GROUP BY node_id
    ) cc ON cc.node_id = n.id;

-- Dernier run backup par repo
CREATE OR REPLACE VIEW v_backup_latest AS
    SELECT DISTINCT ON (r.id)
        r.id            AS repo_id,
        r.name          AS repo_name,
        r.node_id,
        n.hostname,
        r.sftp_host,
        r.tags,
        br.id           AS run_id,
        br.status,
        br.files_new,
        br.files_changed,
        br.files_total,
        br.size_added,
        br.size_total,
        br.snapshots_total,
        br.duration_secs,
        br.error_msg,
        br.finished_at  AS last_run,
        -- Daily cron + 4h tolerance for slow small-file repos
        CASE WHEN br.finished_at < NOW() - INTERVAL '28 hours'
             THEN true ELSE false END AS overdue
    FROM backup_repositories r
    LEFT JOIN backup_runs br ON br.repo_id = r.id
    LEFT JOIN nodes n ON n.id = r.node_id
    ORDER BY r.id, br.finished_at DESC NULLS LAST;

-- Stats backup 30 jours
CREATE OR REPLACE VIEW v_backup_stats_30d AS
    SELECT
        repo_id,
        COUNT(*)                                            AS total_runs,
        COUNT(*) FILTER (WHERE status = 'success')         AS success_count,
        COUNT(*) FILTER (WHERE status = 'failure')         AS failure_count,
        ROUND(AVG(duration_secs))                          AS avg_duration_secs,
        MAX(size_total)                                     AS max_size_total,
        SUM(size_added)                                     AS total_added_30d,
        MAX(finished_at)                                    AS last_run,
        ROUND(
            100.0 * COUNT(*) FILTER (WHERE status = 'success')
            / NULLIF(COUNT(*), 0), 1
        ) AS success_rate
    FROM backup_runs
    WHERE finished_at > NOW() - INTERVAL '30 days'
    GROUP BY repo_id;

-- Nodes actifs sans aucun repo backup configure
CREATE OR REPLACE VIEW v_backup_missing AS
    SELECT n.id AS node_id, n.hostname, n.type, n.os
    FROM nodes n
    WHERE n.is_active = true
      AND NOT EXISTS (
          SELECT 1 FROM backup_repositories br WHERE br.node_id = n.id
      );

-- Alertes backup : failed + overdue + missing
CREATE OR REPLACE VIEW v_backup_alerts AS
    -- Derniers backups en echec
    SELECT
        'failure' AS alert_type,
        l.hostname,
        l.repo_name,
        l.status,
        l.error_msg,
        l.last_run
    FROM v_backup_latest l
    WHERE l.status = 'failure'
    UNION ALL
    -- Backups en retard (>28h : daily cron + 4h tolerance)
    SELECT
        'overdue' AS alert_type,
        l.hostname,
        l.repo_name,
        l.status,
        NULL AS error_msg,
        l.last_run
    FROM v_backup_latest l
    WHERE l.overdue = true
    UNION ALL
    -- Nodes sans backup
    SELECT
        'missing' AS alert_type,
        m.hostname,
        NULL AS repo_name,
        NULL AS status,
        'No backup configured' AS error_msg,
        NULL AS last_run
    FROM v_backup_missing m;

-- Vue correlation : alertes OpenCVE x assets CMDB
-- "cette CVE OpenCVE touche ces nodes dans mon infra"
-- Uses cve_catalog for CVE-level metadata
CREATE OR REPLACE VIEW v_opencve_impact AS
    SELECT
        oa.cve_id,
        oa.severity AS opencve_severity,
        COALESCE(oa.cvss_v3, cat.cvss_score) AS cvss_v3,
        oa.title,
        oa.vendor,
        oa.product,
        oa.created_at AS alert_date,
        ac.node_id,
        n.hostname,
        ac.target,
        ac.installed_ver,
        ac.target_type
    FROM opencve_alerts oa
    JOIN cve_catalog cat ON cat.cve_id = oa.cve_id
    JOIN v_all_cves ac ON ac.cve_id = oa.cve_id
    JOIN nodes n ON n.id = ac.node_id;

-- ══════════════════════════════════════════════════════════════
-- SCAN STATUS
-- ══════════════════════════════════════════════════════════════

-- Fraicheur des scans par node et par source
-- Utilise les timestamps sur nodes (mis a jour meme si 0 CVEs trouvees)
-- avec fallback sur MAX(scanned_at) des tables CVE pour compat
CREATE OR REPLACE VIEW v_scan_status AS
    SELECT
        n.id AS node_id, n.hostname,
        COALESCE(n.last_wazuh_scan, wz.last_scan)       AS last_wazuh_scan,
        COALESCE(n.last_trivy_host_scan, tv.last_scan)   AS last_trivy_host_scan,
        COALESCE(n.last_trivy_image_scan, ci.last_scan)  AS last_trivy_image_scan,
        COALESCE(n.last_trivy_config_scan, mc.last_scan) AS last_trivy_config_scan
    FROM nodes n
    LEFT JOIN (
        SELECT node_id, MAX(scanned_at) AS last_scan
        FROM cve_host_packages WHERE source = 'wazuh'
        GROUP BY node_id
    ) wz ON wz.node_id = n.id
    LEFT JOIN (
        SELECT node_id, MAX(scanned_at) AS last_scan
        FROM cve_host_packages WHERE source = 'trivy'
        GROUP BY node_id
    ) tv ON tv.node_id = n.id
    LEFT JOIN (
        SELECT node_id, MAX(scanned_at) AS last_scan
        FROM cve_containers
        GROUP BY node_id
    ) ci ON ci.node_id = n.id
    LEFT JOIN (
        SELECT node_id, MAX(detected_at) AS last_scan
        FROM misconfigurations
        GROUP BY node_id
    ) mc ON mc.node_id = n.id
    WHERE n.is_active = true;

-- Résumé exposition containers
CREATE OR REPLACE VIEW v_exposure_summary AS
    SELECT
        c.exposure,
        COUNT(*)                              AS container_count,
        COUNT(*) FILTER (WHERE c.traefik)     AS traefik_count,
        COUNT(*) FILTER (WHERE c.authelia)    AS authelia_count,
        COUNT(*) FILTER (WHERE c.geoip)       AS geoip_count,
        ARRAY_AGG(DISTINCT c.name || '@' || n.hostname) AS containers
    FROM containers c
    JOIN nodes n ON n.id = c.node_id
    WHERE n.is_active = true
    GROUP BY c.exposure;

-- Score compliance unifie par node
-- misconf severity via JOIN misconf_rules, CVE via NOT EXISTS on cve_status
CREATE OR REPLACE VIEW v_compliance_summary AS
    SELECT
        n.id AS node_id, n.hostname, n.environment,
        COALESCE(sca.avg_score, 0) AS sca_score,
        COALESCE(mis.total, 0) AS misconf_total,
        COALESCE(mis.crit, 0) AS misconf_critical,
        COALESCE(cve.total, 0) AS cve_open_total,
        COALESCE(cve.crit, 0) AS cve_critical_open,
        COALESCE(drift.total, 0) AS drift_total,
        COALESCE(drift.high, 0) AS drift_high
    FROM nodes n
    LEFT JOIN (
        SELECT node_id, ROUND(AVG(score), 1) AS avg_score
        FROM sca_results GROUP BY node_id
    ) sca ON sca.node_id = n.id
    LEFT JOIN (
        SELECT m.node_id, COUNT(*) AS total,
               COUNT(*) FILTER (WHERE r.severity = 'critical') AS crit
        FROM misconfigurations m
        JOIN misconf_rules r ON r.rule_id = m.rule_id
        WHERE m.status = 'open'
        GROUP BY m.node_id
    ) mis ON mis.node_id = n.id
    LEFT JOIN (
        SELECT node_id, SUM(cnt) AS total, SUM(crit) AS crit FROM (
            SELECT hp.node_id, COUNT(*) AS cnt,
                   COUNT(*) FILTER (WHERE hp.severity = 'critical') AS crit
            FROM cve_host_packages hp
            WHERE NOT EXISTS (
                SELECT 1 FROM cve_status cs
                WHERE cs.node_id = hp.node_id AND cs.cve_id = hp.cve_id
                  AND cs.status != 'open'
            )
            GROUP BY hp.node_id
            UNION ALL
            SELECT cc.node_id, COUNT(*) AS cnt,
                   COUNT(*) FILTER (WHERE cc.severity = 'critical') AS crit
            FROM cve_containers cc
            WHERE NOT EXISTS (
                SELECT 1 FROM cve_status cs
                WHERE cs.node_id = cc.node_id AND cs.cve_id = cc.cve_id
                  AND cs.status != 'open'
            )
            GROUP BY cc.node_id
        ) sub GROUP BY node_id
    ) cve ON cve.node_id = n.id
    LEFT JOIN (
        SELECT node_id, COUNT(*) AS total,
               COUNT(*) FILTER (WHERE severity IN ('critical','high')) AS high
        FROM drift_reports WHERE status = 'open'
        GROUP BY node_id
    ) drift ON drift.node_id = n.id
    WHERE n.is_active = true;

-- ══════════════════════════════════════════════════════════════
-- AUTOMATION
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS automation_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    description     TEXT,
    priority        INT NOT NULL DEFAULT 0,
    enabled         BOOLEAN DEFAULT true,
    trigger_type    TEXT NOT NULL
        CHECK (trigger_type IN (
            'cve_detected','update_available','backup_overdue',
            'scan_stale','exposure_change','misconf_detected',
            'pipeline_failure','deploy_requested',
            'worker_offline','image_update_available',
            'drift_detected'
        )),
    match_hostname      TEXT,
    match_container     TEXT,
    match_image         TEXT,
    match_package       TEXT,
    match_cve_id        TEXT,
    match_severity      TEXT[],
    match_environment   TEXT[],
    match_exposure      TEXT[],
    action          TEXT NOT NULL
        CHECK (action IN (
            'notify','auto_update','manual_validation',
            'rescan','ignore','create_deployment','pull_image',
            'create_incident','email'
        )),
    notify_channels TEXT[] DEFAULT '{matrix}',
    notify_room     TEXT,
    auto_execute    BOOLEAN DEFAULT false,
    config          JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_autopol_priority ON automation_policies (priority DESC) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_autopol_trigger  ON automation_policies (trigger_type) WHERE enabled;

CREATE TABLE IF NOT EXISTS automation_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id   UUID REFERENCES automation_policies(id) ON DELETE SET NULL,
    policy_name TEXT,
    trigger_type TEXT NOT NULL,
    action      TEXT NOT NULL,
    hostname    TEXT,
    container   TEXT,
    image       TEXT,
    package     TEXT,
    cve_id      TEXT,
    severity    TEXT,
    environment TEXT,
    exposure    TEXT,
    status      TEXT DEFAULT 'pending'
        CHECK (status IN ('pending','approved','executing','completed','failed','skipped','ignored')),
    result      JSONB,
    approved_by TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    executed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_autolog_status  ON automation_log (status);
CREATE INDEX IF NOT EXISTS idx_autolog_created ON automation_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_autolog_policy  ON automation_log (policy_id);

-- ══════════════════════════════════════════════════════════════
-- INCIDENTS + SSVC PRIORITY RULES
-- ══════════════════════════════════════════════════════════════

-- Monotonic UID sequence (INC-NNNNNN)
CREATE SEQUENCE IF NOT EXISTS incidents_uid_seq START 1;

CREATE TABLE IF NOT EXISTS priority_rule_sets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT UNIQUE NOT NULL,
    description TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT false,
    rules       JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
-- At most one active rule set
CREATE UNIQUE INDEX IF NOT EXISTS uq_priority_rule_sets_active
    ON priority_rule_sets (is_active) WHERE is_active = true;

CREATE TABLE IF NOT EXISTS incidents (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    uid                  TEXT UNIQUE NOT NULL,
    title                TEXT NOT NULL,
    description          TEXT,
    status               TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new','triaged','in_progress','resolved','closed')),
    priority             TEXT NOT NULL
        CHECK (priority IN ('P1','P2','P3','P4')),
    close_reason         TEXT
        CHECK (close_reason IS NULL OR close_reason IN
            ('fixed','mitigated','false_positive','duplicate','wont_fix','accepted_risk')),
    cve_id               TEXT,
    affected_asset       TEXT,
    affected_package     TEXT,
    severity             TEXT,
    environment          TEXT,
    exposure             TEXT,
    priority_rule_set_id UUID REFERENCES priority_rule_sets(id) ON DELETE SET NULL,
    rule_matched         TEXT,
    assignee             TEXT,
    source_trigger       TEXT,
    source_event         JSONB,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    updated_at           TIMESTAMPTZ DEFAULT NOW(),
    triaged_at           TIMESTAMPTZ,
    resolved_at          TIMESTAMPTZ,
    closed_at            TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_incidents_status_priority ON incidents (status, priority);
CREATE INDEX IF NOT EXISTS idx_incidents_dedup
    ON incidents (cve_id, affected_asset, affected_package)
    WHERE status NOT IN ('resolved','closed');
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_assignee ON incidents (assignee) WHERE assignee IS NOT NULL;

CREATE TABLE IF NOT EXISTS incident_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL
        CHECK (event_type IN
            ('created','status_changed','priority_changed','assigned','commented','action_executed')),
    actor       TEXT,
    from_value  TEXT,
    to_value    TEXT,
    detail      JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_events_timeline
    ON incident_events (incident_id, created_at DESC);

-- Seed preset rule set (idempotent under advisory lock)
DO $$
DECLARE _exists boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(94217001);
    SELECT EXISTS (SELECT 1 FROM priority_rule_sets WHERE name = 'CISA SSVC + ITIL v1')
        INTO _exists;
    IF NOT _exists THEN
        INSERT INTO priority_rule_sets (name, description, is_active, rules) VALUES (
            'CISA SSVC + ITIL v1',
            'Default SSVC priority engine — CISA KEV + CVSS + exposure + environment',
            NOT EXISTS (SELECT 1 FROM priority_rule_sets WHERE is_active = true),
            $rules$[
                {"name":"P1-kev-internet-prod","priority":"P1",
                 "conditions":{"in_kev":true,"exposure":["internet"],"environment":["production"]}},
                {"name":"P2-cvss9-or-kev-prod","priority":"P2",
                 "conditions":{"any":[{"cvss_min":9.0},{"in_kev":true}],"environment":["production"]}},
                {"name":"P3-cvss7-prod-or-internet","priority":"P3",
                 "conditions":{"any":[
                    {"cvss_min":7.0,"environment":["production"]},
                    {"exposure":["internet"]}]}},
                {"name":"P4-default","priority":"P4","conditions":{}}
            ]$rules$::jsonb
        );
    END IF;
END $$;

-- ══════════════════════════════════════════════════════════════
-- ALERT SETTINGS
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS alert_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Defaults
INSERT INTO alert_settings (key, value) VALUES
    ('cve_severity_threshold', 'high'),
    ('matrix_enabled', 'true'),
    ('matrix_url', 'https://matrix.example.com'),
    ('matrix_token', ''),
    ('matrix_room_cve', ''),
    ('matrix_room_security', ''),
    ('email_enabled', 'true'),
    ('alert_email', ''),
    ('smtp_host', ''),
    ('smtp_port', '587'),
    ('smtp_use_starttls', 'true'),
    ('smtp_use_ssl', 'false'),
    ('smtp_user', ''),
    ('smtp_password', ''),
    ('smtp_from', 'cmdb@example.com'),
    ('smtp_from_name', 'Constellation'),
    ('feature_cve_enabled', 'true'),
    ('feature_backup_enabled', 'true')
ON CONFLICT (key) DO NOTHING;

-- ══════════════════════════════════════════════════════════════
-- ALERT DEDUPLICATION
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS alert_sent (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id      TEXT NOT NULL,
    node_id     TEXT NOT NULL DEFAULT 'global',
    target_name TEXT NOT NULL DEFAULT '',
    channel     TEXT NOT NULL DEFAULT 'all',
    sent_at     TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(cve_id, node_id, target_name, channel)
);

CREATE INDEX IF NOT EXISTS idx_alert_sent_cve  ON alert_sent (cve_id);
CREATE INDEX IF NOT EXISTS idx_alert_sent_node ON alert_sent (node_id);

-- ══════════════════════════════════════════════════════════════
-- NOTIFICATION WEBHOOKS (generic: Mattermost, Rocket.Chat, Slack, Discord, ntfy…)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS notification_webhooks (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL UNIQUE,
    platform         TEXT NOT NULL DEFAULT 'generic',
    webhook_url      TEXT NOT NULL,
    enabled          BOOLEAN DEFAULT true,
    route_cve        BOOLEAN DEFAULT true,
    route_security   BOOLEAN DEFAULT true,
    route_cicd       BOOLEAN DEFAULT true,
    route_backup     BOOLEAN DEFAULT true,
    default_channel  TEXT,
    channel_cve      TEXT,
    channel_security TEXT,
    channel_cicd     TEXT,
    channel_backup   TEXT,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_enabled ON notification_webhooks (enabled) WHERE enabled = true;

-- ══════════════════════════════════════════════════════════════
-- ITSM INTEGRATIONS (GLPI, Zammad, Jira)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS itsm_integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    platform        TEXT NOT NULL CHECK (platform IN ('glpi', 'zammad', 'jira')),
    base_url        TEXT NOT NULL,
    auth_config     JSONB NOT NULL DEFAULT '{}',
    project_key     TEXT,
    enabled         BOOLEAN DEFAULT true,
    sync_outbound   BOOLEAN DEFAULT true,
    sync_inbound    BOOLEAN DEFAULT false,
    webhook_secret  TEXT,
    status_map      JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_itsm_enabled ON itsm_integrations (enabled) WHERE enabled = true;

CREATE TABLE IF NOT EXISTS incident_tickets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    integration_id  UUID NOT NULL REFERENCES itsm_integrations(id) ON DELETE CASCADE,
    external_id     TEXT NOT NULL,
    external_url    TEXT,
    external_status TEXT,
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(integration_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_tickets_incident ON incident_tickets (incident_id);

-- ══════════════════════════════════════════════════════════════
-- AUDIT LOG
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT,
    detail      JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target  ON audit_log (target_type, target_id);

-- ── Audit archives (compressed) ──────────────────────────────
CREATE TABLE IF NOT EXISTS audit_archives (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    archive_date  DATE NOT NULL UNIQUE,
    entries_count INTEGER NOT NULL DEFAULT 0,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    compressed    BOOLEAN NOT NULL DEFAULT true,
    data          BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════
-- CI/CD — REPOSITORIES (Gitea)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cicd_repositories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    forge           TEXT NOT NULL DEFAULT 'gitea',
    repo_name       TEXT NOT NULL,
    owner           TEXT,
    description     TEXT,
    default_branch  TEXT DEFAULT 'main',
    url             TEXT,
    private         BOOLEAN DEFAULT false,
    language        TEXT,
    topics          TEXT[] DEFAULT '{}',
    stars           INTEGER DEFAULT 0,
    has_pipeline    BOOLEAN DEFAULT false,
    pipeline_config TEXT,
    branches        TEXT[] DEFAULT '{}',
    last_commit_at  TIMESTAMPTZ,
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(forge, repo_name)
);

CREATE INDEX IF NOT EXISTS idx_cicd_repo_name  ON cicd_repositories (repo_name);
CREATE INDEX IF NOT EXISTS idx_cicd_repo_forge ON cicd_repositories (forge);

-- ══════════════════════════════════════════════════════════════
-- CI/CD — PIPELINE RUNS (Woodpecker)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cicd_pipelines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ci_system       TEXT NOT NULL DEFAULT 'woodpecker',
    repo_name       TEXT NOT NULL,
    pipeline_number INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN (
            'pending','running','success','failure',
            'error','killed','blocked','skipped','declined'
        )),
    event           TEXT
        CHECK (event IS NULL OR event IN (
            'push','pull_request','tag','cron','manual'
        )),
    branch          TEXT,
    commit_sha      TEXT,
    commit_message  TEXT,
    author          TEXT,
    duration_secs   INTEGER,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    link            TEXT,
    raw             JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ci_system, repo_name, pipeline_number)
);

CREATE INDEX IF NOT EXISTS idx_cicd_pipe_repo    ON cicd_pipelines (repo_name);
CREATE INDEX IF NOT EXISTS idx_cicd_pipe_ci      ON cicd_pipelines (ci_system);
CREATE INDEX IF NOT EXISTS idx_cicd_pipe_status  ON cicd_pipelines (status);
CREATE INDEX IF NOT EXISTS idx_cicd_pipe_started ON cicd_pipelines (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cicd_pipe_event   ON cicd_pipelines (event);

-- ══════════════════════════════════════════════════════════════
-- CI/CD — WORKERS
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cicd_workers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ci_system       TEXT NOT NULL DEFAULT 'woodpecker',
    external_id     TEXT NOT NULL,
    name            TEXT NOT NULL,
    hostname        TEXT,
    platform        TEXT,
    labels          JSONB DEFAULT '{}',
    capacity        INTEGER DEFAULT 1,
    status          TEXT DEFAULT 'connected'
        CHECK (status IN ('connected','offline','idle','busy')),
    last_contact    TIMESTAMPTZ,
    node_id         UUID REFERENCES nodes(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ci_system, external_id)
);

CREATE INDEX IF NOT EXISTS idx_cicd_worker_hostname ON cicd_workers (hostname);
CREATE INDEX IF NOT EXISTS idx_cicd_worker_status   ON cicd_workers (status);

-- ══════════════════════════════════════════════════════════════
-- CONTAINER MANAGERS (Portainer, etc.)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS container_managers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    manager_type    TEXT NOT NULL DEFAULT 'portainer'
        CHECK (manager_type IN ('portainer','docker')),
    url             TEXT NOT NULL,
    token           TEXT,
    endpoint_id     INTEGER DEFAULT 1,
    tls_skip_verify BOOLEAN DEFAULT false,
    status          TEXT DEFAULT 'connected'
        CHECK (status IN ('connected','error','offline')),
    last_check      TIMESTAMPTZ,
    node_id         UUID REFERENCES nodes(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mgr_type   ON container_managers (manager_type);
CREATE INDEX IF NOT EXISTS idx_mgr_status ON container_managers (status);

-- ══════════════════════════════════════════════════════════════
-- CI/CD SERVERS
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cicd_servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    server_type     TEXT NOT NULL DEFAULT 'woodpecker'
        CHECK (server_type IN ('woodpecker','gitea','gitlab','forgejo')),
    url             TEXT NOT NULL,
    token           TEXT,
    status          TEXT DEFAULT 'unknown'
        CHECK (status IN ('connected','error','offline','unknown')),
    last_check      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cicd_srv_type   ON cicd_servers (server_type);
CREATE INDEX IF NOT EXISTS idx_cicd_srv_status ON cicd_servers (status);

-- ══════════════════════════════════════════════════════════════
-- DEPLOYMENTS
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS deployments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           TEXT NOT NULL,
    deploy_type     TEXT NOT NULL
        CHECK (deploy_type IN (
            'package_upgrade','container_build',
            'container_deploy','ansible_playbook','image_pull'
        )),
    status          TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN (
            'draft','pending','approved','running',
            'success','failure','cancelled'
        )),
    -- Target
    worker_id       UUID REFERENCES cicd_workers(id) ON DELETE SET NULL,
    worker_hostname TEXT,
    repo_name       TEXT,
    branch          TEXT DEFAULT 'main',
    manager_id      UUID REFERENCES container_managers(id) ON DELETE SET NULL,
    -- Payload (variable selon deploy_type)
    config          JSONB DEFAULT '{}',
    -- Preflight
    preflight_ok    BOOLEAN DEFAULT false,
    preflight_result JSONB DEFAULT '{}',
    -- Woodpecker integration
    pipeline_number INTEGER,
    pipeline_link   TEXT,
    -- Policy link
    policy_id       UUID REFERENCES automation_policies(id) ON DELETE SET NULL,
    automation_log_id UUID REFERENCES automation_log(id) ON DELETE SET NULL,
    -- Workflow
    created_by      TEXT NOT NULL DEFAULT 'system',
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    result          JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE deployments ADD COLUMN IF NOT EXISTS automation_log_id UUID
    REFERENCES automation_log(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_deploy_status  ON deployments (status);
CREATE INDEX IF NOT EXISTS idx_deploy_type    ON deployments (deploy_type);
CREATE INDEX IF NOT EXISTS idx_deploy_worker  ON deployments (worker_id);
CREATE INDEX IF NOT EXISTS idx_deploy_created ON deployments (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deploy_policy  ON deployments (policy_id);

-- ══════════════════════════════════════════════════════════════
-- CI/CD — VIEW: latest pipeline per repo
-- ══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_cicd_latest AS
SELECT DISTINCT ON (p.repo_name)
    p.id,
    p.ci_system,
    p.repo_name,
    p.pipeline_number,
    p.status,
    p.event,
    p.branch,
    p.commit_sha,
    p.commit_message,
    p.author,
    p.duration_secs,
    p.started_at,
    p.finished_at,
    p.link,
    r.forge         AS repo_forge,
    r.description   AS repo_description,
    r.url           AS repo_url,
    r.language      AS repo_language,
    r.topics        AS repo_topics,
    r.private       AS repo_private
FROM cicd_pipelines p
LEFT JOIN cicd_repositories r ON r.repo_name = p.repo_name
ORDER BY p.repo_name, p.started_at DESC NULLS LAST;

-- ══════════════════════════════════════════════════════════════
-- CI/CD — VIEW: pipeline stats per repo (30 days)
-- ══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_cicd_stats_30d AS
SELECT
    repo_name,
    COUNT(*)                                              AS total_runs,
    COUNT(*) FILTER (WHERE status = 'success')            AS success_count,
    COUNT(*) FILTER (WHERE status = 'failure')            AS failure_count,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE status = 'success')
        / NULLIF(COUNT(*), 0), 1
    )                                                     AS success_rate,
    ROUND(AVG(duration_secs) FILTER (WHERE duration_secs > 0))
                                                          AS avg_duration_secs,
    MAX(started_at)                                       AS last_run_at
FROM cicd_pipelines
WHERE started_at >= NOW() - INTERVAL '30 days'
GROUP BY repo_name;

-- ══════════════════════════════════════════════════════════════
-- CI/CD — VIEW: workers with node info
-- ══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_cicd_workers_status AS
SELECT
    w.*,
    n.hostname  AS node_hostname,
    n.os        AS node_os,
    n.environment AS node_environment,
    n.is_active AS node_active,
    COALESCE(rp.running_count, 0) AS running_pipelines
FROM cicd_workers w
LEFT JOIN nodes n ON n.id = w.node_id
LEFT JOIN (
    SELECT
        p.author AS worker_name,
        COUNT(*) AS running_count
    FROM cicd_pipelines p
    WHERE p.status = 'running'
    GROUP BY p.author
) rp ON rp.worker_name = w.name;

-- ══════════════════════════════════════════════════════════════
-- DEPLOYMENTS — VIEW: summary with worker info
-- ══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_deployment_summary AS
SELECT
    d.*,
    w.name          AS worker_name,
    w.labels        AS worker_labels,
    w.status        AS worker_status,
    m.name          AS manager_name,
    m.manager_type,
    m.url           AS manager_url
FROM deployments d
LEFT JOIN cicd_workers w ON w.id = d.worker_id
LEFT JOIN container_managers m ON m.id = d.manager_id;

-- ══════════════════════════════════════════════════════════════
-- API TOKENS — granular permission management
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT NOT NULL UNIQUE,
    permissions JSONB NOT NULL DEFAULT '{}',
    active      BOOLEAN NOT NULL DEFAULT true,
    description TEXT,
    created_by  TEXT NOT NULL DEFAULT 'admin',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash   ON api_tokens (token_hash) WHERE active;
CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens (active);

-- Honeytoken IDS — flag column, idempotent migration
ALTER TABLE api_tokens
    ADD COLUMN IF NOT EXISTS is_honey BOOLEAN NOT NULL DEFAULT FALSE;

-- ══════════════════════════════════════════════════════════════
-- SCHEDULER — Job definitions
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS scheduler_jobs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT NOT NULL UNIQUE,
    description       TEXT,
    job_type          TEXT NOT NULL
        CHECK (job_type IN ('woodpecker_pipeline', 'gitlab_pipeline',
                            'http_request', 'cve_feeds_fetch')),
    enabled           BOOLEAN DEFAULT false,
    cron_expr         TEXT NOT NULL,
    timezone          TEXT NOT NULL DEFAULT 'UTC',
    config            JSONB NOT NULL DEFAULT '{}',
    timeout_secs      INTEGER NOT NULL DEFAULT 300,
    max_retries       INTEGER NOT NULL DEFAULT 0,
    retry_delay_secs  INTEGER NOT NULL DEFAULT 60,
    allow_overlap     BOOLEAN DEFAULT false,
    last_run_at       TIMESTAMPTZ,
    next_run_at       TIMESTAMPTZ,
    last_status       TEXT
        CHECK (last_status IS NULL OR last_status IN (
            'success', 'failure', 'timeout', 'skipped', 'running'
        )),
    created_by        TEXT NOT NULL DEFAULT 'system',
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sched_job_enabled ON scheduler_jobs (enabled, next_run_at) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_sched_job_name    ON scheduler_jobs (name);

-- Allow cve_feeds_fetch job_type for existing databases
DO $$ BEGIN
    ALTER TABLE scheduler_jobs DROP CONSTRAINT IF EXISTS scheduler_jobs_job_type_check;
    ALTER TABLE scheduler_jobs ADD CONSTRAINT scheduler_jobs_job_type_check
        CHECK (job_type IN ('woodpecker_pipeline', 'gitlab_pipeline',
                            'http_request', 'cve_feeds_fetch'));
END $$;

-- Default: heartbeat check every minute. 120s gives the job room to
-- queue on a saturated pool during CVE/Wazuh ingestion peaks before
-- being killed (was 30s, started timing out under load 2026-05-14).
INSERT INTO scheduler_jobs (name, description, job_type, cron_expr, enabled, config, timeout_secs)
VALUES (
    'heartbeat-check',
    'ICMP ping all active nodes every minute',
    'http_request',
    '* * * * *',
    true,
    '{"method": "POST", "url": "/api/v1/heartbeat/check", "expected_status": [200]}',
    120
) ON CONFLICT (name) DO NOTHING;

-- Migration : bump le timeout sur les DBs existantes (le INSERT ci-dessus
-- ne touche rien sur ON CONFLICT). Idempotent.
UPDATE scheduler_jobs
SET timeout_secs = 120
WHERE name = 'heartbeat-check' AND timeout_secs < 120;

-- ══════════════════════════════════════════════════════════════
-- SCHEDULER — Run history
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS scheduler_runs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id            UUID NOT NULL REFERENCES scheduler_jobs(id) ON DELETE CASCADE,
    job_name          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'success', 'failure', 'timeout', 'skipped')),
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at       TIMESTAMPTZ,
    duration_secs     INTEGER,
    attempt           INTEGER NOT NULL DEFAULT 1,
    result            JSONB DEFAULT '{}',
    error_msg         TEXT,
    pipeline_number   INTEGER,
    pipeline_link     TEXT,
    locked_by         TEXT
);

CREATE INDEX IF NOT EXISTS idx_sched_run_job     ON scheduler_runs (job_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sched_run_started ON scheduler_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sched_run_running ON scheduler_runs (job_id) WHERE status = 'running';

-- ══════════════════════════════════════════════════════════════
-- SCHEDULER — VIEW: jobs with latest run + 30d stats
-- ══════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_scheduler_summary AS
SELECT
    j.*,
    r.last_run_status,
    r.last_run_duration,
    r.last_run_error,
    COALESCE(s.total_runs_30d, 0)   AS total_runs_30d,
    COALESCE(s.success_count_30d, 0) AS success_count_30d,
    COALESCE(s.failure_count_30d, 0) AS failure_count_30d,
    COALESCE(s.avg_duration_30d, 0)  AS avg_duration_30d,
    EXISTS (
        SELECT 1 FROM scheduler_runs sr
        WHERE sr.job_id = j.id AND sr.status = 'running'
    ) AS is_running
FROM scheduler_jobs j
LEFT JOIN LATERAL (
    SELECT
        sr.status          AS last_run_status,
        sr.duration_secs   AS last_run_duration,
        sr.error_msg       AS last_run_error
    FROM scheduler_runs sr
    WHERE sr.job_id = j.id
    ORDER BY sr.started_at DESC LIMIT 1
) r ON true
LEFT JOIN LATERAL (
    SELECT
        COUNT(*)                                              AS total_runs_30d,
        COUNT(*) FILTER (WHERE sr.status = 'success')        AS success_count_30d,
        COUNT(*) FILTER (WHERE sr.status = 'failure')        AS failure_count_30d,
        ROUND(AVG(sr.duration_secs) FILTER (WHERE sr.duration_secs > 0))
                                                              AS avg_duration_30d
    FROM scheduler_runs sr
    WHERE sr.job_id = j.id AND sr.started_at > NOW() - INTERVAL '30 days'
) s ON true;

-- ══════════════════════════════════════════════════════════════
-- SCHEDULER — Seed predefined jobs
-- ══════════════════════════════════════════════════════════════

INSERT INTO scheduler_jobs (name, description, job_type, cron_expr, config, timeout_secs, enabled, created_by) VALUES
    ('ansible-collect',
     'Ansible inventory collection (all hosts)',
     'woodpecker_pipeline', '0 2 * * *',
     '{"repo_name": "youruser/cmdb", "branch": "main", "variables": {"PLAYBOOK": "collect"}}',
     900, false, 'system'),
    ('trivy-scan-nodes',
     'Trivy CVE scan of infrastructure nodes',
     'woodpecker_pipeline', '0 3 * * *',
     '{"repo_name": "youruser/cmdb", "branch": "main", "variables": {"PLAYBOOK": "scan_trivy"}}',
     1200, false, 'system'),
    ('trivy-scan-images',
     'Trivy CVE scan of CMDB Docker images',
     'woodpecker_pipeline', '0 4 * * *',
     '{"repo_name": "youruser/cmdb", "branch": "main", "variables": {"PLAYBOOK": "scan_images"}}',
     900, false, 'system'),
    ('woodpecker-sync',
     'Full sync: repos from forge + pipelines and workers from CI',
     'http_request', '0 */4 * * *',
     '{"method": "POST", "url": "/api/v1/cicd/sync", "expected_status": [200]}',
     120, false, 'system'),
    ('backup-check',
     'Check backup health and alert on failures',
     'http_request', '0 */6 * * *',
     '{"method": "GET", "url": "/api/v1/backup/alerts", "expected_status": [200]}',
     30, false, 'system'),
    ('cve-auto-resolve',
     'Auto-resolve CVEs with not_affected or will_not_fix status',
     'http_request', '0 6 * * 1',
     '{"method": "POST", "url": "/api/v1/findings/auto-resolve", "expected_status": [200]}',
     120, false, 'system'),
    ('drift-check',
     'Ansible drift detection — check configuration drift on all nodes',
     'woodpecker_pipeline', '0 3 * * *',
     '{"repo_name": "youruser/cmdb", "branch": "main", "variables": {"PLAYBOOK": "check_drift"}}',
     1800, false, 'system'),
    ('pkg-check-updates',
     'Check package repositories for available updates (APT/Pacman)',
     'http_request', '0 5 * * *',
     '{"method": "POST", "url": "/api/v1/pkg-repos/check-updates", "expected_status": [200]}',
     300, false, 'system'),
    ('ctr-check-updates',
     'Check container image registries for new versions (DockerHub/GHCR/GitLab/Harbor)',
     'http_request', '0 6 * * *',
     '{"method": "POST", "url": "/api/v1/repositories/check-all", "expected_status": [200]}',
     120, false, 'system'),
    ('token-expiry-check',
     'Check for API tokens expiring soon and send notifications',
     'http_request', '0 8 * * *',
     '{"method": "POST", "url": "/api/v1/tokens/check-expiry", "expected_status": [200]}',
     30, false, 'system'),
    ('retention-cleanup',
     'Purge old audit logs, pipeline runs, and resolved CVEs per retention settings',
     'http_request', '0 2 * * 0',
     '{"method": "POST", "url": "/api/v1/retention/run", "expected_status": [200]}',
     120, false, 'system')
ON CONFLICT (name) DO NOTHING;

-- Cleanup job from a previous iteration — remove if present
DELETE FROM scheduler_jobs WHERE name = 'refresh-v-all-cves';

-- ══════════════════════════════════════════════════════════════
-- SECRET ROTATION — alert at 330d, clear on rotation detected
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS secret_rotation_alerts (
    name                 TEXT PRIMARY KEY,
    alerted_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alerted_updated_at   TIMESTAMPTZ NOT NULL
);

INSERT INTO scheduler_jobs (name, description, job_type, cron_expr, config, timeout_secs, enabled, created_by) VALUES
    ('secret-rotation-check',
     'Alert when vault secrets approach 330-day rotation threshold',
     'http_request', '15 10 * * *',
     '{"method": "POST", "url": "/api/v1/settings/rotation-check", "expected_status": [200]}',
     60, true, 'system')
ON CONFLICT (name) DO NOTHING;

-- ══════════════════════════════════════════════════════════════
-- SBOM — Software Bill of Materials (CycloneDX)
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS sbom_components (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     UUID REFERENCES nodes(id) ON DELETE CASCADE,
    image_name  TEXT,
    bom_ref     TEXT,
    comp_type   TEXT NOT NULL DEFAULT 'library',
    name        TEXT NOT NULL,
    version     TEXT,
    purl        TEXT,
    licenses    JSONB DEFAULT '[]',
    supplier    TEXT,
    imported_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_sbom_component
    ON sbom_components (node_id, name, version, COALESCE(image_name, ''));

CREATE INDEX IF NOT EXISTS idx_sbom_node  ON sbom_components (node_id);
CREATE INDEX IF NOT EXISTS idx_sbom_name  ON sbom_components (name);
CREATE INDEX IF NOT EXISTS idx_sbom_purl  ON sbom_components (purl);

-- Saved filters
CREATE TABLE IF NOT EXISTS saved_filters (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    view        TEXT NOT NULL,
    filters     JSONB NOT NULL DEFAULT '{}',
    created_by  TEXT NOT NULL DEFAULT 'admin',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(name, created_by)
);

-- ══════════════════════════════════════════════════════════════
-- MIGRATIONS (safe to re-run)
-- ══════════════════════════════════════════════════════════════

-- Add drift_detected to automation_policies trigger_type CHECK
DO $$ BEGIN
    ALTER TABLE automation_policies
        DROP CONSTRAINT IF EXISTS automation_policies_trigger_type_check;
    ALTER TABLE automation_policies
        ADD CONSTRAINT automation_policies_trigger_type_check
        CHECK (trigger_type IN (
            'cve_detected','update_available','backup_overdue',
            'scan_stale','exposure_change','misconf_detected',
            'pipeline_failure','deploy_requested',
            'worker_offline','image_update_available',
            'drift_detected'
        ));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Add 'email' to automation_policies action CHECK
DO $$ BEGIN
    ALTER TABLE automation_policies
        DROP CONSTRAINT IF EXISTS automation_policies_action_check;
    ALTER TABLE automation_policies
        ADD CONSTRAINT automation_policies_action_check
        CHECK (action IN (
            'notify','auto_update','manual_validation',
            'rescan','ignore','create_deployment','pull_image',
            'create_incident','email'
        ));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
