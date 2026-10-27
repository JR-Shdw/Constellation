-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
-- ═══════════════════════════════════════════════════════════════════
-- Seed simulation X10 — 10000 nodes + proportional fixtures
-- 10000 nodes + ~1000 pkgs + ~300k installed + ~15k containers
-- + 3000 CVEs + ~100k cve_host_packages + ~45k cve_containers
-- + 100 repos + 5 forges + 5 managers + 10 scheduler jobs (disabled)
--
-- Prefix `sim-` / `CVE-SIM-` (same as test1k — purge via test1k_purge.sql).
-- Flush the DB between scales to avoid mixed states.
--
-- Usage on vega:
--   docker compose exec -T postgres psql -U cmdb -d cmdb < scripts/seeds/test10k.sql
-- Timing: ~3-5 min on PG 17 with default tuning.
-- ═══════════════════════════════════════════════════════════════════

BEGIN;

-- ─── 1. NODES — 10000 synthetic machines ─────────────────────────
INSERT INTO nodes (hostname, type, os, os_version, arch, environment, ip_address, is_active)
SELECT
  'sim-' || lpad(i::text, 5, '0'),
  (ARRAY['bare_metal','vm','container','workstation'])[1 + (i % 4)],
  (ARRAY['Debian GNU/Linux','Ubuntu','Rocky Linux','Arch Linux','AIX'])[1 + (i % 5)],
  (ARRAY['12','13','22.04','24.04','9','rolling','7.3'])[1 + (i % 7)],
  (ARRAY['x86_64','aarch64','ppc64le'])[1 + (i % 3)],
  (ARRAY['production','staging','development','lab'])[1 + (i % 4)],
  '10.99.' || ((i / 254) + 1) || '.' || ((i % 254) + 1),
  true
FROM generate_series(1, 10000) AS i
ON CONFLICT (hostname) DO NOTHING;

-- ─── 2. PACKAGE CATALOG — 1000 distinct packages ────────────────
INSERT INTO package_catalog (name, version, arch, manager)
SELECT
  'sim-pkg-' || lpad(i::text, 4, '0'),
  (i % 10)::text || '.' || ((i * 7) % 20)::text || '.' || ((i * 13) % 50)::text,
  'amd64',
  (ARRAY['apt','dpkg','rpm','pacman'])[1 + (i % 4)]
FROM generate_series(1, 1000) AS i
ON CONFLICT (name, version) DO NOTHING;

-- ─── 3. PACKAGES — ~30 per node = ~300k rows ────────────────────
INSERT INTO packages (node_id, package_id, available_ver)
SELECT n.id, p.id, NULL
FROM nodes n
CROSS JOIN LATERAL (
  SELECT id FROM package_catalog
  WHERE name LIKE 'sim-pkg-%'
  ORDER BY random()
  LIMIT 30
) p
WHERE n.hostname LIKE 'sim-%'
ON CONFLICT (node_id, package_id) DO NOTHING;

-- ─── 4. CONTAINER IMAGES — 120 distinct images ───────────────────
INSERT INTO container_images (image, tag)
SELECT
  'sim/svc-' || lpad(i::text, 3, '0'),
  (ARRAY['latest','v1.0','v2.3','edge','3.11','1.29-alpine'])[1 + (i % 6)]
FROM generate_series(1, 120) AS i
ON CONFLICT (image, tag) DO NOTHING;

-- ─── 5. CONTAINERS — 5 per node for 30% of nodes = ~15000 ────────
INSERT INTO containers (node_id, image_id, name, status, exposure, traefik, authelia)
SELECT
  n.id,
  img.id,
  'sim-ctr-' || n.hostname || '-' || gs,
  'running',
  (ARRAY['internet','vpn','private','docker_internal','localhost'])[1 + (gs % 5)],
  (gs % 3 = 0),
  (gs % 7 = 0)
FROM nodes n
CROSS JOIN generate_series(1, 5) AS gs
CROSS JOIN LATERAL (
  SELECT id FROM container_images WHERE image LIKE 'sim/%' ORDER BY random() LIMIT 1
) img
WHERE n.hostname LIKE 'sim-%' AND abs(hashtext(n.hostname)) % 10 < 3  -- ~30% of nodes
ON CONFLICT (node_id, name) DO NOTHING;

-- ─── 6. CVE CATALOG — 3000 CVEs with varied severity + KEV flag ─
INSERT INTO cve_catalog (cve_id, cvss_score, description, exploited, kev)
SELECT
  'CVE-SIM-' || lpad(i::text, 5, '0'),
  ROUND((CASE WHEN i % 10 < 2 THEN 9.0 + random()
              WHEN i % 10 < 5 THEN 7.0 + random() * 2
              WHEN i % 10 < 8 THEN 4.0 + random() * 3
              ELSE random() * 4 END)::numeric, 1),
  'Simulated CVE #' || i || ' — fabricated for scale testing.',
  (i % 20 = 0),   -- 5% exploited
  (i % 50 = 0)    -- 2% in KEV
FROM generate_series(1, 3000) AS i
ON CONFLICT (cve_id) DO NOTHING;

-- ─── 7. CVE HOST PACKAGES — 20 per 50% of nodes = ~100k rows ────
INSERT INTO cve_host_packages (node_id, cve_id, severity, pkg_name, installed_ver, fix_status, source)
SELECT
  n.id,
  c.cve_id,
  (ARRAY['critical','high','medium','low'])[1 + (abs(hashtext(c.cve_id)) % 4)],
  'sim-pkg-' || lpad(((abs(hashtext(c.cve_id || n.hostname))) % 1000 + 1)::text, 4, '0'),
  '1.0',
  (ARRAY['fixed_available','unfixed','not_affected'])[1 + (abs(hashtext(c.cve_id)) % 3)],
  (ARRAY['wazuh','trivy'])[1 + (abs(hashtext(n.hostname)) % 2)]
FROM nodes n
CROSS JOIN LATERAL (
  SELECT cve_id FROM cve_catalog
  WHERE cve_id LIKE 'CVE-SIM-%'
  ORDER BY random()
  LIMIT 20
) c
WHERE n.hostname LIKE 'sim-%' AND abs(hashtext(n.hostname || 'cve')) % 2 = 0
ON CONFLICT (node_id, cve_id, pkg_name) DO NOTHING;

-- ─── 8. CVE CONTAINERS — 5 per container for ~30% containers ────
INSERT INTO cve_containers (container_id, node_id, cve_id, severity, pkg_name, installed_ver, image)
SELECT
  ctr.id,
  ctr.node_id,
  c.cve_id,
  (ARRAY['critical','high','medium','low'])[1 + (abs(hashtext(c.cve_id)) % 4)],
  'sim-pkg-' || lpad(((abs(hashtext(c.cve_id))) % 1000 + 1)::text, 4, '0'),
  '1.0',
  (SELECT image || ':' || tag FROM container_images WHERE id = ctr.image_id)
FROM containers ctr
CROSS JOIN LATERAL (
  SELECT cve_id FROM cve_catalog WHERE cve_id LIKE 'CVE-SIM-%' ORDER BY random() LIMIT 5
) c
WHERE ctr.name LIKE 'sim-ctr-%' AND abs(hashtext(ctr.name)) % 10 < 3
ON CONFLICT DO NOTHING;

-- ─── 9. REPOSITORIES (Docker image repos) — 100 rows ────────────
INSERT INTO repositories (project_name, image_name, registry, current_tag, update_available, listen)
SELECT
  'sim-project-' || lpad(i::text, 3, '0'),
  'sim/svc-' || lpad((i % 120 + 1)::text, 3, '0'),
  (ARRAY['dockerhub','ghcr','gitlab','harbor'])[1 + (i % 4)],
  'v' || (i % 5 + 1)::text || '.0',
  (i % 3 = 0),
  (ARRAY['internet','private_network','localhost','docker_internal'])[1 + (i % 4)]
FROM generate_series(1, 100) AS i
ON CONFLICT DO NOTHING;

-- ─── 10. CI/CD SERVERS (forges + CI) ────────────────────────────
INSERT INTO cicd_servers (name, server_type, url, status) VALUES
  ('sim-gitea-1',      'gitea',      'https://sim.gitea.example.com',  'connected'),
  ('sim-forgejo-1',    'forgejo',    'https://sim.forgejo.example.com','connected'),
  ('sim-gitlab-1',     'gitlab',     'https://sim.gitlab.example.com', 'offline'),
  ('sim-woodpecker-1', 'woodpecker', 'https://sim.ci.example.com',     'connected'),
  ('sim-woodpecker-2', 'woodpecker', 'https://sim.ci2.example.com',    'error')
ON CONFLICT (name) DO NOTHING;

-- ─── 11. CONTAINER MANAGERS (Portainer endpoints) ────────────────
INSERT INTO container_managers (name, manager_type, url, status) VALUES
  ('sim-portainer-prod', 'portainer', 'https://sim.portainer.example.com',    'connected'),
  ('sim-portainer-lab',  'portainer', 'https://sim.portainer-lab.example.com','connected'),
  ('sim-docker-edge',    'docker',    'tcp://sim.docker-edge.example.com:2375','offline'),
  ('sim-portainer-dr',   'portainer', 'https://sim.portainer-dr.example.com', 'error'),
  ('sim-portainer-stag', 'portainer', 'https://sim.portainer-stag.example.com','connected')
ON CONFLICT (name) DO NOTHING;

-- ─── 12. SCHEDULER JOBS — 10 jobs, all DISABLED ─────────────────
INSERT INTO scheduler_jobs (name, description, job_type, enabled, cron_expr, config) VALUES
  ('sim-woodpecker-nightly', 'Simulated nightly CI', 'woodpecker_pipeline', false, '0 2 * * *',  '{"repo_name":"sim/example","branch":"main"}'),
  ('sim-gitlab-weekly',      'Simulated weekly CI',  'gitlab_pipeline',     false, '0 3 * * 0',  '{"repo_name":"sim/example","branch":"main"}'),
  ('sim-heartbeat-probe',    'Simulated HTTP probe', 'http_request',        false, '*/5 * * * *','{"method":"GET","url":"https://sim.example.com/ping"}'),
  ('sim-scan-trivy',         'Simulated Trivy scan', 'http_request',        false, '0 4 * * *',  '{"method":"POST","url":"/api/v1/scan/trivy"}'),
  ('sim-opencve-sync',       'Simulated OpenCVE',    'http_request',        false, '0 */2 * * *','{"method":"POST","url":"/api/v1/opencve/sync"}'),
  ('sim-backup-check',       'Simulated Restic',     'http_request',        false, '*/15 * * * *','{"method":"GET","url":"/api/v1/backup/status"}'),
  ('sim-image-check',        'Simulated image ver',  'http_request',        false, '0 6 * * *',  '{"method":"POST","url":"/api/v1/repositories/check-all"}'),
  ('sim-woodpecker-2',       'Simulated CI #2',      'woodpecker_pipeline', false, '30 2 * * *', '{"repo_name":"sim/other","branch":"main"}'),
  ('sim-misconf-scan',       'Simulated misconf',    'http_request',        false, '0 5 * * 1',  '{"method":"POST","url":"/api/v1/misconf/scan"}'),
  ('sim-sbom-refresh',       'Simulated SBOM',       'http_request',        false, '0 1 * * *',  '{"method":"POST","url":"/api/v1/sbom/refresh"}')
ON CONFLICT (name) DO NOTHING;

COMMIT;

-- ─── Sanity / scale report ──────────────────────────────────────
ANALYZE nodes, packages, containers, cve_host_packages, cve_containers,
        cve_catalog, repositories, cicd_servers, container_managers, scheduler_jobs;

\echo '═══ SEED X10 COMPLETE — row counts ═══'
SELECT 'nodes (sim)'          AS table_name, count(*) FROM nodes              WHERE hostname LIKE 'sim-%'
UNION ALL SELECT 'packages (sim)'         , count(*) FROM packages p JOIN nodes n ON p.node_id = n.id WHERE n.hostname LIKE 'sim-%'
UNION ALL SELECT 'containers (sim)'       , count(*) FROM containers WHERE name LIKE 'sim-ctr-%'
UNION ALL SELECT 'cve_catalog (sim)'      , count(*) FROM cve_catalog WHERE cve_id LIKE 'CVE-SIM-%'
UNION ALL SELECT 'cve_host_packages (sim)', count(*) FROM cve_host_packages WHERE cve_id LIKE 'CVE-SIM-%'
UNION ALL SELECT 'cve_containers (sim)'   , count(*) FROM cve_containers    WHERE cve_id LIKE 'CVE-SIM-%'
UNION ALL SELECT 'repositories (sim)'     , count(*) FROM repositories      WHERE project_name LIKE 'sim-%'
UNION ALL SELECT 'cicd_servers (sim)'     , count(*) FROM cicd_servers      WHERE name LIKE 'sim-%'
UNION ALL SELECT 'container_managers (sim)', count(*) FROM container_managers WHERE name LIKE 'sim-%'
UNION ALL SELECT 'scheduler_jobs (sim)'   , count(*) FROM scheduler_jobs    WHERE name LIKE 'sim-%'
ORDER BY table_name;
