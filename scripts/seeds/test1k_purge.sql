-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
-- Purge simulated data seeded by test1k.sql.
-- Cascades take care of packages / containers / cve_host_packages / cve_containers
-- via FK ON DELETE CASCADE on nodes + cve_catalog.

BEGIN;

DELETE FROM scheduler_jobs     WHERE name LIKE 'sim-%';
DELETE FROM container_managers WHERE name LIKE 'sim-%';
DELETE FROM cicd_servers       WHERE name LIKE 'sim-%';
DELETE FROM repositories       WHERE project_name LIKE 'sim-%';
DELETE FROM cve_catalog        WHERE cve_id LIKE 'CVE-SIM-%';
DELETE FROM nodes              WHERE hostname LIKE 'sim-%';
DELETE FROM package_catalog    WHERE name LIKE 'sim-pkg-%';
DELETE FROM container_images   WHERE image LIKE 'sim/%';

COMMIT;

\echo '═══ PURGE COMPLETE ═══'
