# DO NOT REMOVE: SPDX header + copyright are part of the Apache-2.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Constellation · Author: shdw · License: Apache-2.0
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Stored CVE score maintenance — set-based re-score helpers.

The contextual score used to be computed by `cve_score()` (plpgsql) at
read time inside `v_all_cves` — a full scan + one interpreted function
call per row on every page view, unindexable, spilling sorts to disk
past `work_mem`. It is now a plain `score SMALLINT` column on
`cve_host_packages` / `cve_containers`, computed at write time and
served by an index, so `/cves?sort=score` is an index walk + LIMIT.

The trade is write-side invalidation: any change to a score input must
trigger a scoped re-score. Inputs and their writers:

  cvss_score / exploited / exploitability_context  (cve_catalog)
      -> collect ingest, OpenCVE webhook + NVD sync, findings PATCH
  fix_status / severity                            (finding row)
      -> collect ingest, findings PATCH
  exposure (repositories.listen, containers only)
      -> repositories collect/refresh

Every helper here is one set-based UPDATE: the score is computed once
per candidate row in a subquery, and `IS DISTINCT FROM` skips rewriting
rows whose score did not change (no dead-tuple churn on steady-state
re-scans).
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Structural fragments only — never interpolate user input here.
_HOST_RESCORE = """
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
    WHERE {scope}
) sub
WHERE sub.id = hp.id
  AND hp.score IS DISTINCT FROM sub.new_score
"""

_CONTAINER_RESCORE = """
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
    WHERE {scope}
) sub
WHERE sub.id = cc.id
  AND cc.score IS DISTINCT FROM sub.new_score
"""

_SCOPE_NODE_HOST = "hp2.node_id = CAST(:nid AS uuid)"
_SCOPE_NODE_CTR = "cc2.node_id = CAST(:nid AS uuid)"
_SCOPE_CVE_HOST = "hp2.cve_id = :cve"
_SCOPE_CVE_CTR = "cc2.cve_id = :cve"
_SCOPE_ID_HOST = "hp2.id = CAST(:fid AS uuid)"
_SCOPE_ID_CTR = "cc2.id = CAST(:fid AS uuid)"


async def rescore_node(db: AsyncSession, node_id: str) -> int:
    """Re-score every finding of one node (both tables).

    Called inside the ingest transaction, right after the upserts: the
    catalog rows are already visible, so freshly inserted findings get
    their score in the same commit (consistent immediately after
    ingest — no refresh step, no read-after-write gap).
    """
    r1 = await db.execute(
        text(_HOST_RESCORE.format(scope=_SCOPE_NODE_HOST)), {"nid": node_id}
    )
    r2 = await db.execute(
        text(_CONTAINER_RESCORE.format(scope=_SCOPE_NODE_CTR)), {"nid": node_id}
    )
    return (r1.rowcount or 0) + (r2.rowcount or 0)


async def rescore_cve(db: AsyncSession, cve_id: str) -> int:
    """Re-score every finding of one CVE across all nodes (both tables).

    Fired when catalog-level inputs flip: KEV/exploited propagation,
    NVD cvss refresh, operator PATCH on exploited/exploitability_context.
    Indexed on cve_id — bounded by the CVE's footprint, not table size.
    """
    r1 = await db.execute(
        text(_HOST_RESCORE.format(scope=_SCOPE_CVE_HOST)), {"cve": cve_id}
    )
    r2 = await db.execute(
        text(_CONTAINER_RESCORE.format(scope=_SCOPE_CVE_CTR)), {"cve": cve_id}
    )
    return (r1.rowcount or 0) + (r2.rowcount or 0)


async def rescore_finding(db: AsyncSession, table: str, finding_id: str) -> int:
    """Re-score a single finding row after a fix_status PATCH."""
    if table == "cve_host_packages":
        r = await db.execute(
            text(_HOST_RESCORE.format(scope=_SCOPE_ID_HOST)), {"fid": finding_id}
        )
    elif table == "cve_containers":
        r = await db.execute(
            text(_CONTAINER_RESCORE.format(scope=_SCOPE_ID_CTR)), {"fid": finding_id}
        )
    else:  # pragma: no cover - guarded by _TABLES in findings.py
        raise ValueError(f"unknown finding table: {table}")
    return r.rowcount or 0


async def rescore_node_containers(db: AsyncSession, node_id: str) -> int:
    """Re-score one node's container findings after exposure changes.

    `repositories.listen` feeds the exposure input of container scores;
    the repo collect/refresh path upserts listen per node, so a single
    node-scoped pass after the loop covers every image touched.
    """
    r = await db.execute(
        text(_CONTAINER_RESCORE.format(scope=_SCOPE_NODE_CTR)), {"nid": node_id}
    )
    return r.rowcount or 0
