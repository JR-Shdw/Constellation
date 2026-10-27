# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...audit import log_action, validate_uuid
from ...auth import require_permission
from ...database import get_db
from ...utils.sql import where_clause
from . import _get_cache, _set_cache, router


@router.get("/containers/hosts")
async def container_image_hosts(
    image: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Liste des hôtes, CVEs et repos pour une image Docker."""
    rows = await db.execute(
        text("""
        SELECT c.name, ci.image, ci.tag, c.status,
               c.exposure, c.traefik, c.authelia, c.geoip,
               c.port_bindings, c.networks,
               n.hostname, n.id AS node_id
        FROM containers c
        JOIN container_images ci ON ci.id = c.image_id
        JOIN nodes n ON n.id = c.node_id
        WHERE ci.image = :image
        ORDER BY n.hostname
    """),
        {"image": image},
    )
    items = [dict(r._mapping) for r in rows]

    cve_rows = await db.execute(
        text("""
        SELECT cc.cve_id, cc.severity, cat.cvss_score,
               cc.pkg_name, cc.installed_ver, cc.fixed_ver,
               cc.fix_status, COALESCE(cat.exploited, false) AS exploited,
               n.hostname, cc.node_id
        FROM cve_containers cc
        JOIN cve_catalog cat ON cat.cve_id = cc.cve_id
        JOIN nodes n ON n.id = cc.node_id
        WHERE cc.status = 'open'
          AND (cc.image = :image
               OR cc.image LIKE :image_tag
               OR regexp_replace(cc.image, ':[^:]*$', '') = :image)
        ORDER BY CASE cc.severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1
            WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
            cat.cvss_score DESC NULLS LAST
        LIMIT 50
        """),
        {"image": image, "image_tag": f"{image}:%"},
    )
    cves = [dict(r._mapping) for r in cve_rows]

    repo_rows = await db.execute(
        text("""
        SELECT r.id, r.project_name, r.image_name, r.current_tag,
               r.latest_tag_available, r.update_available, r.listen,
               r.last_checked, n.hostname
        FROM repositories r
        LEFT JOIN nodes n ON n.id = r.node_id
        WHERE r.image_name = :image
        ORDER BY r.project_name
        """),
        {"image": image},
    )
    repos = [dict(r._mapping) for r in repo_rows]

    # All image:tag rows, including ones with no running container
    # (ghosts). UI uses this to offer manual cleanup.
    image_rows = await db.execute(
        text("""
        SELECT ci.id, ci.tag, ci.last_updated,
               (SELECT COUNT(*) FROM containers c WHERE c.image_id = ci.id)
                   AS container_count
        FROM container_images ci
        WHERE ci.image = :image
        ORDER BY ci.tag
        """),
        {"image": image},
    )
    images = [dict(r._mapping) for r in image_rows]

    return {"items": items, "cves": cves, "repos": repos, "images": images}


@router.get("/containers")
async def list_containers(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    image: str | None = None,
    tag: str | None = None,
    node_id: str | None = None,
    hostname: str | None = None,
    search: str | None = None,
    group: bool = Query(True),
    sort_by: str | None = None,
    sort_dir: str = Query("asc"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    offset = (page - 1) * per_page
    params: dict = {"limit": per_page, "offset": offset}
    clauses = []
    if search:
        clauses.append(
            "(c.name ILIKE :search OR ci.image ILIKE :search"
            " OR n.hostname ILIKE :search)"
        )
        params["search"] = f"%{search}%"
    if image:
        clauses.append("ci.image ILIKE :image")
        params["image"] = f"%{image}%"
    if node_id:
        clauses.append("c.node_id = CAST(:node_id AS uuid)")
        params["node_id"] = node_id
    if hostname:
        clauses.append("n.hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"
    if tag:
        clauses.append("ci.tag ILIKE :tag")
        params["tag"] = f"%{tag}%"
    where = where_clause(clauses)

    _CTR_SORT = {
        "name": "c.name",
        "image": "ci.image",
        "tag": "ci.tag",
        "exposure": "exposure",
        "hosts": "host_count",
    }
    ctr_dir = "DESC" if sort_dir == "desc" else "ASC"
    ctr_order = (
        f"{_CTR_SORT[sort_by]} {ctr_dir}, c.name"
        if sort_by in _CTR_SORT
        else "ci.image, c.name"
    )

    _ctr_joins = (
        "FROM containers c"
        " JOIN container_images ci ON ci.id = c.image_id"
        " JOIN nodes n ON n.id = c.node_id"
    )

    if group:
        count_result = await db.execute(
            text(f"""
            SELECT COUNT(*) FROM (
                SELECT 1 {_ctr_joins}
                {where}
                GROUP BY c.name, ci.image, ci.tag
            ) sub
        """),
            params,
        )
        total = count_result.scalar_one()

        rows = await db.execute(
            text(f"""
            SELECT c.name, ci.image, ci.tag,
                   COUNT(*) AS host_count,
                   ARRAY_AGG(DISTINCT n.hostname ORDER BY n.hostname) AS hostnames,
                   -- Most-exposed wins, not MAX() (which is lexicographic and
                   -- would mask an 'internet' instance behind 'localhost'/'vpn'/
                   -- 'wireguard' that sort higher). Mirrors the detail ranking.
                   (ARRAY_AGG(c.exposure ORDER BY CASE c.exposure
                        WHEN 'internet' THEN 0
                        WHEN 'vpn' THEN 1 WHEN 'wireguard' THEN 1
                        WHEN 'private' THEN 1
                        WHEN 'localhost' THEN 2
                        WHEN 'docker_internal' THEN 3
                        ELSE 4 END))[1] AS exposure,
                   BOOL_OR(c.traefik) AS traefik,
                   BOOL_OR(c.authelia) AS authelia,
                   BOOL_OR(c.geoip) AS geoip
            {_ctr_joins}
            {where}
            GROUP BY c.name, ci.image, ci.tag
            ORDER BY {ctr_order}
            LIMIT :limit OFFSET :offset
        """),
            params,
        )
    else:
        count_result = await db.execute(
            text(f"SELECT COUNT(*) {_ctr_joins} {where}"),
            params,
        )
        total = count_result.scalar_one()

        rows = await db.execute(
            text(f"""
            SELECT c.id, c.name, ci.image, ci.tag, c.status,
                   c.exposure, c.traefik, c.authelia, c.geoip,
                   c.port_bindings, c.networks,
                   n.hostname, n.id AS node_id
            {_ctr_joins}
            {where}
            ORDER BY ci.image, n.hostname
            LIMIT :limit OFFSET :offset
        """),
            params,
        )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/exposure")
async def exposure_summary(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("read", "r")),
):
    """Exposure summary + detailed container list."""
    cached = _get_cache("exposure")
    if cached:
        return cached

    summary = await db.execute(text("SELECT * FROM v_exposure_summary"))
    detail = await db.execute(
        text("""
        SELECT c.id AS container_id, c.name, ci.image, ci.tag, c.exposure,
               c.traefik, c.authelia, c.geoip,
               c.exposure_manual_at IS NOT NULL AS exposure_manual,
               c.flags_manual_at    IS NOT NULL AS flags_manual,
               c.port_bindings, c.networks, n.hostname, n.id AS node_id
        FROM containers c
        JOIN container_images ci ON ci.id = c.image_id
        JOIN nodes n ON n.id = c.node_id
        WHERE n.is_active = true
        ORDER BY
            -- Match the grouped-list ranking: 'vpn' is the canonical private
            -- value the classifier writes ('wireguard'/'private' are legacy
            -- aliases). Omitting 'vpn' sorted real private containers into the
            -- ELSE bucket, below docker_internal, in the exposure matrix.
            CASE c.exposure WHEN 'internet' THEN 0
                 WHEN 'vpn' THEN 1 WHEN 'wireguard' THEN 1 WHEN 'private' THEN 1
                 WHEN 'localhost' THEN 2 WHEN 'docker_internal' THEN 3 ELSE 4 END,
            n.hostname, c.name
    """)
    )
    result = {
        "summary": [dict(r._mapping) for r in summary],
        "items": [dict(r._mapping) for r in detail],
    }
    _set_cache("exposure", result)
    return result


_VALID_EXPOSURES = (
    "internet",
    "vpn",
    "private",
    "docker_internal",
    "localhost",
    "none",
    "unknown",
)


@router.patch("/containers/{container_id}/exposure")
async def patch_container_exposure(
    container_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("read", "w")),
):
    """Override exposure/badges for a container.

    Setting `exposure` or any of the 4 flags marks the override as manual
    so subsequent /nodes/report collects don't overwrite it.

    Pass `reset_manual` ("exposure" | "flags" | "all") to clear the lock
    and re-enable auto-detection on the next collect.
    """
    validate_uuid(container_id)
    detail = {}

    reset = body.get("reset_manual")
    if reset in ("exposure", "all"):
        await db.execute(
            text(
                "UPDATE containers SET exposure_manual_at = NULL "
                "WHERE id = CAST(:cid AS uuid)"
            ),
            {"cid": container_id},
        )
        detail["reset_exposure_manual"] = True
    if reset in ("flags", "all"):
        await db.execute(
            text(
                "UPDATE containers SET flags_manual_at = NULL "
                "WHERE id = CAST(:cid AS uuid)"
            ),
            {"cid": container_id},
        )
        detail["reset_flags_manual"] = True

    if "exposure" in body:
        exposure = body["exposure"]
        if exposure not in _VALID_EXPOSURES:
            raise HTTPException(400, f"exposure must be one of {_VALID_EXPOSURES}")
        await db.execute(
            text("""UPDATE containers
                       SET exposure = :exp,
                           exposure_manual_at = NOW()
                     WHERE id = CAST(:cid AS uuid)"""),
            {"cid": container_id, "exp": exposure},
        )
        detail["exposure"] = exposure

    flag_changes = {
        f: bool(body[f])
        for f in ("traefik", "authelia", "geoip", "firewall")
        if f in body
    }
    if flag_changes:
        sets = ", ".join(f"{k} = :{k}" for k in flag_changes)
        await db.execute(
            text(f"""UPDATE containers
                        SET {sets},
                            flags_manual_at = NOW()
                      WHERE id = CAST(:cid AS uuid)"""),
            {"cid": container_id, **flag_changes},
        )
        detail.update(flag_changes)

    if detail:
        await log_action(
            db,
            actor=actor,
            action="patch_exposure",
            target_type="container",
            target_id=container_id,
            detail=detail,
        )
        await db.commit()
    return {"status": "ok"}
