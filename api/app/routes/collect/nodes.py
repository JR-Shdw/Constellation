# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import json

from fastapi import Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_collect_token
from ...database import get_db
from ...models.schemas import NodeReport, NodesBatchReport
from ...utils.sql import set_statement_timeout
from ..automation import run_evaluation
from . import (
    _chunks,
    _classify_exposure,
    _detect_middlewares,
    _exposure_to_listen,
    _has_traefik,
    logger,
    router,
)


async def _process_node_report(payload: NodeReport, db: AsyncSession) -> str:
    """Core ingestion logic — upsert node + packages + containers.

    Caller is responsible for committing and clearing caches.
    """
    result = await db.execute(
        text("""
        INSERT INTO nodes
            (hostname, type, os, os_version, arch, kernel,
             os_raw, hw_info, ip_address)
        VALUES
            (:hostname, :type, :os, :os_version, :arch, :kernel,
             :os_raw, CAST(:hw_info AS jsonb), :ip_address)
        ON CONFLICT (hostname) DO UPDATE SET
            type       = EXCLUDED.type,
            os         = EXCLUDED.os,
            os_version = EXCLUDED.os_version,
            arch       = EXCLUDED.arch,
            kernel     = EXCLUDED.kernel,
            os_raw     = EXCLUDED.os_raw,
            hw_info    = EXCLUDED.hw_info,
            ip_address = COALESCE(EXCLUDED.ip_address, nodes.ip_address),
            check_address = CASE
                WHEN nodes.check_address IS NULL
                THEN COALESCE(EXCLUDED.ip_address, nodes.ip_address)
                ELSE nodes.check_address
            END,
            last_seen  = NOW(),
            is_active  = true
        RETURNING id
    """),
        {
            "hostname": payload.hostname,
            "type": (
                ",".join(payload.type)
                if isinstance(payload.type, list)
                else payload.type
            ),
            "os": payload.os,
            "os_version": payload.kernel
            if payload.os in ("archlinux", "arch", "manjaro")
            and (not payload.os_version or payload.os_version == "rolling")
            else payload.os_version,
            "arch": payload.arch,
            "kernel": payload.kernel,
            "os_raw": payload.os_raw,
            "hw_info": json.dumps(payload.hw_info)
            if isinstance(payload.hw_info, dict)
            else payload.hw_info,
            "ip_address": payload.ip_address,
        },
    )
    node_id = str(result.scalar_one())

    await db.execute(
        text("DELETE FROM packages WHERE node_id = :nid"), {"nid": node_id}
    )
    pkg_rows = []
    for line in payload.packages:
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) >= 2:
            pkg_rows.append(
                {
                    "name": parts[0],
                    "version": parts[1],
                    "arch": parts[2] if len(parts) > 2 else None,
                }
            )

    seen_pkgs: set = set()
    cat_rows = []
    for r in pkg_rows:
        key = (r["name"], r["version"])
        if key not in seen_pkgs:
            seen_pkgs.add(key)
            cat_rows.append(r)

    for batch in _chunks(cat_rows, 500):
        values = ", ".join(f"(:n_{i}, :v_{i}, :a_{i})" for i in range(len(batch)))
        params: dict = {}
        for i, r in enumerate(batch):
            params[f"n_{i}"] = r["name"]
            params[f"v_{i}"] = r["version"]
            params[f"a_{i}"] = r["arch"]
        await db.execute(
            text(f"""
            INSERT INTO package_catalog (name, version, arch)
            VALUES {values}
            ON CONFLICT (name, version) DO UPDATE SET
                arch = COALESCE(EXCLUDED.arch, package_catalog.arch),
                last_updated = NOW()
            """),
            params,
        )

    for batch in _chunks(pkg_rows, 500):
        values = ", ".join(f"(:n_{i}, :v_{i})" for i in range(len(batch)))
        params = {"nid": node_id}
        for i, r in enumerate(batch):
            params[f"n_{i}"] = r["name"]
            params[f"v_{i}"] = r["version"]
        await db.execute(
            text(f"""
            INSERT INTO packages (node_id, package_id)
            SELECT CAST(:nid AS uuid), pc.id
            FROM (VALUES {values}) AS v(name, version)
            JOIN package_catalog pc
                ON pc.name = v.name AND pc.version = v.version
            ON CONFLICT (node_id, package_id) DO NOTHING
            """),
            params,
        )

    old_exposure = {}
    old_rows = await db.execute(
        text("SELECT name, exposure FROM containers WHERE node_id = :nid"),
        {"nid": node_id},
    )
    for r in old_rows:
        old_exposure[r.name] = r.exposure

    # Collect names from the new payload to delete stale containers AFTER upsert.
    # We no longer DELETE-then-INSERT because that wiped manual override timestamps
    # (exposure_manual_at, flags_manual_at).
    payload_container_names: set[str] = set()

    host_geoip = str(getattr(payload, "host_geoip", "") or "").strip()
    host_firewall = str(getattr(payload, "host_firewall", "") or "").strip()
    has_host_geoip = host_geoip not in ("", "none")
    has_host_firewall = host_firewall not in ("", "none")

    for c in payload.containers:
        if isinstance(c, str):
            try:
                c = json.loads(c)
            except json.JSONDecodeError:
                continue
        if isinstance(c, dict):
            image_full = c.get("image", "")
            image_parts = image_full.rsplit(":", 1)
            image = image_parts[0]
            tag = image_parts[1] if len(image_parts) > 1 else "latest"

            port_bindings = c.get("port_bindings", [])
            networks = c.get("networks", [])
            labels = c.get("labels", {})
            digest = c.get("digest", "")

            exposure = _classify_exposure(port_bindings)
            traefik = _has_traefik(labels)
            authelia, geoip = _detect_middlewares(labels)

            if has_host_geoip and traefik:
                geoip = True
            firewall = has_host_firewall

            img_row = await db.execute(
                text("""
                INSERT INTO container_images (image, tag)
                VALUES (:image, :tag)
                ON CONFLICT (image, tag) DO UPDATE SET
                    last_updated = NOW()
                RETURNING id
                """),
                {"image": image, "tag": tag},
            )
            image_id = str(img_row.scalar_one())

            cname = c.get("name", "unknown")
            payload_container_names.add(cname)

            await db.execute(
                text("""
                INSERT INTO containers
                    (node_id, image_id, name, status,
                     digest, networks, port_bindings, labels,
                     exposure, traefik, authelia, geoip, firewall)
                VALUES
                    (:nid, CAST(:img_id AS uuid), :name, :status,
                     :digest, CAST(:networks AS jsonb),
                     CAST(:port_bindings AS jsonb),
                     CAST(:labels AS jsonb),
                     :exposure, :traefik, :authelia, :geoip, :firewall)
                ON CONFLICT (node_id, name) DO UPDATE SET
                    image_id      = EXCLUDED.image_id,
                    status        = EXCLUDED.status,
                    digest        = EXCLUDED.digest,
                    networks      = EXCLUDED.networks,
                    port_bindings = EXCLUDED.port_bindings,
                    labels        = EXCLUDED.labels,
                    exposure      = CASE
                        WHEN containers.exposure_manual_at IS NULL
                        THEN EXCLUDED.exposure ELSE containers.exposure END,
                    traefik       = CASE
                        WHEN containers.flags_manual_at IS NULL
                        THEN EXCLUDED.traefik ELSE containers.traefik END,
                    authelia      = CASE
                        WHEN containers.flags_manual_at IS NULL
                        THEN EXCLUDED.authelia ELSE containers.authelia END,
                    geoip         = CASE
                        WHEN containers.flags_manual_at IS NULL
                        THEN EXCLUDED.geoip ELSE containers.geoip END,
                    firewall      = CASE
                        WHEN containers.flags_manual_at IS NULL
                        THEN EXCLUDED.firewall ELSE containers.firewall END,
                    collected_at  = NOW()
            """),
                {
                    "nid": node_id,
                    "img_id": image_id,
                    "name": cname,
                    "status": c.get("status", ""),
                    "digest": digest,
                    "networks": json.dumps(networks),
                    "port_bindings": json.dumps(port_bindings),
                    "labels": json.dumps(labels),
                    "exposure": exposure,
                    "traefik": traefik,
                    "authelia": authelia,
                    "geoip": geoip,
                    "firewall": firewall,
                },
            )

    # Drop stale containers (present before, absent in this report) — preserves
    # manual override timestamps for containers still reported.
    if payload_container_names:
        await db.execute(
            text("DELETE FROM containers WHERE node_id = :nid AND name <> ALL(:names)"),
            {"nid": node_id, "names": list(payload_container_names)},
        )
    else:
        await db.execute(
            text("DELETE FROM containers WHERE node_id = :nid"),
            {"nid": node_id},
        )

    for c in payload.containers:
        if isinstance(c, str):
            try:
                c = json.loads(c)
            except json.JSONDecodeError:
                continue
        if not isinstance(c, dict):
            continue
        cname = c.get("name", "")
        new_exp = _classify_exposure(c.get("port_bindings", []))
        old_exp = old_exposure.get(cname)
        if old_exp and old_exp != new_exp:
            try:
                await run_evaluation(
                    {
                        "trigger_type": "exposure_change",
                        "hostname": payload.hostname,
                        "container": cname,
                        "image": c.get("image", ""),
                        # Normalize to the listen/scoring vocabulary so
                        # match_exposure (e.g. ["private_network"]) matches the
                        # same way it does for image_update_available events.
                        "exposure": _exposure_to_listen(new_exp),
                    },
                    db,
                )
            except Exception as e:
                logger.warning(
                    "[collect] exposure_change eval failed for %s: %s", cname, e
                )

    for c in payload.containers:
        if isinstance(c, str):
            try:
                c = json.loads(c)
            except json.JSONDecodeError:
                continue
        if not isinstance(c, dict):
            continue
        image_full = c.get("image", "")
        if not image_full:
            continue
        image_parts = image_full.rsplit(":", 1)
        image = image_parts[0]
        tag = image_parts[1] if len(image_parts) > 1 else "latest"
        if not image or image.startswith("sha256"):
            continue
        exposure = _classify_exposure(c.get("port_bindings", []))
        listen = _exposure_to_listen(exposure)
        project = image.split("/")[0] if "/" in image else "library"
        registry = "ghcr" if "ghcr.io" in image else "dockerhub"
        await db.execute(
            text("""
            INSERT INTO repositories
                (project_name, image_name, registry, current_tag,
                 current_digest, listen, node_id)
            VALUES
                (:project, :image, :registry, :tag,
                 :digest, :listen, :node_id)
            ON CONFLICT (image_name, current_tag, node_id) DO UPDATE SET
                current_digest = COALESCE(EXCLUDED.current_digest,
                                          repositories.current_digest),
                listen         = EXCLUDED.listen,
                updated_at     = NOW()
            """),
            {
                "project": project,
                "image": image,
                "registry": registry,
                "tag": tag,
                "digest": c.get("digest"),
                "listen": listen,
                "node_id": node_id,
            },
        )

    return node_id


@router.post("/nodes/report")
async def node_report(
    payload: NodeReport,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Endpoint collecte Ansible — upsert node + packages + containers."""
    await set_statement_timeout(db, "batch")
    node_id = await _process_node_report(payload, db)
    await db.commit()

    from ..read import _cache

    _cache.clear()

    return {"status": "ok", "node_id": node_id, "hostname": payload.hostname}


@router.post("/nodes/report-batch")
async def node_report_batch(
    payload: NodesBatchReport,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Bulk collecte Ansible — upsert N nodes dans une seule transaction.

    Commit unique à la fin + un seul cache clear. En cas d'erreur sur un
    node, tout le batch est rollback et une 500 est retournée.
    """
    await set_statement_timeout(db, "batch")
    results = []
    try:
        for item in payload.items:
            node_id = await _process_node_report(item, db)
            results.append({"node_id": node_id, "hostname": item.hostname})
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        logger.warning("[collect] nodes/report-batch failed: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Batch failed, all rolled back: {e.__class__.__name__}",
        ) from e

    from ..read import _cache

    _cache.clear()

    return {"status": "ok", "count": len(results), "items": results}
