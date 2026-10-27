# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Repository / image tracking — version check via registry connectors."""

import asyncio
import logging
import re
import urllib.parse

import httpx
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_collect_token, require_permission
from ..connectors import get_registry
from ..connectors.registry import is_version_tag, tag_sortkey, tags_comparable
from ..database import get_db
from ..models.schemas import RepoCreate, RepoPatch
from ..utils.scoring import rescore_node_containers
from ..utils.sql import set_statement_timeout, where_clause
from .automation import run_evaluation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/repositories", tags=["repositories"])

# Bounded fan-out for check-all registry lookups. The same image:tag on many
# hosts is resolved once (per-run memo), then unique lookups run concurrently
# under this cap — fast at thousands of repos without hammering a registry.
_RESOLVE_CONCURRENCY = 8


async def _gather_bounded(coros: list) -> list:
    """Run coroutines with a concurrency cap, preserving input order."""
    sem = asyncio.Semaphore(_RESOLVE_CONCURRENCY)

    async def _run(c):
        async with sem:
            return await c

    return await asyncio.gather(*(_run(c) for c in coros))


# Manifest media types — request the index/list first so a multi-arch tag
# resolves to the SAME digest Docker records as the image's RepoDigest.
_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    )
)


def _detect_registry(image_name: str, registry: str) -> tuple[str, str]:
    """Auto-detect registry type and clean image name from full reference.

    Images like 'git.cybertron.fr:5050/group/repo' contain the registry host.
    Returns (registry_type, clean_image_name).
    """
    # If registry is already set to non-dockerhub, trust it
    if registry and registry != "dockerhub":
        return registry, image_name

    # Check if image contains a registry host (domain with . or port)
    first_part = image_name.split("/")[0]
    if "." in first_part or ":" in first_part:
        # Image has a registry host prefix — not a bare DockerHub name.
        if (
            first_part in ("docker.io", "registry-1.docker.io", "index.docker.io")
            and "/" in image_name
        ):
            # Explicit DockerHub host — strip it and use the Hub API, not OCI
            # (docker.io/v2 isn't DockerHub's tags endpoint). DockerHubRegistry
            # fills in the library/ default itself.
            return "dockerhub", image_name.split("/", 1)[1]
        if "ghcr.io" in first_part:
            # ghcr.io/owner/repo → strip ghcr.io/
            return "ghcr", image_name.replace("ghcr.io/", "", 1)
        # Private registry (GitLab, Harbor, etc.) — use OCI API
        return "oci", image_name

    # Plain image name (nginx, postgres) → DockerHub
    return "dockerhub", image_name


def _evaluate_update(current: str, latest: str | None) -> tuple[str | None, bool]:
    """Return (latest_tag_to_store, update_available).

    Only reports a latest tag when it is COMPARABLE to current (both version
    tags, same variant/suffix). For a non-version current tag (latest, main,
    stable, edge) or a different variant, returns (None, False) — otherwise the
    UI shows a misleading "latest -> 3.5" mismatch for tags that can't be
    compared. (Detecting updates for a 'latest'-pinned image needs digest
    comparison, not tag comparison — tracked separately.)
    """
    if latest and tags_comparable(current, latest):
        return latest, tag_sortkey(latest) > tag_sortkey(current)
    return None, False


def _pick_latest(raw_tags: list[str] | None, current_tag: str | None) -> str | None:
    """Highest version tag, restricted to current_tag's variant when known.

    A '3.18-alpine' image must not be compared against a higher '3.20' debian
    tag — picking the global highest then letting the caller's tags_comparable
    reject a different suffix means same-variant updates ('3.19-alpine') are
    silently missed (and the pick is non-deterministic when versions tie across
    suffixes). When current_tag is a version tag, only same-suffix candidates
    are considered; otherwise fall back to the global highest.
    """
    from ..connectors.registry import (
        _filter_tags,
        is_version_tag,
        tag_sortkey,
        tag_suffix,
    )

    tags = _filter_tags(raw_tags or [])
    if not tags:
        return None
    if current_tag and is_version_tag(current_tag):
        suffix = tag_suffix(current_tag)
        same_variant = [t for t in tags if tag_suffix(t) == suffix]
        if same_variant:
            tags = same_variant
    return sorted(tags, key=tag_sortkey, reverse=True)[0]


async def resolve_latest(
    image_name: str, registry: str, current_tag: str | None = None
) -> str | None:
    """Resolve latest tag for an image, matching current_tag's variant."""
    detected, clean_name = _detect_registry(image_name, registry)

    # OCI: private registry — query /v2/{name}/tags/list directly
    if detected == "oci":
        parts = clean_name.split("/", 1)
        host = parts[0]
        repo_path = parts[1] if len(parts) > 1 else ""
        if not repo_path:
            return None
        url = f"https://{host}/v2/{repo_path}/tags/list"
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(url, headers={"Accept": "application/json"})
                if r.status_code == 401:
                    # Try anonymous token auth (OCI spec)
                    www = r.headers.get("www-authenticate", "")
                    if "Bearer" in www:
                        import re

                        realm = re.search(r'realm="([^"]+)"', www)
                        scope = re.search(r'scope="([^"]+)"', www)
                        if realm:
                            token_url = realm.group(1)
                            if scope:
                                token_url += f"?scope={scope.group(1)}"
                            tr = await c.get(token_url)
                            if tr.status_code == 200:
                                token = tr.json().get("token", "")
                                r = await c.get(
                                    url,
                                    headers={
                                        "Authorization": f"Bearer {token}",
                                        "Accept": "application/json",
                                    },
                                )
                if r.status_code != 200:
                    return None
                return _pick_latest(r.json().get("tags", []), current_tag)
        except Exception as e:
            logger.warning("[registry] oci %s failed: %s", host, e)
            return None

    try:
        connector = get_registry(detected)
    except ValueError:
        return None
    return _pick_latest(await connector.list_tags(clean_name), current_tag)


# Digest comparison (latest-pinned images)


def _norm_digest(d: str | None) -> str | None:
    """Reduce a digest reference to its bare 'sha256:...' form.

    RepoDigests come as 'repo@sha256:...'; registry Docker-Content-Digest
    headers come as bare 'sha256:...'. Normalise both so they compare equal.
    """
    if not d:
        return None
    d = d.strip()
    if "@" in d:
        d = d.split("@", 1)[1]
    return d or None


def _evaluate_digest(current: str | None, remote: str | None) -> bool:
    """Update available when the deployed manifest digest differs from remote.

    Both sides must be present; a missing digest (locally-built image with no
    RepoDigest, or a tag we couldn't resolve) means "no signal" → no update.
    """
    cur = _norm_digest(current)
    rem = _norm_digest(remote)
    if not cur or not rem:
        return False
    return cur != rem


def _registry_host_repo(detected: str, clean_name: str) -> tuple[str, str] | None:
    """Map a detected registry + clean image name to (host, repo_path).

    Returns None when the reference has no repository path to query.
    """
    if detected == "dockerhub":
        repo = clean_name if "/" in clean_name else f"library/{clean_name}"
        return "registry-1.docker.io", repo
    if detected == "ghcr":
        return ("ghcr.io", clean_name) if "/" in clean_name else None
    # oci / private registry: host is the first path segment
    parts = clean_name.split("/", 1)
    if len(parts) < 2 or not parts[1]:
        return None
    return parts[0], parts[1]


async def _bearer_token(client: httpx.AsyncClient, www_authenticate: str) -> str | None:
    """Follow a registry 'Www-Authenticate: Bearer ...' challenge for a token.

    Includes the service= param (required by DockerHub/GHCR token endpoints).
    """
    realm = re.search(r'realm="([^"]+)"', www_authenticate)
    if not realm:
        return None
    query = {}
    service = re.search(r'service="([^"]+)"', www_authenticate)
    if service:
        query["service"] = service.group(1)
    scope = re.search(r'scope="([^"]+)"', www_authenticate)
    if scope:
        query["scope"] = scope.group(1)
    url = realm.group(1)
    if query:
        url += "?" + urllib.parse.urlencode(query)
    r = await client.get(url)
    if r.status_code != 200:
        return None
    body = r.json()
    return body.get("token") or body.get("access_token") or None


async def resolve_remote_digest(image_name: str, registry: str, tag: str) -> str | None:
    """Resolve the remote manifest digest of image:tag (Docker-Content-Digest).

    Works across DockerHub / GHCR / private OCI via the distribution API and an
    anonymous Bearer token dance. Returns the bare 'sha256:...' or None.
    """
    detected, clean_name = _detect_registry(image_name, registry)
    host_repo = _registry_host_repo(detected, clean_name)
    if not host_repo:
        return None
    host, repo = host_repo
    url = f"https://{host}/v2/{repo}/manifests/{tag}"
    headers = {"Accept": _MANIFEST_ACCEPT}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url, headers=headers)
            if r.status_code == 401:
                token = await _bearer_token(c, r.headers.get("www-authenticate", ""))
                if token:
                    r = await c.get(
                        url, headers={**headers, "Authorization": f"Bearer {token}"}
                    )
            if r.status_code != 200:
                return None
            return _norm_digest(r.headers.get("docker-content-digest"))
    except Exception as e:
        logger.warning("[registry] digest %s/%s failed: %s", host, repo, e)
        return None


# Routes


@router.get("")
async def list_repositories(
    project: str | None = None,
    update_available: bool | None = None,
    search: str | None = None,
    listen: str | None = None,
    registry: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("repositories", "r")),
):
    offset = (page - 1) * per_page
    clauses = []
    params: dict = {"limit": per_page, "offset": offset}
    if project:
        clauses.append("r.project_name ILIKE :project")
        params["project"] = f"%{project}%"
    if update_available is not None:
        clauses.append("r.update_available = :upd")
        params["upd"] = update_available
    if search:
        clauses.append(
            "(r.project_name ILIKE :search OR r.image_name ILIKE :search"
            " OR n.hostname ILIKE :search)"
        )
        params["search"] = f"%{search}%"
    if listen:
        clauses.append("r.listen = :listen")
        params["listen"] = listen
    if registry:
        clauses.append("r.registry = :registry")
        params["registry"] = registry
    where = where_clause(clauses)
    join_nodes = "LEFT JOIN nodes n ON n.id = r.node_id" if search else ""

    total = (
        await db.execute(
            text(f"SELECT COUNT(*) FROM repositories r {join_nodes} {where}"),
            params,
        )
    ).scalar_one()

    rows = await db.execute(
        text(f"""
        SELECT r.*, n.hostname
        FROM repositories r
        LEFT JOIN nodes n ON n.id = r.node_id
        {where}
        ORDER BY r.update_available DESC, r.project_name, r.image_name
        LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(row._mapping) for row in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.post("/report")
async def repository_report(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Ingest repository/image data from collectors (Ansible, scripts)."""
    await set_statement_timeout(db, "batch")
    hostname = payload.get("hostname", "")
    images = payload.get("images", [])

    node_row = await db.execute(
        text("SELECT id FROM nodes WHERE hostname = :h LIMIT 1"), {"h": hostname}
    )
    node_id = node_row.scalar_one_or_none()

    upserted = 0
    for img in images:
        image_name = img.get("image_name", "")
        if not image_name:
            continue
        await db.execute(
            text("""
            INSERT INTO repositories
                (project_name, image_name, registry, current_tag, current_digest,
                 auto_update_candidate, listen, node_id)
            VALUES
                (:project, :image, :registry, :tag, :digest,
                 :auto_update, :listen, :node_id)
            ON CONFLICT (image_name, current_tag, node_id) DO UPDATE SET
                current_digest      = EXCLUDED.current_digest,
                auto_update_candidate = EXCLUDED.auto_update_candidate,
                listen              = EXCLUDED.listen,
                updated_at          = NOW()
            """),
            {
                "project": img.get("project_name", image_name.split("/")[0]),
                "image": image_name,
                "registry": img.get("registry", "dockerhub"),
                "tag": img.get("current_tag", "latest"),
                "digest": img.get("current_digest"),
                "auto_update": img.get("auto_update_candidate", False),
                "listen": img.get("listen", "docker_internal"),
                "node_id": str(node_id) if node_id else None,
            },
        )
        upserted += 1

    # repositories.listen feeds the exposure input of the materialized
    # container CVE score — one node-scoped re-score pass after the loop.
    if upserted and node_id:
        await rescore_node_containers(db, str(node_id))

    await db.commit()
    return {"status": "ok", "upserted": upserted}


@router.post("/{repo_id}/check")
async def check_repository_version(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("repositories", "w")),
):
    """Check latest available version for a repository entry."""
    validate_uuid(repo_id, "repo_id")
    row = (
        (
            await db.execute(
                text("SELECT * FROM repositories WHERE id = :id LIMIT 1"),
                {"id": repo_id},
            )
        )
        .mappings()
        .first()
    )
    if not row:
        return {"error": "not found"}

    # Release the read transaction before the registry calls below — otherwise
    # the session sits "idle in transaction" for the whole HTTP round-trip
    # (resolve_latest + resolve_remote_digest's token dance), which trips the
    # PG watchdog (idle_in_tx_stuck). Network I/O must hold no open tx.
    await db.commit()

    latest = await resolve_latest(
        row["image_name"], row["registry"], row["current_tag"]
    )
    current = row["current_tag"] or ""
    latest_store, update_available = _evaluate_update(current, latest)

    # Tag comparison can't speak for latest-pinned tags (latest/main/stable/…):
    # compare the deployed manifest digest against the remote one instead.
    latest_digest = None
    if not update_available and not is_version_tag(current):
        remote_digest = await resolve_remote_digest(
            row["image_name"], row["registry"], current or "latest"
        )
        if remote_digest:
            latest_digest = remote_digest
            update_available = _evaluate_digest(row["current_digest"], remote_digest)

    await db.execute(
        text("""
        UPDATE repositories SET
            latest_tag_available = :latest,
            latest_digest        = :ldigest,
            update_available     = :upd,
            last_checked         = NOW()
        WHERE id = :id
        """),
        {
            "latest": latest_store,
            "ldigest": latest_digest,
            "upd": update_available,
            "id": repo_id,
        },
    )
    await db.commit()

    # Fire automation event if update is available
    if update_available:
        try:
            await run_evaluation(
                {
                    "trigger_type": "image_update_available",
                    "image": f"{row['image_name']}:{row['current_tag'] or 'latest'}",
                    "exposure": row.get("listen"),
                },
                db,
            )
            await db.commit()
        except Exception as e:
            logger.warning("[repos] automation eval failed: %s", e)

    return {
        "id": repo_id,
        "image_name": row["image_name"],
        "current_tag": row["current_tag"],
        "latest_tag_available": latest_store,
        "latest_digest": latest_digest,
        "update_available": update_available,
    }


@router.post("/check-all")
async def check_all_repositories(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("repositories", "w")),
):
    """Check latest versions for all repositories."""
    await set_statement_timeout(db, "batch")
    rows = (
        (
            await db.execute(
                text(
                    "SELECT id, image_name, registry, current_tag, current_digest "
                    "FROM repositories"
                )
            )
        )
        .mappings()
        .all()
    )
    # Release the read transaction before the registry calls — holding it open
    # across the HTTP fan-out leaves the session "idle in transaction" (trips
    # the PG idle_in_tx watchdog). Each repo gets its own short write tx below.
    await db.commit()

    # Resolve each UNIQUE (image, registry, tag) once — the same image:tag on N
    # hosts is N rows but one registry lookup. This collapses the dominant
    # redundancy at scale, then the unique lookups run concurrently (bounded).
    latest_keys = list(
        {(r["image_name"], r["registry"], r["current_tag"]) for r in rows}
    )
    latest_vals = await _gather_bounded([resolve_latest(*k) for k in latest_keys])
    latest_by_key = dict(zip(latest_keys, latest_vals))

    # Digest lookups only for the rows tag-comparison can't settle (latest-
    # pinned tags). Collect their unique keys, then resolve concurrently too.
    digest_keys: set = set()
    for row in rows:
        current = row["current_tag"] or ""
        _, upd = _evaluate_update(
            current,
            latest_by_key[(row["image_name"], row["registry"], row["current_tag"])],
        )
        if not upd and not is_version_tag(current):
            digest_keys.add((row["image_name"], row["registry"], current or "latest"))
    digest_klist = list(digest_keys)
    digest_vals = await _gather_bounded(
        [resolve_remote_digest(*k) for k in digest_klist]
    )
    digest_by_key = dict(zip(digest_klist, digest_vals))

    updated = 0
    for row in rows:
        latest = latest_by_key[(row["image_name"], row["registry"], row["current_tag"])]
        current = row["current_tag"] or ""
        latest_store, update_available = _evaluate_update(current, latest)

        latest_digest = None
        if not update_available and not is_version_tag(current):
            remote_digest = digest_by_key.get(
                (row["image_name"], row["registry"], current or "latest")
            )
            if remote_digest:
                latest_digest = remote_digest
                update_available = _evaluate_digest(
                    row["current_digest"], remote_digest
                )

        await db.execute(
            text("""
            UPDATE repositories SET
                latest_tag_available = :latest,
                latest_digest        = :ldigest,
                update_available     = :upd,
                last_checked         = NOW()
            WHERE id = :id
            """),
            {
                "latest": latest_store,
                "ldigest": latest_digest,
                "upd": update_available,
                "id": row["id"],
            },
        )
        # Commit this repo's write before moving to the next repo's network
        # I/O, so the tx never spans an HTTP call.
        await db.commit()
        updated += 1

        if update_available:
            try:
                await run_evaluation(
                    {
                        "trigger_type": "image_update_available",
                        "image": (
                            f"{row['image_name']}:{row['current_tag'] or 'latest'}"
                        ),
                    },
                    db,
                )
                await db.commit()
            except Exception as e:
                logger.warning("[repos] automation eval failed: %s", e)
                await db.rollback()

    return {"status": "ok", "checked": updated}


@router.post("")
async def create_repository(
    repo: RepoCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("repositories", "w")),
):
    """Create a repository entry manually from the UI."""
    result = await db.execute(
        text("""
        INSERT INTO repositories
            (project_name, image_name, registry, current_tag,
             auto_update_candidate, listen)
        VALUES
            (:project, :image, :registry, :tag, :auto_update, :listen)
        RETURNING id
        """),
        {
            "project": repo.project_name or repo.image_name.split("/")[0],
            "image": repo.image_name,
            "registry": repo.registry,
            "tag": repo.current_tag,
            "auto_update": repo.auto_update_candidate,
            "listen": repo.listen,
        },
    )
    new_id = str(result.scalar_one())
    await log_action(
        db,
        actor=actor,
        action="create_repository",
        target_type="repository",
        target_id=new_id,
        detail={"image_name": repo.image_name},
    )
    await db.commit()
    return {"status": "ok", "id": new_id}


@router.delete("/{repo_id}")
async def delete_repository(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("repositories", "w")),
):
    """Delete a repository entry."""
    validate_uuid(repo_id, "repo_id")
    await db.execute(text("DELETE FROM repositories WHERE id = :id"), {"id": repo_id})
    await log_action(
        db,
        actor=actor,
        action="delete_repository",
        target_type="repository",
        target_id=repo_id,
    )
    await db.commit()
    return {"status": "ok"}


@router.patch("/{repo_id}")
async def update_repository(
    repo_id: str,
    patch: RepoPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("repositories", "w")),
):
    """Update listen exposure or auto_update_candidate flag."""
    validate_uuid(repo_id, "repo_id")
    updates = patch.model_dump(exclude_none=True)
    if not updates:
        return {"error": "no valid fields"}
    sets = [f"{key} = :{key}" for key in updates]
    sets.append("updated_at = NOW()")
    params = {"id": repo_id, **updates}
    await db.execute(
        text(f"UPDATE repositories SET {', '.join(sets)} WHERE id = :id"), params
    )
    # listen feeds the exposure input of the materialized container CVE
    # score — re-score the repo's node when it changes.
    if "listen" in updates:
        node_row = await db.execute(
            text("SELECT node_id FROM repositories WHERE id = :id"), {"id": repo_id}
        )
        repo_node = node_row.scalar_one_or_none()
        if repo_node:
            await rescore_node_containers(db, str(repo_node))
    await log_action(
        db,
        actor=actor,
        action="update_repository",
        target_type="repository",
        target_id=repo_id,
        detail=updates,
    )
    await db.commit()
    return {"status": "ok"}
