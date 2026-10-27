# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Package repositories — OS repo management (APT, DNF, Pacman…)."""

import gzip
import io
import logging
import tarfile

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..database import get_db
from ..utils.sql import set_statement_timeout, where_clause

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/pkg-repos", tags=["pkg-repos"])

# Decompression-bomb guards for repo metadata fetched from operator-configured
# mirrors. A small Packages.gz / .db can expand to gigabytes; cap the
# decompressed output so a malicious or corrupt mirror can't OOM the API.
# Real APT Packages files are a few MB; pacman desc members are tiny.
_MAX_DECOMPRESSED = 128 * 1024 * 1024  # 128 MB
_MAX_TAR_MEMBER = 4 * 1024 * 1024  # 4 MB per .db member


def _safe_gunzip(data: bytes, cap: int = _MAX_DECOMPRESSED) -> str:
    """Decompress gzip data, raising if it expands past `cap` (bomb guard)."""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        out = gz.read(cap + 1)
    if len(out) > cap:
        raise ValueError("gzip output exceeds decompression cap")
    return out.decode(errors="replace")


# Version comparison (dpkg-compatible)
def _split_epoch(v: str) -> tuple[int, str]:
    if ":" in v:
        e, rest = v.split(":", 1)
        try:
            return int(e), rest
        except ValueError:
            return 0, v
    return 0, v


def _split_rev(v: str) -> tuple[str, str]:
    """Split upstream-version from the debian-revision (last hyphen)."""
    idx = v.rfind("-")
    return (v[:idx], v[idx + 1 :]) if idx >= 0 else (v, "")


def _order(c: str) -> int:
    """dpkg character ordering: '~' first, then letters, then other punct.

    Digits are handled separately by the numeric path; end-of-string is 0.
    """
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Faithful port of dpkg's verrevcmp for one version part.

    Alternates non-digit and numeric segments. Terminates on every input —
    the previous hand-rolled version infinite-looped on e.g. ('1.2.0','1.2')
    because a trailing non-digit segment never advanced the cursor.
    """
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        # Non-digit run: compare char by char; past end-of-string orders as 0
        # so '~' (-1) < end < other punctuation.
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _order(a[i]) if i < la else 0
            bc = _order(b[j]) if j < lb else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        # Numeric run: skip leading zeros, then a longer significant run (or a
        # larger leading digit) wins.
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        first_diff = 0
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff != 0:
            return first_diff
    return 0


def _vercmp(a: str, b: str) -> int:
    """Compare two package versions: <0, 0, or >0 (epoch:upstream-revision)."""
    ea, ra = _split_epoch(a)
    eb, rb = _split_epoch(b)
    if ea != eb:
        return -1 if ea < eb else 1
    ua, da = _split_rev(ra)
    ub, db = _split_rev(rb)
    c = _verrevcmp(ua, ub)
    if c != 0:
        return c
    return _verrevcmp(da, db)


def _ver_gt(a: str, b: str) -> bool:
    """Return True if version *a* is strictly greater than *b*.

    Faithful to dpkg's algorithm (epoch, upstream, revision; '~' sorts before
    everything, letters before other punctuation, numeric runs compared as
    integers). Used for APT/DNF/Pacman/generic version strings.
    """
    return _vercmp(a, b) > 0


_VALID_OS = {
    "debian",
    "ubuntu",
    "centos",
    "rocky",
    "rhel",
    "archlinux",
    "aix",
    "fedora",
    "generic",
}


@router.get("")
async def list_pkg_repos(
    os_family: str | None = Query(None),
    repo_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("repositories", "r")),
):
    where = []
    params: dict = {}
    if os_family:
        where.append("os_family = :os")
        params["os"] = os_family
    if repo_type:
        where.append("repo_type = :rt")
        params["rt"] = repo_type
    clause = where_clause(where)
    rows = await db.execute(
        text(
            f"SELECT * FROM package_repositories {clause} "
            "ORDER BY os_family, repo_type, name"
        ),
        params,
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.post("")
async def create_pkg_repo(
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("repositories", "w")),
):
    name = (body.get("name") or "").strip()
    os_family = (body.get("os_family") or "").strip().lower()
    url = (body.get("url") or "").strip()
    if not name or not url:
        raise HTTPException(400, "name and url required")
    if os_family not in _VALID_OS:
        valid = ", ".join(sorted(_VALID_OS))
        raise HTTPException(400, f"os_family must be one of: {valid}")

    row = await db.execute(
        text("""
        INSERT INTO package_repositories
            (name, os_family, url, repo_type, enabled,
             description, components, distribution, gpg_key_url)
        VALUES
            (:name, :os, :url, :rt, :enabled,
             :desc, :comp, :dist, :gpg)
        ON CONFLICT (name, os_family) DO UPDATE SET
            url = EXCLUDED.url,
            repo_type = EXCLUDED.repo_type,
            description = EXCLUDED.description,
            components = EXCLUDED.components,
            distribution = EXCLUDED.distribution,
            gpg_key_url = EXCLUDED.gpg_key_url,
            updated_at = NOW()
        RETURNING id
        """),
        {
            "name": name,
            "os": os_family,
            "url": url,
            "rt": body.get("repo_type", "custom"),
            "enabled": body.get("enabled", True),
            "desc": body.get("description"),
            "comp": body.get("components"),
            "dist": body.get("distribution"),
            "gpg": body.get("gpg_key_url"),
        },
    )
    repo_id = str(row.scalar_one())
    await log_action(
        db,
        actor=actor,
        action="create_pkg_repo",
        target_type="pkg_repo",
        target_id=repo_id,
        detail={"name": name, "os_family": os_family},
    )
    await db.commit()
    return {"status": "ok", "id": repo_id}


@router.patch("/{repo_id}")
async def patch_pkg_repo(
    repo_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("repositories", "w")),
):
    validate_uuid(repo_id)
    allowed = {
        "name",
        "url",
        "repo_type",
        "enabled",
        "description",
        "components",
        "distribution",
        "gpg_key_url",
    }
    sets = []
    params: dict = {"rid": repo_id}
    for k, v in body.items():
        if k in allowed:
            sets.append(f"{k} = :{k}")
            params[k] = v
    if not sets:
        return {"status": "ok", "changed": False}
    sets.append("updated_at = NOW()")
    await db.execute(
        text(
            f"UPDATE package_repositories SET {', '.join(sets)} "
            "WHERE id = CAST(:rid AS uuid)"
        ),
        params,
    )
    await log_action(
        db,
        actor=actor,
        action="update_pkg_repo",
        target_type="pkg_repo",
        target_id=repo_id,
    )
    await db.commit()
    return {"status": "ok", "changed": True}


@router.delete("/{repo_id}")
async def delete_pkg_repo(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("repositories", "w")),
):
    validate_uuid(repo_id)
    result = await db.execute(
        text("DELETE FROM package_repositories WHERE id = CAST(:rid AS uuid)"),
        {"rid": repo_id},
    )
    if result.rowcount == 0:
        raise HTTPException(404, "Repository not found")
    await log_action(
        db,
        actor=actor,
        action="delete_pkg_repo",
        target_type="pkg_repo",
        target_id=repo_id,
    )
    await db.commit()
    return {"status": "ok"}


# Check updates — fetch repo metadata and compare

# APT arch: map uname -m → Debian binary arch
_APT_ARCH = {
    "x86_64": "amd64",
    "aarch64": "arm64",
    "armv7l": "armhf",
    "i686": "i386",
    "i386": "i386",
}

# Debian/Ubuntu version → codename (used to match repos by distribution)
_DEBIAN_CODENAMES = {
    "10": "buster",
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
}
_UBUNTU_CODENAMES = {
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "24.10": "oracular",
    "25.04": "plucky",
}


def _detect_os_family(os_name: str) -> str | None:
    """Map node OS name to package_repositories os_family."""
    os_lower = os_name.lower()
    if "debian" in os_lower:
        return "debian"
    if "ubuntu" in os_lower:
        return "ubuntu"
    if "arch" in os_lower or "manjaro" in os_lower:
        return "archlinux"
    if "rocky" in os_lower:
        return "rocky"
    if "centos" in os_lower:
        return "centos"
    if "fedora" in os_lower:
        return "fedora"
    return None


def _resolve_codename(os_family: str, os_version: str | None) -> str | None:
    """Map OS version to APT distribution codename."""
    if not os_version:
        return None
    if os_family == "debian":
        major = os_version.split(".")[0]
        return _DEBIAN_CODENAMES.get(major)
    if os_family == "ubuntu":
        return _UBUNTU_CODENAMES.get(os_version)
    return None


async def _fetch_apt_packages(
    url: str, dist: str, components: str, arch: str = "amd64"
) -> dict:
    """Download Packages.gz from APT repo for given arch, return {name: version}."""
    pkgs = {}
    comps = (components or "main").split()
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        for comp in comps:
            pkg_url = f"{url}/dists/{dist}/{comp}/binary-{arch}/Packages.gz"
            try:
                r = await client.get(pkg_url)
                if r.status_code != 200:
                    continue
                text_data = _safe_gunzip(r.content)
                name = None
                for line in text_data.splitlines():
                    if line.startswith("Package: "):
                        name = line[9:].strip()
                    elif line.startswith("Version: ") and name:
                        ver = line[9:].strip()
                        # Pick the highest version with dpkg semantics, not a
                        # lexical compare (lexically '1.10' < '1.9', which would
                        # advertise an older version as the available one).
                        if name not in pkgs or _ver_gt(ver, pkgs[name]):
                            pkgs[name] = ver
                        name = None
            except Exception as e:
                logger.debug("APT fetch %s failed: %s", pkg_url, e)
    return pkgs


async def _fetch_pacman_db(url: str) -> dict:
    """Download single pacman .db from repo URL, return {name: version}.

    URL points to the repo directory (e.g. https://mirror/core/os/x86_64).
    The .db file name is derived from the path (core.db, extra.db, etc.).
    """
    pkgs = {}
    parts = url.rstrip("/").split("/")
    db_name = parts[-1]
    try:
        os_idx = parts.index("os")
        db_name = parts[os_idx - 1]
    except ValueError:
        pass

    db_url = f"{url.rstrip('/')}/{db_name}.db"
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get(db_url)
            if r.status_code != 200:
                logger.debug("Pacman DB %s → %d", db_url, r.status_code)
                return pkgs
            with tarfile.open(fileobj=io.BytesIO(r.content)) as tar:
                for member in tar.getmembers():
                    if member.name.endswith("/desc"):
                        # Bomb guard: skip a member whose declared size is
                        # absurd, and cap the actual read regardless.
                        if member.size > _MAX_TAR_MEMBER:
                            continue
                        f = tar.extractfile(member)
                        if not f:
                            continue
                        raw = f.read(_MAX_TAR_MEMBER + 1)
                        if len(raw) > _MAX_TAR_MEMBER:
                            continue
                        lines = raw.decode(errors="replace").splitlines()
                        name = ver = None
                        for i, line in enumerate(lines):
                            if line == "%NAME%":
                                name = lines[i + 1] if i + 1 < len(lines) else None
                            elif line == "%VERSION%":
                                ver = lines[i + 1] if i + 1 < len(lines) else None
                        if name and ver:
                            pkgs[name] = ver
    except Exception as e:
        logger.debug("Pacman fetch %s failed: %s", db_url, e)
    return pkgs


@router.post("/check-updates")
async def check_updates(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("repositories", "w")),
):
    """Refresh per-OS-profile available versions from configured repos.

    Two-phase, no long-lived transaction:
      1. Fetch repo metadata in memory (HTTP, no DB held).
      2. Per group (os_family, os_version, arch): single bulk UPSERT into
         `package_availability`, committed immediately to keep the tx short.

    Result: O(groups) write statements instead of the previous
    O(nodes × packages). Critically, we explicitly `commit()` after
    every read that precedes an HTTP fetch — SQLAlchemy async sessions
    keep an implicit tx open after the first execute, so without an
    early commit each `await _fetch_apt_packages(...)` would leave the
    connection in `idle in transaction` and trip both
    `idle_in_transaction_session_timeout` and the watchdog.
    """
    # 1. Group active nodes by (os, os_version, arch)
    node_groups = await db.execute(
        text("""
        SELECT n.os, n.os_version, n.arch,
               array_agg(n.id) AS node_ids,
               COUNT(*) AS node_count
        FROM nodes n
        WHERE n.is_active = true AND n.os IS NOT NULL
        GROUP BY n.os, n.os_version, n.arch
        """)
    )
    groups = [dict(r._mapping) for r in node_groups]
    # Release the read tx so the upcoming HTTP fetches don't pin
    # the connection as `idle in transaction`.
    await db.commit()

    total_updated = 0
    total_repos = 0
    details = []
    repo_cache: dict[str, dict] = {}

    for grp in groups:
        os_fam = _detect_os_family(grp["os"] or "")
        if not os_fam:
            continue

        codename = _resolve_codename(os_fam, grp["os_version"])
        node_arch = grp["arch"] or "x86_64"
        apt_arch = _APT_ARCH.get(node_arch, "amd64")

        # 2. Find matching repos for this profile
        repo_params: dict = {"os": os_fam}
        if codename:
            repo_sql = """
                SELECT * FROM package_repositories
                WHERE os_family = :os AND enabled = true
                  AND distribution LIKE :cn
                ORDER BY name
            """
            repo_params["cn"] = f"{codename}%"
        else:
            repo_sql = """
                SELECT * FROM package_repositories
                WHERE os_family = :os AND enabled = true
                ORDER BY name
            """

        repos = await db.execute(text(repo_sql), repo_params)
        repo_list = [dict(r._mapping) for r in repos]
        # Release tx before HTTP — see top-of-handler comment.
        await db.commit()
        if not repo_list:
            continue

        # 3. Phase 1 — fetch repo metadata over HTTP (no tx implications)
        repo_pkgs: dict[str, str] = {}
        for repo in repo_list:
            # Key the cache by (repo, arch): APT serves arch-specific
            # binary-<arch>/Packages.gz, so reusing one arch's fetch for a
            # different-arch node group would advertise the wrong versions.
            rid = f"{repo['id']}:{apt_arch}"
            if rid in repo_cache:
                repo_pkgs.update(repo_cache[rid])
                continue
            try:
                if os_fam in ("debian", "ubuntu"):
                    pkgs = await _fetch_apt_packages(
                        repo["url"],
                        repo["distribution"] or "",
                        repo["components"] or "",
                        apt_arch,
                    )
                elif os_fam == "archlinux":
                    pkgs = await _fetch_pacman_db(repo["url"])
                else:
                    continue
                repo_cache[rid] = pkgs
                repo_pkgs.update(pkgs)
                total_repos += 1
                logger.info(
                    "[check-updates] %s: %d packages from %s",
                    os_fam,
                    len(pkgs),
                    repo["name"],
                )
            except Exception as e:
                logger.warning("[check-updates] fetch failed %s: %s", repo["name"], e)

        if not repo_pkgs:
            continue

        # 4. Resolve catalog entries used on this profile's nodes.
        # One SELECT per group, not per node.
        catalog = await db.execute(
            text(
                "SELECT DISTINCT pc.id, pc.name, pc.version"
                " FROM packages p"
                " JOIN package_catalog pc ON pc.id = p.package_id"
                " WHERE p.node_id = ANY(:nids)"
            ),
            {"nids": grp["node_ids"]},
        )
        catalog_rows = [dict(r._mapping) for r in catalog]

        # 5. Compute upgrades in memory (no DB)
        upgrades: list[dict] = []
        for entry in catalog_rows:
            repo_ver = repo_pkgs.get(entry["name"])
            if (
                repo_ver
                and repo_ver != entry["version"]
                and _ver_gt(repo_ver, entry["version"])
            ):
                upgrades.append({"pid": str(entry["id"]), "ver": repo_ver})

        # 6. Phase 2 — single bulk UPSERT for this profile. SET LOCAL
        # the batch statement_timeout against the current tx (catalog
        # SELECT opened it), then always commit before the next group's
        # HTTP fetches so no transaction stays open across the network.
        grp_updated = 0
        if upgrades:
            await set_statement_timeout(db, "batch")
            grp_updated = await _upsert_availability(
                db,
                os_family=os_fam,
                os_version=grp["os_version"] or "",
                arch=node_arch,
                upgrades=upgrades,
            )
        await db.commit()

        total_updated += grp_updated
        details.append(
            {
                "os": os_fam,
                "codename": codename,
                "arch": node_arch,
                "nodes": grp["node_count"],
                "repos": len(repo_list),
                "updated": grp_updated,
            }
        )

    logger.info(
        "[check-updates] done — %d repos, %d packages updated",
        total_repos,
        total_updated,
    )
    return {
        "status": "ok",
        "repos_checked": total_repos,
        "packages_updated": total_updated,
        "groups": details,
    }


# Bulk insert chunk size — picked to keep each statement well under PG's
# bind-parameter limit (32k) while still doing meaningful batching.
_UPSERT_CHUNK = 1000


async def _upsert_availability(
    db: AsyncSession,
    os_family: str,
    os_version: str,
    arch: str,
    upgrades: list[dict],
) -> int:
    """Bulk UPSERT into package_availability for one OS profile.

    Splits large groups into chunks so a 50k-package profile doesn't blow
    past asyncpg's bind-parameter limit. Returns the number of rows sent
    (each chunk fires one INSERT, the ON CONFLICT path may DO UPDATE).
    """
    total = 0
    for start in range(0, len(upgrades), _UPSERT_CHUNK):
        chunk = upgrades[start : start + _UPSERT_CHUNK]
        placeholders: list[str] = []
        params: dict = {"os": os_family, "osv": os_version, "arch": arch}
        for i, u in enumerate(chunk):
            placeholders.append(
                f"(CAST(:pid{i} AS uuid), :os, :osv, :arch, :ver{i}, NOW())"
            )
            params[f"pid{i}"] = u["pid"]
            params[f"ver{i}"] = u["ver"]
        await db.execute(
            text(
                "INSERT INTO package_availability"
                " (package_id, os_family, os_version, arch, available_ver, checked_at)"
                f" VALUES {', '.join(placeholders)}"
                " ON CONFLICT (package_id, os_family, os_version, arch)"
                " DO UPDATE SET"
                "   available_ver = EXCLUDED.available_ver,"
                "   checked_at    = EXCLUDED.checked_at"
            ),
            params,
        )
        total += len(chunk)
    return total
