# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Full sync — repos + pipelines + workers from all configured servers."""

from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_permission
from ...config import settings as app_settings
from ...connectors import get_ci, get_forge
from ...crypto import decrypt_setting
from ...database import get_db
from ...utils.sql import set_statement_timeout
from . import logger, router
from .pipelines import pipelines_report
from .repos import repos_report
from .workers import workers_report


@router.post("/sync")
async def sync_all(
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("cicd", "w")),
):
    """Full sync: repos from forge(s), pipelines + workers from CI system(s)."""
    await set_statement_timeout(db, "batch")
    results = {"repos": 0, "pipelines": 0, "workers": 0, "errors": []}

    rows = await db.execute(
        text(
            "SELECT server_type, url, token FROM cicd_servers WHERE status != 'offline'"
        )
    )
    servers = [dict(r._mapping) for r in rows]

    for st in ("gitea", "forgejo", "woodpecker", "gitlab"):
        if not any(s["server_type"] == st for s in servers):
            url = getattr(app_settings, f"{st}_url", "")
            token = getattr(app_settings, f"{st}_token", "")
            if url and token:
                servers.append({"server_type": st, "url": url, "token": token})

    # Release the read tx before the forge/CI network fan-out below — the
    # initial SELECT would otherwise pin the connection as `idle in
    # transaction` across every list_repos/get_branches HTTP call. Each
    # *_report() helper manages its own short write tx + commit.
    await db.commit()

    for srv in servers:
        st = srv["server_type"]
        if st not in ("gitea", "forgejo", "gitlab"):
            continue
        try:
            forge = get_forge(st, srv["url"], decrypt_setting(srv["token"]))
            repos = await forge.list_repos()
            for repo in repos:
                owner = repo.get("owner", "")
                rname = repo.get("name", "")
                short = rname.split("/")[-1] if "/" in rname else rname
                try:
                    repo["branches"] = await forge.get_branches(owner, short)
                except Exception:
                    pass
                try:
                    repo["has_pipeline"] = await forge.has_ci_config(owner, short)
                except Exception:
                    pass

            payload = [
                {
                    "forge": st,
                    "repo_name": r["name"],
                    "owner": r.get("owner", ""),
                    "description": r.get("description", ""),
                    "default_branch": r.get("default_branch", "main"),
                    "url": r.get("url", ""),
                    "private": r.get("private", False),
                    "language": r.get("language", ""),
                    "topics": r.get("topics", []),
                    "stars": r.get("stars", 0),
                    "has_pipeline": r.get("has_pipeline", False),
                    "branches": r.get("branches", []),
                    "last_commit_at": r.get("last_commit_at"),
                }
                for r in repos
            ]
            res = await repos_report(payload, db, actor)
            results["repos"] += res.get("upserted", 0)
        except Exception as e:
            logger.warning("[cicd] sync forge %s failed: %s", st, e)
            results["errors"].append(f"forge:{st} — {e}")

    for srv in servers:
        st = srv["server_type"]
        if st not in ("woodpecker", "gitlab"):
            continue
        try:
            ci = get_ci(st, srv["url"], decrypt_setting(srv["token"]))

            ci_repos = await ci.list_repos()
            all_pipes: list[dict] = []
            for repo in ci_repos:
                repo_id = repo.get("id") or repo.get("full_name", "")
                repo_name = repo.get("full_name", "")
                try:
                    pipes = await ci.list_pipelines(repo_id, limit=20)
                    for p in pipes:
                        p["repo_name"] = repo_name
                        p["ci_system"] = st
                    all_pipes.extend(pipes)
                except Exception:
                    pass
            if all_pipes:
                res = await pipelines_report(all_pipes, db, actor)
                results["pipelines"] += res.get("upserted", 0)

            try:
                runners = await ci.list_runners()
                payload = [
                    {
                        "ci_system": st,
                        "external_id": str(r.get("external_id", "")),
                        "name": r.get("name", ""),
                        "hostname": (
                            r.get("labels", {}).get("host")
                            or r.get("hostname")
                            or r.get("name", "")
                        ),
                        "platform": r.get("platform", ""),
                        "labels": r.get("labels", {}),
                        "capacity": r.get("capacity", 1),
                        "last_contact": r.get("last_contact"),
                    }
                    for r in runners
                ]
                res = await workers_report(payload, db, actor)
                results["workers"] += res.get("upserted", 0)
            except Exception as e:
                logger.warning("[cicd] sync workers %s failed: %s", st, e)
        except Exception as e:
            logger.warning("[cicd] sync CI %s failed: %s", st, e)
            results["errors"].append(f"ci:{st} — {e}")

    return results
