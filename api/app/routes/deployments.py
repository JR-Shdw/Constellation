# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Deployments — CRUD, preflight, approval workflow, execution."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, validate_uuid
from ..auth import require_permission
from ..config import settings as app_settings
from ..connectors import get_ci
from ..connectors.vault import VaultSealedError, require_vault_unsealed
from ..database import get_db
from ..models.schemas import DeploymentCreate, DeploymentPatch
from .automation import run_evaluation

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/deployments", tags=["deployments"])


# CRUD


@router.post("")
async def create_deployment(
    payload: DeploymentCreate,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("deployments", "w")),
):
    """Create a deployment in draft status."""
    row = await db.execute(
        text("""
        INSERT INTO deployments
            (title, deploy_type, worker_hostname, repo_name,
             branch, manager_id, config, status, created_by)
        VALUES
            (:title, :deploy_type, :worker_hostname, :repo_name,
             :branch, CAST(:manager_id AS uuid), CAST(:config AS jsonb),
             'draft', :actor)
        RETURNING id
        """),
        {
            "title": payload.title,
            "deploy_type": payload.deploy_type,
            "worker_hostname": payload.worker_hostname,
            "repo_name": payload.repo_name,
            "branch": payload.branch,
            "manager_id": payload.manager_id,
            "config": json.dumps(payload.config),
            "actor": actor,
        },
    )
    dep_id = row.scalar()
    await log_action(
        db,
        actor=actor,
        action="create",
        target_type="deployment",
        target_id=str(dep_id),
        detail={"title": payload.title},
    )
    await db.commit()
    return {"status": "ok", "id": str(dep_id)}


@router.get("")
async def list_deployments(
    status_filter: str | None = Query(None, alias="status"),
    deploy_type: str | None = Query(None),
    size: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("deployments", "r")),
):
    """List deployments with optional filters."""
    conditions = []
    params: dict = {"limit": size, "offset": offset}

    if status_filter:
        conditions.append("d.status = :status")
        params["status"] = status_filter
    if deploy_type:
        conditions.append("d.deploy_type = :dtype")
        params["dtype"] = deploy_type

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    count_row = await db.execute(
        text(f"SELECT COUNT(*) FROM deployments d {where}"),
        params,
    )
    total = count_row.scalar() or 0

    rows = await db.execute(
        text(f"""
        SELECT d.* FROM v_deployment_summary d
        {where}
        ORDER BY d.created_at DESC
        LIMIT :limit OFFSET :offset
        """),
        params,
    )
    return {
        "items": [dict(r._mapping) for r in rows],
        "total": total,
    }


@router.get("/stats")
async def deployment_stats(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("deployments", "r")),
):
    """Deployment summary stats."""
    row = await db.execute(
        text("""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (
                WHERE status IN ('draft','pending','approved')
            ) AS active,
            COUNT(*) FILTER (WHERE status = 'running')
                AS running,
            COUNT(*) FILTER (WHERE status = 'success')
                AS success,
            COUNT(*) FILTER (WHERE status = 'failure')
                AS failed,
            COUNT(*) FILTER (WHERE status = 'cancelled')
                AS cancelled
        FROM deployments
    """)
    )
    return dict(row.mappings().first() or {})


@router.get("/{dep_id}")
async def get_deployment(
    dep_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("deployments", "r")),
):
    """Single deployment detail."""
    validate_uuid(dep_id)
    row = await db.execute(
        text("""
        SELECT * FROM v_deployment_summary
        WHERE id = CAST(:did AS uuid)
        """),
        {"did": dep_id},
    )
    dep = row.mappings().first()
    if not dep:
        raise HTTPException(404, "Deployment not found")
    return dict(dep)


@router.put("/{dep_id}")
async def update_deployment(
    dep_id: str,
    payload: DeploymentPatch,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("deployments", "w")),
):
    """Update a deployment (draft/pending only)."""
    validate_uuid(dep_id)
    current = await db.execute(
        text("SELECT status FROM deployments WHERE id = CAST(:did AS uuid)"),
        {"did": dep_id},
    )
    row = current.mappings().first()
    if not row:
        raise HTTPException(404, "Deployment not found")
    if row["status"] not in ("draft", "pending"):
        raise HTTPException(409, f"Cannot edit deployment in {row['status']} status")

    updates = {}
    if payload.title is not None:
        updates["title"] = payload.title
    if payload.worker_hostname is not None:
        updates["worker_hostname"] = payload.worker_hostname
    if payload.repo_name is not None:
        updates["repo_name"] = payload.repo_name
    if payload.branch is not None:
        updates["branch"] = payload.branch
    if payload.manager_id is not None:
        updates["manager_id"] = payload.manager_id
    if payload.config is not None:
        updates["config"] = json.dumps(payload.config)

    if not updates:
        return {"status": "ok", "changed": False}

    set_clauses = []
    for k, v in updates.items():
        if k == "manager_id":
            set_clauses.append(f"{k} = CAST(:{k} AS uuid)")
        elif k == "config":
            set_clauses.append(f"{k} = CAST(:{k} AS jsonb)")
        else:
            set_clauses.append(f"{k} = :{k}")
    set_clauses.append("updated_at = NOW()")
    set_sql = ", ".join(set_clauses)

    updates["did"] = dep_id
    await db.execute(
        text(f"UPDATE deployments SET {set_sql} WHERE id = CAST(:did AS uuid)"),
        updates,
    )
    await log_action(
        db,
        actor=actor,
        action="update",
        target_type="deployment",
        target_id=dep_id,
    )
    await db.commit()
    return {"status": "ok", "changed": True}


# Preflight


@router.post("/{dep_id}/preflight")
async def preflight_check(
    dep_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_permission("deployments", "w")),
):
    """Run pre-flight checks before deployment."""
    validate_uuid(dep_id)
    row = await db.execute(
        text("SELECT * FROM deployments WHERE id = CAST(:did AS uuid)"),
        {"did": dep_id},
    )
    dep = row.mappings().first()
    if not dep:
        raise HTTPException(404, "Deployment not found")

    checks = []

    # 1. Worker check
    if dep["worker_hostname"]:
        w = await db.execute(
            text("SELECT status FROM cicd_workers WHERE hostname = :h"),
            {"h": dep["worker_hostname"]},
        )
        worker = w.mappings().first()
        if not worker:
            checks.append(
                {
                    "check": "worker_exists",
                    "ok": False,
                    "detail": "Worker not found",
                }
            )
        elif worker["status"] == "offline":
            checks.append(
                {
                    "check": "worker_online",
                    "ok": False,
                    "detail": "Worker is offline",
                }
            )
        else:
            checks.append(
                {
                    "check": "worker_online",
                    "ok": True,
                    "detail": "Worker available",
                }
            )

    # 2. Repo + CI/CD check
    if dep["repo_name"]:
        r = await db.execute(
            text("SELECT has_pipeline FROM cicd_repositories WHERE repo_name = :n"),
            {"n": dep["repo_name"]},
        )
        repo = r.mappings().first()
        if not repo:
            checks.append(
                {
                    "check": "repo_exists",
                    "ok": False,
                    "detail": "Repo not found in CMDB",
                }
            )
        elif not repo["has_pipeline"]:
            checks.append(
                {
                    "check": "repo_has_ci",
                    "ok": False,
                    "detail": "Repo has no CI/CD config",
                }
            )
        else:
            checks.append(
                {
                    "check": "repo_has_ci",
                    "ok": True,
                    "detail": "Repo has CI/CD",
                }
            )

    # 3. Manager check (for container deploys)
    if dep["manager_id"]:
        m = await db.execute(
            text("SELECT status FROM container_managers WHERE id = CAST(:mid AS uuid)"),
            {"mid": str(dep["manager_id"])},
        )
        mgr = m.mappings().first()
        if not mgr:
            checks.append(
                {
                    "check": "manager_exists",
                    "ok": False,
                    "detail": "Manager not found",
                }
            )
        elif mgr["status"] != "connected":
            checks.append(
                {
                    "check": "manager_connected",
                    "ok": False,
                    "detail": f"Manager status: {mgr['status']}",
                }
            )
        else:
            checks.append(
                {
                    "check": "manager_connected",
                    "ok": True,
                    "detail": "Manager connected",
                }
            )

    # 4. Woodpecker availability (for pipeline-based deploys)
    if dep["deploy_type"] in ("container_build", "ansible_playbook"):
        wp_available = bool(
            app_settings.woodpecker_url and app_settings.woodpecker_token
        )
        checks.append(
            {
                "check": "woodpecker_available",
                "ok": wp_available,
                "detail": (
                    "Woodpecker configured"
                    if wp_available
                    else "Woodpecker not configured"
                ),
            }
        )

    # 5. Vault unsealed (if configured)
    from ..connectors.vault import vault_configured, vault_is_unsealed

    if vault_configured():
        unsealed = await vault_is_unsealed()
        checks.append(
            {
                "check": "vault_unsealed",
                "ok": unsealed,
                "detail": (
                    "Vault unsealed" if unsealed else "Vault sealed — unlock required"
                ),
            }
        )

    all_ok = all(c["ok"] for c in checks) if checks else True

    await db.execute(
        text("""
        UPDATE deployments
        SET preflight_ok = :ok,
            preflight_result = CAST(:result AS jsonb),
            updated_at = NOW()
        WHERE id = CAST(:did AS uuid)
        """),
        {
            "ok": all_ok,
            "result": json.dumps(checks),
            "did": dep_id,
        },
    )
    await db.commit()
    return {"preflight_ok": all_ok, "checks": checks}


# State transitions


async def _transition(
    db: AsyncSession,
    dep_id: str,
    actor: str,
    from_states: tuple,
    to_state: str,
    extra_sql: str = "",
    extra_params: dict | None = None,
):
    """Generic state transition with validation."""
    validate_uuid(dep_id)
    row = await db.execute(
        text("SELECT status FROM deployments WHERE id = CAST(:did AS uuid)"),
        {"did": dep_id},
    )
    dep = row.mappings().first()
    if not dep:
        raise HTTPException(404, "Deployment not found")
    if dep["status"] not in from_states:
        raise HTTPException(
            409,
            f"Cannot transition from {dep['status']} to {to_state}",
        )

    params = {"did": dep_id, "status": to_state}
    if extra_params:
        params.update(extra_params)
    sql = (
        f"UPDATE deployments SET status = :status, "
        f"updated_at = NOW() {extra_sql} "
        f"WHERE id = CAST(:did AS uuid)"
    )
    await db.execute(text(sql), params)
    await log_action(
        db,
        actor=actor,
        action=to_state,
        target_type="deployment",
        target_id=dep_id,
    )
    await db.commit()
    return {"status": "ok", "new_status": to_state}


@router.post("/{dep_id}/submit")
async def submit_deployment(
    dep_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("deployments", "w")),
):
    """Draft -> pending."""
    result = await _transition(
        db,
        dep_id,
        actor,
        ("draft",),
        "pending",
    )

    # Fire automation event for deployment request
    row = await db.execute(
        text(
            "SELECT title, deploy_type, worker_hostname, repo_name"
            " FROM deployments WHERE id = CAST(:did AS uuid)"
        ),
        {"did": dep_id},
    )
    dep = row.mappings().first()
    if dep:
        try:
            await run_evaluation(
                {
                    "trigger_type": "deploy_requested",
                    "hostname": dep["worker_hostname"] or "",
                    "container": dep["repo_name"] or "",
                },
                db,
            )
            await db.commit()
        except Exception as e:
            logger.warning("[deployments] automation eval failed: %s", e)

    return result


@router.post("/{dep_id}/approve")
async def approve_deployment(
    dep_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("deployments", "w")),
):
    """Pending -> approved."""
    return await _transition(
        db,
        dep_id,
        actor,
        ("pending",),
        "approved",
        extra_sql=", approved_by = :approver, approved_at = NOW()",
        extra_params={"approver": actor},
    )


@router.post("/{dep_id}/reject")
async def reject_deployment(
    dep_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("deployments", "w")),
):
    """Pending -> cancelled."""
    return await _transition(
        db,
        dep_id,
        actor,
        ("pending",),
        "cancelled",
    )


@router.post("/{dep_id}/execute")
async def execute_deployment(
    dep_id: str,
    db: AsyncSession = Depends(get_db),
    actor: str = Depends(require_permission("deployments", "w")),
):
    """Approved -> running. Triggers Woodpecker pipeline if applicable."""
    try:
        await require_vault_unsealed()
    except VaultSealedError as e:
        raise HTTPException(503, str(e)) from e

    validate_uuid(dep_id)
    row = await db.execute(
        text("SELECT * FROM deployments WHERE id = CAST(:did AS uuid)"),
        {"did": dep_id},
    )
    dep = row.mappings().first()
    if not dep:
        raise HTTPException(404, "Deployment not found")
    if dep["status"] != "approved":
        raise HTTPException(
            409,
            f"Cannot execute deployment in {dep['status']} status",
        )

    pipeline_number = None
    pipeline_link = None

    # Trigger Woodpecker if deploy type uses pipelines
    wp_url = app_settings.woodpecker_url
    wp_token = app_settings.woodpecker_token
    # A pipeline-backed deploy type with a repo and a configured Woodpecker MUST
    # actually start a pipeline. If it doesn't, the deployment failed to launch
    # and must not masquerade as 'running' — nothing would ever report back, so
    # it would sit running forever.
    pipeline_expected = bool(
        dep["deploy_type"] in ("container_build", "ansible_playbook")
        and dep["repo_name"]
        and wp_url
        and wp_token
    )
    trigger_error = None
    if pipeline_expected:
        try:
            ci = get_ci("woodpecker", wp_url, wp_token)
            wp_repos = await ci.list_repos()
            wp_repo = next(
                (r for r in wp_repos if r.get("full_name") == dep["repo_name"]),
                None,
            )
            if not wp_repo:
                trigger_error = f"Repo '{dep['repo_name']}' not found in Woodpecker"
            else:
                config = dep["config"] if isinstance(dep["config"], dict) else {}
                result = await ci.trigger_pipeline(
                    wp_repo["id"],
                    dep["branch"] or "main",
                    config.get("variables", {}),
                )
                pipeline_number = result.get("number")
                pipeline_link = result.get("link", "")
        except Exception as e:
            trigger_error = f"Woodpecker trigger failed: {e}"
            logger.warning("Woodpecker trigger failed: %s", e)

    # Pipeline was required but never started → fail loudly rather than parking
    # the deployment in a perpetual 'running' state with no pipeline behind it.
    if pipeline_expected and pipeline_number is None:
        err = trigger_error or "Pipeline did not start"
        await db.execute(
            text("""
            UPDATE deployments SET
                status = 'failure',
                started_at = NOW(),
                finished_at = NOW(),
                result = CAST(:result AS jsonb),
                updated_at = NOW()
            WHERE id = CAST(:did AS uuid)
            """),
            {"did": dep_id, "result": json.dumps({"error": err})},
        )
        await log_action(
            db,
            actor=actor,
            action="execute",
            target_type="deployment",
            target_id=dep_id,
            detail={"error": err},
        )
        await db.commit()
        raise HTTPException(502, err)

    await db.execute(
        text("""
        UPDATE deployments SET
            status = 'running',
            started_at = NOW(),
            pipeline_number = :pnum,
            pipeline_link = :plink,
            updated_at = NOW()
        WHERE id = CAST(:did AS uuid)
        """),
        {
            "did": dep_id,
            "pnum": pipeline_number,
            "plink": pipeline_link,
        },
    )
    await log_action(
        db,
        actor=actor,
        action="execute",
        target_type="deployment",
        target_id=dep_id,
        detail={
            "pipeline_number": pipeline_number,
            "pipeline_link": pipeline_link,
        },
    )
    await db.commit()
    return {
        "status": "ok",
        "new_status": "running",
        "pipeline_number": pipeline_number,
        "pipeline_link": pipeline_link,
    }
