# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import require_collect_token
from ...database import get_db
from ...utils.severity import normalize_severity
from ...utils.sql import set_statement_timeout
from . import logger, router


@router.post("/secrets/report")
async def secrets_report(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_collect_token),
):
    """Ingest secrets detected by Trivy (host rootfs + container images)."""
    await set_statement_timeout(db, "batch")
    hostname = payload.get("hostname", "")
    target_type = payload.get("target_type", "host")
    image = payload.get("image")
    secrets = payload.get("secrets", [])

    result = await db.execute(
        text("SELECT id FROM nodes WHERE hostname = :h LIMIT 1"),
        {"h": hostname},
    )
    row = result.scalar_one_or_none()
    if not row:
        return {"status": "error", "detail": f"Node {hostname} not found"}
    node_id = str(row)

    ingested = 0
    for s in secrets:
        rule_id = s.get("RuleID", s.get("rule_id", ""))
        title = s.get("Title", s.get("title", ""))
        severity = normalize_severity(
            s.get("Severity", s.get("severity")), allow_unknown=False, fallback="high"
        )
        # Mask the detected value before it ever hits the DB — a CMDB must not
        # store full credentials. The previous `len > 16` guard left short
        # secrets (passwords, short tokens) stored verbatim; tier the reveal so
        # short matches expose nothing.
        match = s.get("Match", s.get("match", ""))
        if match:
            if len(match) > 16:
                match = match[:8] + "****" + match[-4:]
            elif len(match) > 8:
                match = match[:4] + "****"
            else:
                match = "****"

        file_path = s.get("Target", s.get("file_path", ""))
        if not file_path:
            file_path = s.get("Category", rule_id or "unknown")

        secret_type = s.get("Category", s.get("secret_type", rule_id))

        await db.execute(
            text("""
            INSERT INTO secret_rules (secret_type, title, severity)
            VALUES (:stype, :title, :sev)
            ON CONFLICT (secret_type) DO UPDATE SET
                title    = COALESCE(EXCLUDED.title, secret_rules.title),
                severity = EXCLUDED.severity,
                last_updated = NOW()
            """),
            {
                "stype": secret_type,
                "title": title[:200] if title else None,
                "sev": severity,
            },
        )

        await db.execute(
            text("""
            INSERT INTO secrets_detected
                (node_id, file_path, secret_type,
                 image, match, target_type)
            VALUES
                (CAST(:nid AS uuid), :path, :stype,
                 :image, :match, :ttype)
            ON CONFLICT (node_id, file_path, secret_type,
                         COALESCE(image, ''))
            DO UPDATE SET
                match       = EXCLUDED.match,
                detected_at = NOW()
            """),
            {
                "nid": node_id,
                "path": file_path,
                "stype": secret_type,
                "image": image,
                "match": match[:200] if match else None,
                "ttype": target_type,
            },
        )
        ingested += 1

    await db.commit()
    logger.info(
        "[secrets] %s: %d secrets ingested (%s)",
        hostname,
        ingested,
        target_type,
    )
    return {"status": "ok", "node_id": node_id, "secrets_ingested": ingested}
