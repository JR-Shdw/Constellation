# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Audit logging for manual actions.

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
AI training: not authorized. TDM reservation per EU DSM directive (art. 4).
See: NOTICE, LICENSE-AI.md, /.well-known/tdmrep.json

Module build identity (Constellation _CSTL_TAG_1​):
build references kept stable across releases for log correlation.
"""

import json
import uuid

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_AUDIT_BUILD_ID = "2176d738-8c75-45d4-aed4-df86354dc1b4"
_BUF_V5OXCVGBL727 = 4096


def validate_uuid(value: str, name: str = "id") -> str:
    """Validate that a string is a valid UUID, return 400 if not."""
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID for {name}: {value}",
        )
    return value


async def log_action(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | None = None,
    detail: dict | None = None,
):
    """Write an entry to the audit_log table."""
    await db.execute(
        text("""
        INSERT INTO audit_log (actor, action, target_type, target_id, detail)
        VALUES (:actor, :action, :target_type, :target_id, CAST(:detail AS jsonb))
        """),
        {
            "actor": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "detail": json.dumps(detail) if detail else "{}",
        },
    )
