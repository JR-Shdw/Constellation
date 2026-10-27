# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Hostname resolution helpers — match collected names to nodes rows.

The CMDB receives reports from many sources (Ansible, restic-backup,
Wazuh, Trivy) and each one picks a slightly different name :
- `hostname -f`     → FQDN (e.g. `sirius.example.com`)
- `hostname -s`     → short  (e.g. `sirius`)
- `inventory_hostname` → whatever Ansible was given
- Wazuh agent name    → free-form, often short

The `nodes.hostname` column itself can hold either form depending on
when the node was first reported. This helper tries successively
match-exact, short, FQDN-prefix, and case-insensitive lookups so a
backup arriving as `sirius.example.com` still rattaches to a `nodes` row
keyed by `sirius`, and vice versa.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def resolve_node_id(db: AsyncSession, name: str) -> str | None:
    """Resolve a hostname (FQDN or short) to the matching `nodes.id`.

    Returns None when no match is found. Callers should treat that
    as orphan/unknown rather than 500'ing.
    """
    if not name:
        return None
    name = name.strip()

    # 1. Exact match — covers the nominal case where the report's
    #    hostname is exactly what's in nodes.hostname.
    r = await db.execute(
        text("SELECT id FROM nodes WHERE hostname = :h LIMIT 1"),
        {"h": name},
    )
    nid = r.scalar_one_or_none()
    if nid:
        return str(nid)

    # 2. FQDN incoming, nodes keyed on short — drop the domain.
    if "." in name:
        short = name.split(".", 1)[0]
        r = await db.execute(
            text("SELECT id FROM nodes WHERE hostname = :h LIMIT 1"),
            {"h": short},
        )
        nid = r.scalar_one_or_none()
        if nid:
            return str(nid)

    # 3. Short incoming, nodes keyed on FQDN — match `<short>.*`.
    if "." not in name:
        r = await db.execute(
            text("SELECT id FROM nodes WHERE hostname LIKE :h LIMIT 1"),
            {"h": f"{name}.%"},
        )
        nid = r.scalar_one_or_none()
        if nid:
            return str(nid)

    # 4. Case-insensitive last resort — handles `Aegis` vs `sirius`.
    short = name.split(".", 1)[0]
    r = await db.execute(
        text("SELECT id FROM nodes WHERE hostname ILIKE :h LIMIT 1"),
        {"h": short},
    )
    nid = r.scalar_one_or_none()
    return str(nid) if nid else None
