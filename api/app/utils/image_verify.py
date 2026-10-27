# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Cosign-based image signature verification.

Phase 5 of rhorizon's supply-chain plan (consumer gate). Refuse to pull
images whose namespace is in TRUSTED_NAMESPACES unless their cosign
signature verifies against the matching pinned public key in `trust/`.

Trust roots:
- `trust/rhorizon-cosign.pub` covers `gitea.example.com/shdw/rhorizon-*`.

The `cosign` binary is shipped in the api Docker image (multi-stage
copy from gcr.io/projectsigstore/cosign at a pinned digest). When the
binary is missing for a trusted-namespace image, verification fails
CLOSED (the pull is refused) — a missing verifier must never silently
disable the gate. For dev / unit tests without cosign, set
`CMDB_ALLOW_UNVERIFIED_PULL=1` to skip with a warning instead.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger("cmdb.image_verify")

# Map: image-namespace prefix → public key path.
# Keep in sync with trust/README.md.
_TRUST_MAP = {
    "gitea.example.com/shdw/rhorizon-": "trust/rhorizon-cosign.pub",
}


class SignatureError(Exception):
    """Raised when a trusted-namespace image fails cosign verify."""


def _key_for(image: str) -> str | None:
    """Return the pinned public key path for image, or None if untrusted."""
    for prefix, key in _TRUST_MAP.items():
        if image.startswith(prefix):
            return key
    return None


def _resolve_key_path(rel: str) -> Path | None:
    """Locate the trust file relative to the project root or runtime dir."""
    candidates = [
        Path("/app") / rel,
        Path(__file__).resolve().parents[3] / rel,
        Path.cwd() / rel,
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


async def verify_image(image: str, tag: str = "latest") -> None:
    """Run `cosign verify` on the image.

    Raises SignatureError if the image is in a trusted namespace and
    verification fails. Returns silently for untrusted namespaces or
    when cosign isn't installed (with a warning so the operator notices).
    """
    key_rel = _key_for(image)
    if not key_rel:
        # Image isn't in a trusted namespace — no policy applies.
        return

    cosign = shutil.which("cosign")
    if not cosign:
        # The image IS in a trusted namespace (a signature policy applies) but we
        # have no verifier. Fail CLOSED — a missing cosign must not silently turn
        # the gate into a no-op (that's how a misconfigured deploy ships
        # unverified images). An explicit opt-in keeps dev/test, where cosign
        # isn't installed, working.
        if os.getenv("CMDB_ALLOW_UNVERIFIED_PULL", "").lower() in ("1", "true", "yes"):
            logger.warning(
                "cosign missing but CMDB_ALLOW_UNVERIFIED_PULL set — skipping "
                "verification for %s:%s (override — never set in production)",
                image,
                tag,
            )
            return
        raise SignatureError(
            f"cosign not available — cannot verify trusted-namespace image "
            f"{image}:{tag}; refusing to pull "
            f"(set CMDB_ALLOW_UNVERIFIED_PULL=1 to override in dev/test)"
        )

    key_path = _resolve_key_path(key_rel)
    if not key_path:
        raise SignatureError(
            f"trust file {key_rel!r} not found — refusing to pull {image}:{tag}"
        )

    ref = f"{image}:{tag}"
    proc = await asyncio.create_subprocess_exec(
        cosign,
        "verify",
        "--key",
        str(key_path),
        ref,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = stderr.decode("utf-8", errors="replace").strip() or "verify failed"
        logger.error(
            "cosign verify FAILED for %s — refusing to pull. cosign stderr: %s",
            ref,
            msg,
        )
        raise SignatureError(f"signature verification failed for {ref}: {msg}")

    logger.info("cosign verify OK for %s", ref)
