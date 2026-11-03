# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Ingestion endpoints (collect_token auth) — nodes, CVEs, secrets.

Author: shdw <contact@resurgamus.com>
Project: Constellation — open-source CAASM/CMDB platform.
License: Apache-2.0
See: NOTICE, LICENSE
"""

import logging

from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["collect"])

# WireGuard IP ranges
_WG_PREFIXES = ("10.0.0.", "10.0.1.")


def _chunks(lst, n):
    """Yield successive n-sized chunks from list."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


_EXPOSURE_RANK = {"none": 0, "localhost": 1, "vpn": 2, "internet": 3}


def _classify_exposure(port_bindings: list) -> str:
    """Classify container network exposure from port bindings.

    Returns the MOST-exposed binding across all ports, not the first match:
    a container with a port on 127.0.0.1 *and* one on 0.0.0.0 is internet-
    exposed, and the security score must reflect that regardless of binding
    order (returning on the first match silently under-reported it).
    """
    if not port_bindings:
        return "docker_internal"
    best = "none"
    for pb in port_bindings:
        host_ip = pb.get("host_ip", "")
        if host_ip in ("0.0.0.0", "::") or host_ip == "":
            cur = "internet"
        elif any(host_ip.startswith(p) for p in _WG_PREFIXES):
            cur = "vpn"
        elif host_ip in ("127.0.0.1", "::1"):
            cur = "localhost"
        else:
            cur = "none"
        if _EXPOSURE_RANK[cur] > _EXPOSURE_RANK[best]:
            best = cur
        if best == "internet":
            break  # nothing ranks higher
    return best


# Map the descriptive exposure vocabulary (incl. WG-specific 'vpn' and the
# catch-all 'none') to the DB-constrained `listen` vocabulary shared by scoring,
# repositories.listen, and automation match_exposure. Single source of truth so
# the automation event and the repos upsert can never drift apart.
_EXPOSURE_TO_LISTEN = {
    "internet": "internet",
    "vpn": "private_network",
    "localhost": "localhost",
}


def _exposure_to_listen(exposure: str) -> str:
    return _EXPOSURE_TO_LISTEN.get(exposure, "docker_internal")


def _has_traefik(labels: dict) -> bool:
    return str(labels.get("traefik.enable", "")).lower() == "true"


def _detect_middlewares(labels: dict) -> tuple[bool, bool]:
    """Detect authelia and geoip from traefik middleware labels."""
    authelia = False
    geoip = False
    for k, v in labels.items():
        val = str(v).lower()
        combined = k.lower() + "=" + val
        if "authelia" in combined:
            authelia = True
        if "geoip" in combined or "geo-block" in combined or "geoblock" in combined:
            geoip = True
    return authelia, geoip


from . import cves, nodes, secrets  # noqa: E402, F401
