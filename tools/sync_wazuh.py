#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Sync Wazuh → CMDB API.

Sources:
  - Vulnerabilities : OpenSearch index wazuh-states-vulnerabilities-*
  - SCA results     : Wazuh REST API /sca/{agent_id}/checks

Usage:
    sync_wazuh.py [--agent-id 001]

Environment:
    WAZUH_URL              Wazuh REST API (default: https://wazuh.example.com:55000)
    WAZUH_USER             Wazuh API user (default: wazuh-wui)
    WAZUH_PASSWORD         Wazuh API password
    OPENSEARCH_URL         OpenSearch URL (default: https://wazuh-indexer:9200)
    OPENSEARCH_USER        OpenSearch user (default: admin)
    OPENSEARCH_PASSWORD    OpenSearch password
    CMDB_API               CMDB URL (default: http://api:8000)
    CMDB_COLLECT_TOKEN     CMDB Bearer token
"""

import argparse
import os
import sys
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_URL = os.environ.get("WAZUH_URL", "https://wazuh.example.com:55000")
WAZUH_USER = os.environ.get("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD", "")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://wazuh-indexer:9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD", "")

CMDB_API = os.environ.get("CMDB_API", "http://api:8000")
CMDB_TOKEN = os.environ.get("CMDB_COLLECT_TOKEN", "")
# Ingestion CMDB peut etre longue sur un gros payload (centaines de CVEs).
# 300s aligne sur PG_STATEMENT_TIMEOUT_BATCH_MS cote API : si l'API est
# encore en train d'ecrire au-dela, c'est qu'il y a un probleme reel.
CMDB_INGEST_TIMEOUT = int(os.environ.get("CMDB_INGEST_TIMEOUT", "1200"))

VULN_INDEX_STATES = "wazuh-states-vulnerabilities-*"
VULN_INDEX_ALERTS = "wazuh-alerts-4.x-*"
SCA_PAGE_SIZE = 100


# Wazuh REST helpers

def get_wazuh_token() -> str:
    r = requests.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASSWORD),
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def get_agents(token: str, agent_id: str | None = None) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}"}
    if agent_id:
        r = requests.get(
            f"{WAZUH_URL}/agents",
            headers=headers,
            params={"agents_list": agent_id},
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()["data"].get("affected_items", [])

    agents, offset = [], 0
    while True:
        r = requests.get(
            f"{WAZUH_URL}/agents",
            headers=headers,
            params={"offset": offset, "limit": 500, "status": "active"},
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()["data"]
        items = data.get("affected_items", [])
        if not items:
            break
        agents.extend(items)
        offset += len(items)
        if offset >= data.get("total_affected_items", 0):
            break
    return agents


def get_sca_results(token: str, agent_id: str) -> list[dict]:
    """Fetch all SCA policy checks for an agent."""
    headers = {"Authorization": f"Bearer {token}"}

    # List available SCA policies for this agent
    r = requests.get(
        f"{WAZUH_URL}/sca/{agent_id}",
        headers=headers,
        verify=False,
        timeout=15,
    )
    if r.status_code == 404:
        return []
    r.raise_for_status()

    policies = r.json()["data"].get("affected_items", [])
    results = []

    for policy in policies:
        policy_id = policy.get("policy_id", "")
        policy_name = policy.get("name", policy_id)
        score = policy.get("score", 0)
        total_checks = policy.get("total_checks", 0)
        passed = policy.get("pass", 0)
        failed = policy.get("fail", 0)

        results.append({
            "policy_id": policy_id,
            "policy_name": policy_name,
            "score": score,
            "total_checks": total_checks,
            "passed": passed,
            "failed": failed,
            "end_scan": policy.get("end_scan"),
        })

    return results


# OpenSearch helpers

def _os_get(path: str, body: dict) -> dict:
    r = requests.get(
        f"{OPENSEARCH_URL}/{path}",
        auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        json=body,
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def _parse_fixed_version(condition: str) -> str | None:
    """Extract version from scanner condition like 'Package less than 2.44.2'."""
    if not condition:
        return None
    import re
    m = re.search(r"less than\s+(\S+)", condition, re.IGNORECASE)
    return m.group(1) if m else None


def _get_vulns_from_states(agent_name: str) -> list[dict]:
    """Query wazuh-states-vulnerabilities-* (Wazuh 4.8+)."""
    query = {
        "size": 1000,
        "_source": [
            "vulnerability.id", "vulnerability.severity",
            "vulnerability.score.base", "vulnerability.scanner.condition",
            "vulnerability.scanner.reference",
            "package.name", "package.version",
            "agent.name",
        ],
        "query": {"bool": {"must": [{"term": {"agent.name": agent_name}}]}},
    }
    try:
        resp = _os_get(f"{VULN_INDEX_STATES}/_search", query)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            return []
        raise

    vulns = []
    for hit in resp.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        vuln = src.get("vulnerability", {})
        pkg = src.get("package", {})
        cve_id = vuln.get("id", "")
        if not cve_id:
            continue
        vulns.append({
            "cve_id": cve_id,
            "severity": (vuln.get("severity") or "unknown").lower(),
            "cvss_score": vuln.get("score", {}).get("base"),
            "pkg_name": pkg.get("name", ""),
            "installed_ver": pkg.get("version", ""),
            "fixed_ver": _parse_fixed_version(
                vuln.get("scanner", {}).get("condition", "")
            ),
            "description": vuln.get("scanner", {}).get("reference", ""),
        })
    return vulns


def _get_vulns_from_alerts(agent_name: str) -> list[dict]:
    """Query wazuh-alerts-4.x-* (Wazuh < 4.8, vulnerability-detector rule group)."""
    query = {
        "size": 10000,
        "_source": [
            "data.vulnerability.cve", "data.vulnerability.severity",
            "data.vulnerability.score.base", "data.vulnerability.cvss.cvss3.base_score",
            "data.vulnerability.package.name", "data.vulnerability.package.version",
            "data.vulnerability.package.condition",
            "data.vulnerability.reference",
            "data.vulnerability.status",
            "agent.name",
        ],
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.name": agent_name}},
                    {"term": {"rule.groups": "vulnerability-detector"}},
                ],
            }
        },
    }
    try:
        resp = _os_get(f"{VULN_INDEX_ALERTS}/_search", query)
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            return []
        raise

    seen = {}
    for hit in resp.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        vuln = src.get("data", {}).get("vulnerability", {})
        pkg = vuln.get("package", {})

        cve_id = vuln.get("cve", "")
        if not cve_id:
            continue

        pkg_name = pkg.get("name", "")
        key = (cve_id, pkg_name)
        if key in seen:
            continue

        cvss = vuln.get("score", {}).get("base")
        if not cvss:
            cvss = vuln.get("cvss", {}).get("cvss3", {}).get("base_score")
        if cvss:
            try:
                cvss = float(cvss)
                if cvss < 0:
                    cvss = None
            except (ValueError, TypeError):
                cvss = None

        fixed_ver = _parse_fixed_version(pkg.get("condition", ""))

        _VALID_SEV = {"critical", "high", "medium", "low"}
        raw_sev = (vuln.get("severity") or "").strip().lower()
        severity = raw_sev if raw_sev in _VALID_SEV else "unknown"

        seen[key] = {
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": cvss,
            "pkg_name": pkg_name,
            "installed_ver": pkg.get("version", ""),
            "fixed_ver": fixed_ver,
            "description": vuln.get("reference", ""),
        }

    return list(seen.values())


def get_vulnerabilities_from_opensearch(agent_name: str) -> list[dict]:
    """
    Try stateful index first (Wazuh 4.8+), fall back to alerts index.
    """
    vulns = _get_vulns_from_states(agent_name)
    if vulns:
        return vulns
    return _get_vulns_from_alerts(agent_name)


# CMDB push helpers

def push_vulns_to_cmdb(hostname: str, vulns: list[dict]) -> int:
    payload = {
        "hostname": hostname,
        "source": "wazuh",
        "target_type": "package",
        "target_name": hostname,
        "vulnerabilities": vulns,
    }

    r = requests.post(
        f"{CMDB_API}/api/v1/cves/report",
        headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
        json=payload,
        timeout=CMDB_INGEST_TIMEOUT,
    )
    if r.status_code == 200:
        return r.json().get("cves_ingested", len(vulns))

    print(
        f"  CMDB CVE error for {hostname}: {r.status_code} {r.text}",
        file=sys.stderr,
    )
    return 0


def push_sca_to_cmdb(hostname: str, sca: list[dict]) -> bool:
    """Push SCA results to CMDB (endpoint /api/v1/sca/report)."""
    if not sca:
        return True

    payload = {"hostname": hostname, "source": "wazuh", "policies": sca}

    r = requests.post(
        f"{CMDB_API}/api/v1/sca/report",
        headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
        json=payload,
        timeout=CMDB_INGEST_TIMEOUT,
    )
    if r.status_code == 200:
        return True

    # 404 means endpoint not yet deployed — log a warning, don't fail
    if r.status_code == 404:
        print(
            "  SCA endpoint not found (deploy api/routes/sca.py first)",
            file=sys.stderr,
        )
        return False

    print(
        f"  CMDB SCA error for {hostname}: {r.status_code} {r.text}",
        file=sys.stderr,
    )
    return False


# Main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Wazuh vulns + SCA → CMDB")
    parser.add_argument("--agent-id", help="Sync a single agent by ID")
    parser.add_argument(
        "--skip-sca",
        action="store_true",
        help="Skip SCA collection",
    )
    parser.add_argument(
        "--skip-vulns",
        action="store_true",
        help="Skip vulnerability collection",
    )
    args = parser.parse_args()

    missing = []
    if not WAZUH_PASSWORD:
        missing.append("WAZUH_PASSWORD")
    if not OPENSEARCH_PASSWORD:
        missing.append("OPENSEARCH_PASSWORD")
    if not CMDB_TOKEN:
        missing.append("CMDB_COLLECT_TOKEN")
    if missing:
        print(f"Missing env vars: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    print(f"[{datetime.now().isoformat()}] Wazuh → CMDB sync")
    print(f"  OpenSearch : {OPENSEARCH_URL}")
    print(f"  Wazuh API  : {WAZUH_URL}")

    # Authenticate against Wazuh REST
    try:
        wazuh_token = get_wazuh_token()
    except Exception as e:
        print(f"Auth failed: {e}", file=sys.stderr)
        sys.exit(1)

    agents = get_agents(wazuh_token, args.agent_id)
    print(f"  {len(agents)} agent(s)")

    total_cves = 0
    total_sca_policies = 0

    for agent in agents:
        aid = agent.get("id", "")
        name = agent.get("name", aid)

        if aid == "000":
            continue  # skip manager node

        # Vulnerabilities (OpenSearch)
        if not args.skip_vulns:
            vulns = get_vulnerabilities_from_opensearch(name)
            count = push_vulns_to_cmdb(name, vulns)
            total_cves += count
            if vulns:
                print(f"  {name}: {count}/{len(vulns)} CVEs pushed")
            else:
                print(f"  {name}: 0 vulns (scan tracked)")

        # SCA (Wazuh REST API)
        if not args.skip_sca:
            sca = get_sca_results(wazuh_token, aid)
            if sca:
                ok = push_sca_to_cmdb(name, sca)
                policies_pushed = len(sca) if ok else 0
                total_sca_policies += policies_pushed
                scores = ", ".join(
                    f"{p['policy_name']}: {p['score']}%" for p in sca
                )
                print(f"  {name}: SCA [{scores}]")
            else:
                print(f"  {name}: no SCA policies")

    print(
        f"Done. CVEs: {total_cves} | SCA policies: {total_sca_policies}"
    )
