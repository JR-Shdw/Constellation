"""Collect coverage — full node report with containers, CVE report, secrets."""

import pytest

# _classify_exposure — most-exposed binding wins (not first match)


def test_classify_exposure_most_exposed_wins():
    from api.app.routes.collect import _classify_exposure

    # localhost binding listed BEFORE an internet one must still be internet.
    assert (
        _classify_exposure([{"host_ip": "127.0.0.1"}, {"host_ip": "0.0.0.0"}])
        == "internet"
    )
    # order-independent
    assert (
        _classify_exposure([{"host_ip": "0.0.0.0"}, {"host_ip": "127.0.0.1"}])
        == "internet"
    )


def test_classify_exposure_single_categories():
    from api.app.routes.collect import _classify_exposure

    assert _classify_exposure([]) == "docker_internal"
    assert _classify_exposure([{"host_ip": "0.0.0.0"}]) == "internet"
    assert _classify_exposure([{"host_ip": ""}]) == "internet"
    assert _classify_exposure([{"host_ip": "127.0.0.1"}]) == "localhost"
    assert _classify_exposure([{"host_ip": "10.0.0.3"}]) == "vpn"
    assert _classify_exposure([{"host_ip": "192.168.1.5"}]) == "none"


def test_classify_exposure_vpn_plus_localhost_is_vpn():
    from api.app.routes.collect import _classify_exposure

    assert (
        _classify_exposure([{"host_ip": "127.0.0.1"}, {"host_ip": "10.0.1.2"}])
        == "vpn"
    )


@pytest.mark.anyio
async def test_node_report_full_containers(client, collect_auth):
    """Node report with multiple containers, port bindings, labels."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "collect-full-node",
            "type": ["bare_metal", "container_host"],
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0-21",
            "ip_address": "192.0.2.99",
            "packages": [
                "nginx\t1.24.0\tamd64",
                "curl\t7.88.1\tamd64",
                "openssl\t3.0.11\tamd64",
            ],
            "containers": [
                {
                    "name": "traefik",
                    "image": "traefik:v3.0",
                    "status": "running",
                    "port_bindings": [
                        {"host_ip": "0.0.0.0", "host_port": "443"},
                        {"host_ip": "0.0.0.0", "host_port": "80"},
                    ],
                    "labels": {
                        "traefik.enable": "true",
                        "traefik.http.middlewares.auth.forwardauth.address": "http://authelia:9091",
                    },
                    "networks": ["proxy"],
                    "digest": "sha256:abc123",
                },
                {
                    "name": "postgres",
                    "image": "postgres:17-bookworm",
                    "status": "running",
                    "port_bindings": [],
                    "labels": {},
                    "networks": ["internal"],
                },
                {
                    "name": "wireguard-ui",
                    "image": "ngoduykhanh/wireguard-ui:latest",
                    "status": "running",
                    "port_bindings": [
                        {"host_ip": "192.0.2.1", "host_port": "5000"},
                    ],
                    "labels": {},
                    "networks": ["wg"],
                },
                {
                    "name": "local-svc",
                    "image": "myapp:dev",
                    "status": "running",
                    "port_bindings": [
                        {"host_ip": "127.0.0.1", "host_port": "8080"},
                    ],
                    "labels": {},
                    "networks": ["bridge"],
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["hostname"] == "collect-full-node"


@pytest.mark.anyio
async def test_node_report_arch_os_version(client, collect_auth):
    """Arch/Manjaro nodes use kernel as os_version."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "arch-node",
            "type": "bare_metal",
            "os": "archlinux",
            "os_version": "rolling",
            "arch": "x86_64",
            "kernel": "6.8.1-arch1-1",
            "packages": ["linux\t6.8.1.arch1-1"],
            "containers": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_node_report_json_container_strings(client, collect_auth):
    """Containers can be passed as JSON strings (Ansible raw output)."""
    import json

    container = json.dumps(
        {
            "name": "json-string-ctr",
            "image": "alpine:3.21",
            "status": "running",
            "port_bindings": [],
            "labels": {},
            "networks": [],
        }
    )
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "json-ctr-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [container],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_node_report_hw_info(client, collect_auth):
    """Node report with hw_info as dict."""
    r = await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "hw-info-node",
            "type": "bare_metal",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "hw_info": {"cpu": "Intel i7", "memory": "16GB"},
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_cve_report_packages(client, collect_auth):
    """CVE report for host packages with full Trivy format."""
    # Create node first
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "cve-pkg-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["curl\t7.88.1\tamd64"],
            "containers": [],
        },
        headers=collect_auth,
    )
    r = await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "cve-pkg-node",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-CC01",
                    "Severity": "CRITICAL",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "FixedVersion": "7.88.2",
                    "Description": "A critical vuln in curl",
                    "Status": "fixed",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                },
                {
                    "VulnerabilityID": "CVE-2099-CC02",
                    "Severity": "LOW",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "Status": "affected",
                    "CVSS": {"nvd": {"V3Score": 2.1}},
                },
                {
                    "VulnerabilityID": "CVE-2099-CC03",
                    "Severity": "MEDIUM",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "Status": "will_not_fix",
                    "CVSS": {},
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["cves_ingested"] == 3


@pytest.mark.anyio
async def test_cve_report_containers(client, collect_auth):
    """CVE report for container image scan."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "cve-ctr-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    r = await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "cve-ctr-node",
            "source": "trivy",
            "target_type": "container",
            "target_name": "nginx:1.25",
            "image": "nginx:1.25",
            "vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-CTR1",
                    "Severity": "HIGH",
                    "PkgName": "libssl3",
                    "PkgType": "debian",
                    "InstalledVersion": "3.0.11-1",
                    "FixedVersion": "3.0.13-1",
                    "Description": "OpenSSL vuln in container",
                    "Target": "nginx:1.25 (debian 12.4)",
                    "Layer": {"Digest": "sha256:abc"},
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["cves_ingested"] == 1


@pytest.mark.anyio
async def test_cve_report_unknown_host(client, collect_auth):
    """CVE report for nonexistent host returns error."""
    r = await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "nonexistent-cve-host",
            "source": "trivy",
            "target_type": "package",
            "vulnerabilities": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_cve_report_wazuh_source(client, collect_auth):
    """CVE report from Wazuh source updates last_wazuh_scan."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "wazuh-cve-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": ["openssl\t3.0.11\tamd64"],
            "containers": [],
        },
        headers=collect_auth,
    )
    r = await client.post(
        "/api/v1/cves/report",
        json={
            "hostname": "wazuh-cve-node",
            "source": "wazuh",
            "target_type": "package",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2099-WZ01",
                    "severity": "high",
                    "pkg_name": "openssl",
                    "installed_ver": "3.0.11",
                    "cvss_score": 7.5,
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["cves_ingested"] == 1


@pytest.mark.anyio
async def test_secrets_report(client, collect_auth):
    """Secrets report ingest with masking."""
    await client.post(
        "/api/v1/nodes/report",
        json={
            "hostname": "secrets-node",
            "type": "vm",
            "os": "debian",
            "os_version": "12",
            "arch": "x86_64",
            "kernel": "6.1.0",
            "packages": [],
            "containers": [],
        },
        headers=collect_auth,
    )
    r = await client.post(
        "/api/v1/secrets/report",
        json={
            "hostname": "secrets-node",
            "target_type": "host",
            "secrets": [
                {
                    "RuleID": "aws-access-key",
                    "Title": "AWS Access Key",
                    "Severity": "CRITICAL",
                    "Match": "AKIAIOSFODNN7EXAMPLE1234567890",
                    "Target": "/app/.env",
                    "Category": "aws",
                },
                {
                    "RuleID": "private-key",
                    "Title": "Private Key",
                    "Severity": "HIGH",
                    "Match": "-----BEGIN RSA PRIVATE KEY-----XXXX",
                    "Target": "/root/.ssh/id_rsa",
                },
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["secrets_ingested"] == 2


@pytest.mark.anyio
async def test_secrets_report_unknown_host(client, collect_auth):
    """Secrets report for unknown host returns error."""
    r = await client.post(
        "/api/v1/secrets/report",
        json={
            "hostname": "nonexistent-secrets-host",
            "target_type": "host",
            "secrets": [],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"
