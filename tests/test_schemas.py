from api.app.models.schemas import BackupReport, CVEReport, NodeReport


def test_node_report_minimal():
    r = NodeReport(hostname="test-node")
    assert r.hostname == "test-node"
    assert r.type == "vm"
    assert r.packages == []
    assert r.containers == []


def test_node_report_full():
    r = NodeReport(
        hostname="srv-01",
        type="bare_metal",
        os="debian",
        os_version="12",
        arch="x86_64",
        kernel="6.1.0",
        packages=["nginx\t1.22\tamd64", "openssl\t3.0.9\tamd64"],
        containers=['{"name":"web","image":"nginx:latest","status":"Up 3 days"}'],
    )
    assert r.type == "bare_metal"
    assert len(r.packages) == 2


def test_backup_report_defaults():
    r = BackupReport(hostname="test")
    assert r.status == "unknown"
    assert r.source == "script"
    assert r.files_new == 0


def test_cve_report():
    r = CVEReport(
        hostname="test",
        source="trivy",
        target_type="container",
        target_name="nginx",
        image="nginx:1.25",
        vulnerabilities=[
            {
                "VulnerabilityID": "CVE-2024-1234",
                "Severity": "HIGH",
                "PkgName": "openssl",
                "InstalledVersion": "3.0.9",
                "FixedVersion": "3.0.10",
            }
        ],
    )
    assert len(r.vulnerabilities) == 1
    assert r.target_type == "container"
