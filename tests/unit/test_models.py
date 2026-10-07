"""Unit tests for domain and vulnerability taxonomy models."""

from webscan.models.report import ScanReport
from webscan.models.scan import ScanOptions, ScanProfile, ScanStatus
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding


def test_severity_and_category_enums() -> None:
    """Test qualitative severity and vulnerability category enums."""
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.HIGH == "HIGH"
    assert Severity.INFO == "INFO"

    assert VulnerabilityCategory.HEADERS == "HEADERS"
    assert VulnerabilityCategory.XSS == "XSS"
    assert VulnerabilityCategory.SQLI == "SQLI"
    assert VulnerabilityCategory.CORS == "CORS"


def test_vulnerability_finding_instantiation() -> None:
    """Test VulnerabilityFinding attributes and serialization."""
    finding = VulnerabilityFinding(
        finding_id="FIND-XSS-001",
        title="Reflected XSS in Query Parameter",
        category=VulnerabilityCategory.XSS,
        severity=Severity.HIGH,
        cwe_id="CWE-79",
        cvss_score=7.5,
        target_url="http://localhost:8000/search",
        parameter="q",
        description="Search input reflects unencoded HTML script tags.",
        evidence="Reflected payload in response body: <script>...",
        remediation="Ensure all user input is HTML entity encoded before rendering.",
    )
    assert finding.finding_id == "FIND-XSS-001"
    assert finding.cvss_score == 7.5
    assert finding.parameter == "q"
    assert finding.timestamp is not None

    dumped = finding.model_dump()
    assert dumped["severity"] == "HIGH"
    assert dumped["cwe_id"] == "CWE-79"


def test_scan_target_and_options() -> None:
    """Test ScanTarget and ScanOptions default configurations."""
    target = ScanTarget(url="http://localhost:8080/app")
    assert target.url == "http://localhost:8080/app"
    assert target.timeout == 8.0
    assert "Authorized Security Auditor" in target.authorized_by

    options = ScanOptions(profile=ScanProfile.DEEP, concurrency=25)
    assert options.profile == ScanProfile.DEEP
    assert options.concurrency == 25
    assert "headers" in options.enabled_modules
    assert "xss" in options.enabled_modules


def test_scan_report_instantiation_and_serialization() -> None:
    """Test ScanReport structure, metrics, and JSON serialization."""
    target = ScanTarget(url="http://127.0.0.1:3000")
    report = ScanReport(
        scan_id="SCAN-TEST-001",
        target=target,
        status=ScanStatus.COMPLETED,
        overall_score=85,
        risk_rating="B",
        summary_counts={"HIGH": 1, "MEDIUM": 2},
    )
    assert report.scan_id == "SCAN-TEST-001"
    assert report.overall_score == 85
    assert report.risk_rating == "B"
    assert report.status == ScanStatus.COMPLETED

    json_str = report.model_dump_json()
    assert "SCAN-TEST-001" in json_str
    assert "http://127.0.0.1:3000" in json_str
