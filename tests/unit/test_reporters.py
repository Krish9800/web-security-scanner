"""Unit tests for multi-format report generators: JSON, Markdown, and SARIF v2.1.0."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from webscan.models.report import ScanReport
from webscan.models.scan import ScanStatus
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding
from webscan.reporters.factory import ReporterFactory
from webscan.reporters.json_reporter import JSONReporter
from webscan.reporters.markdown_reporter import MarkdownReporter
from webscan.reporters.sarif_reporter import SARIFReporter


@pytest.fixture
def sample_report() -> ScanReport:
    """Fixture providing a populated sample ScanReport for reporter testing."""
    target = ScanTarget(url="http://example.local:8080/app", scope_allowlist=["example.local"])
    findings = [
        VulnerabilityFinding(
            finding_id="FIND-SQLI-001",
            title="SQL Error Disclosure in Param 'id'",
            category=VulnerabilityCategory.SQLI,
            severity=Severity.HIGH,
            cwe_id="CWE-89",
            cvss_score=8.5,
            target_url="http://example.local:8080/app/users?id=1",
            parameter="id",
            evidence="syntax error in SQL query",
            description="Database syntax error disclosure detected upon probe injection.",
            remediation="Use parameterized queries and suppress raw error disclosures.",
        ),
        VulnerabilityFinding(
            finding_id="FIND-HDR-001",
            title="Missing Content-Security-Policy (CSP)",
            category=VulnerabilityCategory.HEADERS,
            severity=Severity.MEDIUM,
            cwe_id="CWE-693",
            cvss_score=5.0,
            target_url="http://example.local:8080/app",
            evidence="Header absent",
            description="Content-Security-Policy header is missing from HTTP response.",
            remediation="Configure a restrictive Content-Security-Policy header.",
        ),
        VulnerabilityFinding(
            finding_id="FIND-FILE-003",
            title="Robots Policy File Disclosed",
            category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
            severity=Severity.INFO,
            cwe_id="CWE-200",
            cvss_score=0.0,
            target_url="http://example.local:8080/robots.txt",
            evidence="Disallow: /admin",
            description="Robots.txt file found disclosing paths.",
            remediation="Review robots.txt to ensure sensitive routes are not disclosed.",
        ),
    ]

    return ScanReport(
        scan_id="test-scan-uuid-1234",
        target=target,
        start_time=datetime(2026, 10, 7, 10, 0, 0, tzinfo=UTC),
        end_time=datetime(2026, 10, 7, 10, 0, 5, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
        findings=findings,
        overall_score=80,
        risk_rating="B",
        summary_counts={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 1},
    )


def test_json_reporter_render_and_file(sample_report: ScanReport, tmp_path: Path) -> None:
    """Test JSONReporter renders valid schema and writes cleanly to disk."""
    json_text = JSONReporter.render(sample_report)
    parsed = json.loads(json_text)

    assert parsed["scan_id"] == "test-scan-uuid-1234"
    assert parsed["overall_score"] == 80
    assert parsed["risk_rating"] == "B"
    assert len(parsed["findings"]) == 3
    assert parsed["target"]["url"] == "http://example.local:8080/app"

    output_file = tmp_path / "report.json"
    written = JSONReporter.write_to_file(sample_report, output_file)
    assert written.exists()
    assert written.read_text(encoding="utf-8") == json_text


def test_markdown_reporter_render_and_file(sample_report: ScanReport, tmp_path: Path) -> None:
    """Test MarkdownReporter renders executive summary, tables, and remediations."""
    md_text = MarkdownReporter.render(sample_report)

    assert "# Web Security Assessment Report:" in md_text
    assert "## 1. Executive Summary" in md_text
    assert "**80 / 100**" in md_text
    assert "**Grade B**" in md_text
    assert "## 2. Findings Inventory" in md_text
    assert "| `FIND-SQLI-001` | `HIGH` |" in md_text
    assert "## 3. Detailed Vulnerability Analyses & Remediations" in md_text
    assert "Use parameterized queries" in md_text

    output_file = tmp_path / "report.md"
    written = MarkdownReporter.write_to_file(sample_report, output_file)
    assert written.exists()
    assert written.read_text(encoding="utf-8") == md_text


def test_markdown_reporter_empty_findings(tmp_path: Path) -> None:
    """Test MarkdownReporter handles report with zero findings gracefully."""
    empty_report = ScanReport(
        scan_id="empty-123",
        target=ScanTarget(url="http://secure.local"),
        findings=[],
        overall_score=100,
        risk_rating="A",
    )
    md_text = MarkdownReporter.render(empty_report)
    assert "No security vulnerabilities or weaknesses detected" in md_text


def test_sarif_reporter_render_and_file(sample_report: ScanReport, tmp_path: Path) -> None:
    """Test SARIFReporter produces valid SARIF v2.1.0 output matching schema specifications."""
    sarif_dict = SARIFReporter.to_sarif_dict(sample_report)

    assert sarif_dict["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif_dict["$schema"]
    runs = sarif_dict["runs"]
    assert len(runs) == 1
    tool_driver = runs[0]["tool"]["driver"]
    assert tool_driver["name"] == "web-security-scanner"
    assert len(tool_driver["rules"]) == 3

    results = runs[0]["results"]
    assert len(results) == 3

    # Check rule level mappings
    high_result = next(r for r in results if r["ruleId"] == "FIND-SQLI-001")
    assert high_result["level"] == "error"

    med_result = next(r for r in results if r["ruleId"] == "FIND-HDR-001")
    assert med_result["level"] == "warning"

    info_result = next(r for r in results if r["ruleId"] == "FIND-FILE-003")
    assert info_result["level"] == "note"

    # Test file output
    output_file = tmp_path / "report.sarif"
    written = SARIFReporter.write_to_file(sample_report, output_file)
    assert written.exists()
    parsed_disk = json.loads(written.read_text(encoding="utf-8"))
    assert parsed_disk["version"] == "2.1.0"


def test_reporter_factory_dispatch_and_errors(sample_report: ScanReport, tmp_path: Path) -> None:
    """Test ReporterFactory properly formats across types and raises on unknown types."""
    json_out = ReporterFactory.render(sample_report, "json")
    assert json.loads(json_out)["scan_id"] == "test-scan-uuid-1234"

    md_out = ReporterFactory.render(sample_report, "markdown")
    assert "Executive Summary" in md_out

    sarif_out = ReporterFactory.render(sample_report, "sarif")
    assert '"version": "2.1.0"' in sarif_out

    # File writing via factory
    f_json = ReporterFactory.write_to_file(sample_report, tmp_path / "f.json", "json")
    assert f_json.exists()
    f_md = ReporterFactory.write_to_file(sample_report, tmp_path / "f.md", "md")
    assert f_md.exists()
    f_sarif = ReporterFactory.write_to_file(sample_report, tmp_path / "f.sarif", "sarif")
    assert f_sarif.exists()

    with pytest.raises(ValueError, match="Unsupported report format"):
        ReporterFactory.render(sample_report, "pdf")

    with pytest.raises(ValueError, match="Unsupported report format"):
        ReporterFactory.write_to_file(sample_report, tmp_path / "f.pdf", "pdf")
