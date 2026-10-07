"""Integration tests for the vulnerable lab test application and the Typer CLI."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from webscan.cli.main import app
from webscan.lab.vulnerable_app import create_vulnerable_test_app
from webscan.models.report import ScanReport
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

runner = CliRunner()


def test_vulnerable_lab_routes() -> None:
    """Verify vulnerable lab application exhibits all intentional security weaknesses."""
    lab_app = create_vulnerable_test_app()
    client = TestClient(lab_app)

    # 1. Landing page banner and cookies
    r_index = client.get("/")
    assert r_index.status_code == 200
    assert "Server" in r_index.headers
    assert "Apache" in r_index.headers["Server"]
    assert "session_id" in r_index.headers.get("set-cookie", "")

    # 2. XSS reflection
    r_xss = client.get("/search?q=canary_probe")
    assert r_xss.status_code == 200
    assert "canary_probe" in r_xss.text

    # 3. SQL syntax error disclosure
    r_sqli_norm = client.get("/users?id=1")
    assert r_sqli_norm.status_code == 200
    r_sqli_err = client.get("/users?id=1'")
    assert r_sqli_err.status_code == 500
    assert "sqlite3.OperationalError" in r_sqli_err.text

    # 4. CORS reflection with credentials
    r_cors = client.get("/api/user", headers={"Origin": "https://attacker.local"})
    assert r_cors.status_code == 200
    assert r_cors.headers.get("access-control-allow-origin") == "https://attacker.local"
    assert r_cors.headers.get("access-control-allow-credentials") == "true"

    # 5. Open redirect
    r_redir = client.get("/login?next=https://evil.local", follow_redirects=False)
    assert r_redir.status_code == 302
    assert r_redir.headers.get("location") == "https://evil.local"

    # 6. Sensitive files
    r_env = client.get("/.env")
    assert r_env.status_code == 200
    assert "DB_PASSWORD" in r_env.text

    r_git = client.get("/.git/HEAD")
    assert r_git.status_code == 200
    assert "ref: refs/heads/" in r_git.text

    r_robots = client.get("/robots.txt")
    assert r_robots.status_code == 200
    assert "Disallow:" in r_robots.text

    r_sec = client.get("/.well-known/security.txt")
    assert r_sec.status_code == 200
    assert "Contact:" in r_sec.text

    r_sql = client.get("/backup.sql")
    assert r_sql.status_code == 200
    assert "CREATE TABLE" in r_sql.text

    # 7. Methods probe
    r_trace = client.request("TRACE", "/api/methods")
    assert r_trace.status_code == 200
    assert "TRACE /api/methods" in r_trace.text

    r_put = client.put("/api/methods")
    assert r_put.status_code == 201


def test_cli_version() -> None:
    """Test CLI version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "web-security-scanner" in result.output
    assert "Active modules:" in result.output


def test_cli_invalid_url() -> None:
    """Test CLI handles invalid URLs gracefully with non-zero exit."""
    result = runner.invoke(app, ["scan", "ftp://unsupported-scheme.com"])
    assert result.exit_code == 2
    assert "Target URL Error" in result.output

    result_probe = runner.invoke(app, ["probe", "ftp://unsupported-scheme.com"])
    assert result_probe.exit_code == 2
    assert "URL Error" in result_probe.output


def test_cli_probe_success() -> None:
    """Test CLI probe command executes and outputs findings table."""
    mock_resp = httpx.Response(200, headers={"Server": "Apache/2.4"})
    with (
        patch(
            "webscan.core.requester.AsyncRequester.get",
            new_callable=AsyncMock,
            return_value=mock_resp,
        ),
        patch(
            "webscan.scanners.methods_scanner.MethodsScanner.scan_methods",
            new_callable=AsyncMock,
            return_value=[],
        ),
    ):
        result = runner.invoke(app, ["probe", "http://localhost:8000/"])
        assert result.exit_code == 0
        assert "Security Probe:" in result.output


def test_cli_scan_mocked_execution(tmp_path: Path) -> None:
    """Test CLI scan command running orchestrator with output formatting."""
    mock_findings = [
        VulnerabilityFinding(
            finding_id="FIND-SQLI-001",
            title="SQL Error Disclosure",
            category=VulnerabilityCategory.SQLI,
            severity=Severity.HIGH,
            cwe_id="CWE-89",
            cvss_score=8.5,
            target_url="http://localhost:8000/users?id=1",
            description="Database syntax error disclosure detected.",
            remediation="Use parameterized queries.",
        )
    ]
    mock_report = ScanReport(
        scan_id="test-cli-uuid",
        target=ScanTarget(url="http://localhost:8000/"),
        findings=mock_findings,
        overall_score=85,
        risk_rating="B",
        summary_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    )

    with patch(
        "webscan.engine.orchestrator.ScanOrchestrator.execute_scan",
        return_value=mock_report,
    ):
        out_file = tmp_path / "out_report.json"
        result = runner.invoke(
            app,
            [
                "scan",
                "http://localhost:8000/",
                "--format",
                "json",
                "--output",
                str(out_file),
                "--no-scope",
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        assert "Report saved to:" in result.output

        # Test fail-on-high gate
        fail_result = runner.invoke(
            app,
            [
                "scan",
                "http://localhost:8000/",
                "--fail-on-high",
                "--no-scope",
            ],
        )
        assert fail_result.exit_code == 1
        assert "Security Gate Failed" in fail_result.output
