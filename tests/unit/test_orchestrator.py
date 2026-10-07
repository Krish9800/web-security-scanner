"""Unit tests for the SecurityScorer and ScanOrchestrator."""

import httpx
import pytest

from webscan.core.requester import AsyncRequester
from webscan.core.scope import ScopeGuardian
from webscan.engine.orchestrator import ScanOrchestrator
from webscan.engine.scoring import PostureGrade, SecurityScorer
from webscan.models.scan import ScanOptions, ScanStatus
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding


def test_security_scorer_metrics() -> None:
    """Test posture score deductions, boundary clamping, and grade thresholds."""
    # Empty findings -> perfect score 100, Grade A
    assert SecurityScorer.calculate_score([]) == 100
    assert SecurityScorer.calculate_grade(100) == PostureGrade.A
    assert SecurityScorer.calculate_grade(95) == PostureGrade.A
    assert SecurityScorer.calculate_grade(85) == PostureGrade.B
    assert SecurityScorer.calculate_grade(75) == PostureGrade.C
    assert SecurityScorer.calculate_grade(65) == PostureGrade.D
    assert SecurityScorer.calculate_grade(50) == PostureGrade.F

    # Deductions testing
    findings = [
        VulnerabilityFinding(
            finding_id="F-1",
            title="Critical SQLi",
            category=VulnerabilityCategory.SQLI,
            severity=Severity.CRITICAL,
            cwe_id="CWE-89",
            cvss_score=9.8,
            target_url="http://test.local",
            evidence="error",
            description="desc",
            remediation="fix",
        ),
        VulnerabilityFinding(
            finding_id="F-2",
            title="High XSS",
            category=VulnerabilityCategory.XSS,
            severity=Severity.HIGH,
            cwe_id="CWE-79",
            cvss_score=8.0,
            target_url="http://test.local",
            evidence="canary",
            description="desc",
            remediation="fix",
        ),
        VulnerabilityFinding(
            finding_id="F-3",
            title="Medium Header",
            category=VulnerabilityCategory.HEADERS,
            severity=Severity.MEDIUM,
            cwe_id="CWE-693",
            cvss_score=5.0,
            target_url="http://test.local",
            evidence="missing",
            description="desc",
            remediation="fix",
        ),
        VulnerabilityFinding(
            finding_id="F-4",
            title="Low Header",
            category=VulnerabilityCategory.HEADERS,
            severity=Severity.LOW,
            cwe_id="CWE-693",
            cvss_score=3.0,
            target_url="http://test.local",
            evidence="missing",
            description="desc",
            remediation="fix",
        ),
        VulnerabilityFinding(
            finding_id="F-5",
            title="Info Tech",
            category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
            severity=Severity.INFO,
            cwe_id="CWE-200",
            cvss_score=0.0,
            target_url="http://test.local",
            evidence="banner",
            description="desc",
            remediation="fix",
        ),
    ]

    # 100 - (25 + 15 + 7 + 2 + 0) = 51
    score = SecurityScorer.calculate_score(findings)
    assert score == 51
    assert SecurityScorer.calculate_grade(score) == PostureGrade.F

    summary = SecurityScorer.calculate_summary_counts(findings)
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 1
    assert summary["info"] == 1

    # Test clamping lower bound at 0
    severe_findings = findings * 5
    assert SecurityScorer.calculate_score(severe_findings) == 0


@pytest.mark.asyncio
async def test_scan_orchestrator_successful_execution() -> None:
    """Test full orchestrator execution across modules with mock transport."""
    progress_updates: list[tuple[str, float]] = []

    def progress_callback(stage: str, progress: float) -> None:
        progress_updates.append((stage, progress))

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        # Baseline HTML containing link to discover
        if request.method == "GET" and url_str == "http://localhost:8000/":
            return httpx.Response(
                200,
                headers={"Set-Cookie": "session=123"},
                text='<html><body><a href="/login?next=/dash">Login</a></body></html>',
            )
        if "login" in url_str:
            return httpx.Response(200, text="Login page")
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, POST, OPTIONS"})
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    guardian = ScopeGuardian(allowlist=["localhost"])
    requester = AsyncRequester(scope_guardian=guardian, rate_limit_rps=100.0)
    requester._client = httpx.AsyncClient(transport=transport)

    target = ScanTarget(url="http://localhost:8000/", scope_allowlist=["localhost"])
    options = ScanOptions(crawl_depth=1)
    orchestrator = ScanOrchestrator(
        target=target,
        options=options,
        requester=requester,
        progress_callback=progress_callback,
    )

    report = await orchestrator.execute_scan()

    assert report.status == ScanStatus.COMPLETED
    assert report.scan_id != ""
    assert report.end_time is not None
    assert report.start_time <= report.end_time
    assert len(report.findings) > 0  # Missing security headers, insecure cookie flags
    assert report.overall_score <= 100
    assert len(progress_updates) >= 5


@pytest.mark.asyncio
async def test_scan_orchestrator_initial_probe_failure() -> None:
    """Test orchestrator handles baseline probe failure gracefully."""

    def failure_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    transport = httpx.MockTransport(failure_handler)
    guardian = ScopeGuardian(allowlist=["localhost"])
    requester = AsyncRequester(scope_guardian=guardian, rate_limit_rps=100.0)
    requester._client = httpx.AsyncClient(transport=transport)

    target = ScanTarget(url="http://localhost:8000/")
    orchestrator = ScanOrchestrator(target=target, requester=requester)

    report = await orchestrator.execute_scan()
    assert report.status == ScanStatus.FAILED
    assert report.overall_score == 0
    assert report.risk_rating == "F"
    assert report.findings == []


@pytest.mark.asyncio
async def test_scan_orchestrator_selective_modules() -> None:
    """Test orchestrator only runs explicitly enabled modules."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"X-Frame-Options": "DENY"}, text="OK")

    transport = httpx.MockTransport(handler)
    guardian = ScopeGuardian(allowlist=["localhost"])
    requester = AsyncRequester(scope_guardian=guardian, rate_limit_rps=100.0)
    requester._client = httpx.AsyncClient(transport=transport)

    target = ScanTarget(url="http://localhost:8000/")
    # Only headers enabled
    options = ScanOptions(enabled_modules=["headers"], crawl_depth=0)
    orchestrator = ScanOrchestrator(target=target, options=options, requester=requester)

    report = await orchestrator.execute_scan()
    assert report.status == ScanStatus.COMPLETED
    # All findings must belong to security headers / info disclosure
    for finding in report.findings:
        assert finding.category in (
            VulnerabilityCategory.HEADERS,
            VulnerabilityCategory.INFORMATION_DISCLOSURE,
        )
