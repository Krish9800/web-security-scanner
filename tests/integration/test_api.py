"""Integration tests for web-security-scanner FastAPI microservice."""

from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from webscan.api.app import api_app
from webscan.models.report import ScanReport
from webscan.models.scan import ScanStatus
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

client = TestClient(api_app)


def test_api_health_check() -> None:
    """Test health check route returns healthy status and metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data


def test_api_start_scan_and_get_by_id() -> None:
    """Test initiating a scan and retrieving the generated report by ID."""
    mock_report = ScanReport(
        scan_id="scan-api-1234",
        target=ScanTarget(url="http://localhost:8000/"),
        status=ScanStatus.COMPLETED,
        findings=[
            VulnerabilityFinding(
                finding_id="FIND-HDR-001",
                title="Missing HSTS",
                category=VulnerabilityCategory.HEADERS,
                severity=Severity.MEDIUM,
                cwe_id="CWE-693",
                cvss_score=5.3,
                target_url="http://localhost:8000/",
                description="HSTS absent",
                remediation="Add header",
            )
        ],
        overall_score=93,
        risk_rating="A",
        summary_counts={"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
    )

    with patch(
        "webscan.engine.orchestrator.ScanOrchestrator.execute_scan",
        new_callable=AsyncMock,
        return_value=mock_report,
    ):
        payload = {
            "target_url": "http://localhost:8000/",
            "allowed_hosts": ["localhost"],
            "profile": "STANDARD",
            "concurrency": 5,
            "rate_limit_rps": 10.0,
            "crawl_depth": 0,
        }
        res = client.post("/api/v1/scan", json=payload)
        assert res.status_code == 200
        scan_data = res.json()
        assert scan_data["scan_id"] == "scan-api-1234"
        assert scan_data["overall_score"] == 93
        assert scan_data["risk_rating"] == "A"
        assert scan_data["findings_count"] == 1

        # Retrieve cached scan by ID
        get_res = client.get("/api/v1/scans/scan-api-1234")
        assert get_res.status_code == 200
        assert get_res.json()["scan_id"] == "scan-api-1234"

        # Not found lookup
        nf_res = client.get("/api/v1/scans/non-existent-scan-id")
        assert nf_res.status_code == 404


def test_api_invalid_url_validation() -> None:
    """Test validation rejection for invalid target URLs."""
    res = client.post("/api/v1/scan", json={"target_url": "ftp://unsupported.local"})
    assert res.status_code == 422
    assert "Invalid target URL" in res.json()["detail"]

    res_probe = client.post("/api/v1/probe", json={"target_url": "ftp://unsupported.local"})
    assert res_probe.status_code == 422
    assert "Invalid target URL" in res_probe.json()["detail"]


def test_api_quick_probe() -> None:
    """Test quick probe endpoint."""
    mock_resp = httpx.Response(200, headers={"Server": "Nginx/1.18"})
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
        res = client.post("/api/v1/probe", json={"target_url": "http://localhost:8000/"})
        assert res.status_code == 200
        probe_data = res.json()
        assert probe_data["target_url"] == "http://localhost:8000/"
        assert isinstance(probe_data["findings"], list)
