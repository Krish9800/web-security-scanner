"""REST API routes for orchestrating scans and querying assessment reports."""

import logging

import httpx
from fastapi import APIRouter, HTTPException, status

from webscan.api.schemas import (
    HealthResponse,
    QuickProbeRequest,
    QuickProbeResponse,
    ScanReportResponse,
    ScanRequest,
)
from webscan.core.requester import AsyncRequester
from webscan.core.sanitizer import URLSanitizer
from webscan.core.scope import ScopeGuardian
from webscan.engine.orchestrator import ScanOrchestrator
from webscan.models.report import ScanReport
from webscan.models.scan import ScanOptions
from webscan.models.target import ScanTarget
from webscan.scanners.headers_scanner import HeadersScanner
from webscan.scanners.methods_scanner import MethodsScanner

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory report cache for scan session lookups
SCANS_DB: dict[str, ScanReport] = {}


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """Service liveness and readiness probe."""
    return HealthResponse()


@router.post(
    "/api/v1/scan",
    response_model=ScanReportResponse,
    status_code=status.HTTP_200_OK,
    tags=["Scanning"],
)
async def start_scan(request: ScanRequest) -> ScanReportResponse:
    """Trigger an automated security vulnerability assessment against an authorized target."""
    try:
        normalized_url = URLSanitizer.normalize_url(request.target_url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid target URL: {exc}",
        ) from exc

    hosts = list(request.allowed_hosts)
    try:
        domain = URLSanitizer.extract_domain(normalized_url)
        if domain not in hosts:
            hosts.append(domain)
    except ValueError:
        pass

    target = ScanTarget(
        url=normalized_url,
        scope_allowlist=hosts,
    )
    options = ScanOptions(
        profile=request.profile,
        concurrency=request.concurrency,
        rate_limit_rps=request.rate_limit_rps,
        crawl_depth=request.crawl_depth,
        enabled_modules=request.enabled_modules,
    )

    guardian = ScopeGuardian(allowlist=hosts, enforce_scope=True)
    requester = AsyncRequester(
        scope_guardian=guardian,
        concurrency=request.concurrency,
        rate_limit_rps=request.rate_limit_rps,
    )

    orchestrator = ScanOrchestrator(
        target=target,
        options=options,
        requester=requester,
    )

    report = await orchestrator.execute_scan()
    SCANS_DB[report.scan_id] = report

    return ScanReportResponse(
        scan_id=report.scan_id,
        target_url=report.target.url,
        status=report.status,
        overall_score=report.overall_score,
        risk_rating=report.risk_rating,
        findings_count=len(report.findings),
        summary_counts=report.summary_counts,
        report=report,
    )


@router.get(
    "/api/v1/scans/{scan_id}",
    response_model=ScanReportResponse,
    tags=["Scanning"],
)
async def get_scan_report(scan_id: str) -> ScanReportResponse:
    """Retrieve an assessment report by scan session identifier."""
    report = SCANS_DB.get(scan_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan report with ID '{scan_id}' not found.",
        )

    return ScanReportResponse(
        scan_id=report.scan_id,
        target_url=report.target.url,
        status=report.status,
        overall_score=report.overall_score,
        risk_rating=report.risk_rating,
        findings_count=len(report.findings),
        summary_counts=report.summary_counts,
        report=report,
    )


@router.post(
    "/api/v1/probe",
    response_model=QuickProbeResponse,
    status_code=status.HTTP_200_OK,
    tags=["Probing"],
)
async def quick_probe(request: QuickProbeRequest) -> QuickProbeResponse:
    """Perform immediate single-endpoint HTTP header and method audit."""
    try:
        normalized_url = URLSanitizer.normalize_url(request.target_url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid target URL: {exc}",
        ) from exc

    domain = URLSanitizer.extract_domain(normalized_url)
    guardian = ScopeGuardian(allowlist=[domain], enforce_scope=False)
    requester = AsyncRequester(scope_guardian=guardian)

    async with requester:
        try:
            resp = await requester.get(normalized_url, follow_redirects=True)
            hdr_findings = HeadersScanner.scan_headers(normalized_url, resp.headers)
            method_findings = await MethodsScanner.scan_methods(normalized_url, requester)
            findings = hdr_findings + method_findings
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            logger.debug("Quick probe error: %s", exc)
            findings = []

    return QuickProbeResponse(
        target_url=normalized_url,
        findings=findings,
    )
