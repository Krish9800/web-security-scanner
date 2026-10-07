"""Scan orchestrator coordinating scanner execution, URL discovery, and report generation."""

import asyncio
import logging
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urljoin

import httpx

from webscan.core.requester import AsyncRequester
from webscan.core.sanitizer import URLSanitizer
from webscan.core.scope import ScopeGuardian
from webscan.engine.scoring import SecurityScorer
from webscan.models.report import ScanReport
from webscan.models.scan import ScanOptions, ScanStatus
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import VulnerabilityFinding
from webscan.scanners.cookie_scanner import CookieScanner
from webscan.scanners.cors_scanner import CORSScanner
from webscan.scanners.headers_scanner import HeadersScanner
from webscan.scanners.methods_scanner import MethodsScanner
from webscan.scanners.redirect_scanner import OpenRedirectScanner
from webscan.scanners.sensitive_files import SensitiveFilesScanner
from webscan.scanners.sqli_scanner import SQLiScanner
from webscan.scanners.xss_scanner import XSSScanner

logger = logging.getLogger(__name__)

HREF_REGEX = re.compile(r'href=["\']([^"\'\s>]+)["\']', re.IGNORECASE)


class ScanOrchestrator:
    """Coordinates security scanning execution across modules, paths, and targets."""

    def __init__(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
        requester: AsyncRequester | None = None,
        progress_callback: Callable[[str, float], None] | None = None,
    ) -> None:
        self.target = target
        self.options = options or ScanOptions()
        self.progress_callback = progress_callback

        self.scope_guardian = ScopeGuardian(
            allowlist=self.target.scope_allowlist,
        )
        self.scope_guardian.add_allowed_target(self.target.url)

        self.requester = requester or AsyncRequester(
            scope_guardian=self.scope_guardian,
            rate_limit_rps=self.options.rate_limit_rps,
            concurrency=self.options.concurrency,
            timeout=self.target.timeout,
            custom_headers=self.target.custom_headers,
            cookies=self.target.cookies,
        )

    def _notify(self, stage: str, progress: float) -> None:
        """Invoke optional progress reporting callback."""
        if self.progress_callback:
            try:
                self.progress_callback(stage, progress)
            except Exception as exc:
                logger.debug("Progress callback error: %s", exc)

    async def execute_scan(self) -> ScanReport:
        """Run the configured scan workflow and produce a comprehensive ScanReport."""
        scan_id = str(uuid.uuid4())
        start_time = datetime.now(UTC)
        findings: list[VulnerabilityFinding] = []

        self._notify("Initiating scan session", 0.05)

        # Baseline probe
        try:
            base_resp = await self.requester.get(self.target.url, follow_redirects=True)
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            logger.error("Initial target probe failed for %s: %s", self.target.url, exc)
            return ScanReport(
                scan_id=scan_id,
                target=self.target,
                start_time=start_time,
                end_time=datetime.now(UTC),
                status=ScanStatus.FAILED,
                findings=[],
                overall_score=0,
                risk_rating="F",
                summary_counts=SecurityScorer.calculate_summary_counts([]),
            )

        self._notify("Baseline response analyzed", 0.15)
        enabled = set(self.options.enabled_modules)

        # 1. Headers Scanner
        if "headers" in enabled:
            findings.extend(HeadersScanner.scan_headers(self.target.url, base_resp.headers))
        self._notify("Security headers analyzed", 0.25)

        # 2. Cookie Scanner
        if "cookies" in enabled:
            cookie_headers = base_resp.headers.get_list("set-cookie")
            findings.extend(CookieScanner.scan_cookies(self.target.url, cookie_headers))
        self._notify("Cookie attributes inspected", 0.35)

        # 3. HTTP Methods Scanner
        if "methods" in enabled:
            method_findings = await MethodsScanner.scan_methods(self.target.url, self.requester)
            findings.extend(method_findings)
        self._notify("HTTP methods audited", 0.45)

        # 4. Sensitive Files Discovery
        if "sensitive_files" in enabled:
            file_findings = await SensitiveFilesScanner.scan_sensitive_files(
                self.target.url, self.requester
            )
            findings.extend(file_findings)
        self._notify("Sensitive path discovery complete", 0.60)

        # Discover crawled paths within scope
        discovered_urls = self._discover_endpoints(self.target.url, base_resp.text)

        # 5. Application Scanners across discovered targets
        app_tasks = []
        for url in discovered_urls:
            if "xss" in enabled:
                app_tasks.append(XSSScanner.scan_url(url, self.requester))
            if "sqli" in enabled:
                app_tasks.append(SQLiScanner.scan_url(url, self.requester))
            if "cors" in enabled:
                app_tasks.append(CORSScanner.scan_cors(url, self.requester))
            if "redirect" in enabled:
                app_tasks.append(OpenRedirectScanner.scan_redirects(url, self.requester))

        if app_tasks:
            app_results = await asyncio.gather(*app_tasks, return_exceptions=True)
            for res in app_results:
                if isinstance(res, list):
                    findings.extend(res)
                elif isinstance(res, Exception):
                    logger.debug("Application scanner task error: %s", res)

        self._notify("Application vulnerability scanners completed", 0.90)

        # Deduplicate findings
        deduped_findings = self._deduplicate_findings(findings)

        # Compute scoring and final metrics
        overall_score = SecurityScorer.calculate_score(deduped_findings)
        risk_rating = str(SecurityScorer.calculate_grade(overall_score))
        summary_counts = SecurityScorer.calculate_summary_counts(deduped_findings)
        status = ScanStatus.COMPLETED

        self._notify("Assessment report finalized", 1.0)

        return ScanReport(
            scan_id=scan_id,
            target=self.target,
            start_time=start_time,
            end_time=datetime.now(UTC),
            status=status,
            findings=deduped_findings,
            overall_score=overall_score,
            risk_rating=risk_rating,
            summary_counts=summary_counts,
        )

    def _discover_endpoints(self, base_url: str, html_body: str) -> list[str]:
        """Extract and sanitize in-scope endpoints from response body."""
        endpoints = [base_url]
        if self.options.crawl_depth <= 0 or not html_body:
            return endpoints

        matches = HREF_REGEX.findall(html_body)
        seen: set[str] = {base_url}

        for match in matches:
            if match.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            try:
                full_url = urljoin(base_url, match)
                normalized = URLSanitizer.normalize_url(full_url)
                if self.scope_guardian.is_in_scope(normalized) and normalized not in seen:
                    seen.add(normalized)
                    endpoints.append(normalized)
                    if len(endpoints) >= 20:  # Bound discovered endpoints
                        break
            except ValueError:
                continue

        return endpoints

    @staticmethod
    def _deduplicate_findings(
        findings: list[VulnerabilityFinding],
    ) -> list[VulnerabilityFinding]:
        """Deduplicate findings based on ID, category, target URL, and parameter."""
        seen: set[tuple[str, str, str, str | None]] = set()
        deduped: list[VulnerabilityFinding] = []

        for f in findings:
            key = (f.finding_id, f.category.value, f.target_url, f.parameter)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped
