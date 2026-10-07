"""Reflected Cross-Site Scripting (XSS) parameter canary scanner."""

import logging
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from webscan.core.requester import AsyncRequester
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

logger = logging.getLogger(__name__)


class XSSScanner:
    """Detects reflected XSS vulnerabilities using harmless non-destructive canary tokens."""

    CANARY_TAG = "<webscan-xss-canary>"
    DEFAULT_TEST_PARAMS = ("q", "search", "query", "id", "name", "redirect")

    @classmethod
    async def scan_url(
        cls,
        target_url: str,
        requester: AsyncRequester,
    ) -> list[VulnerabilityFinding]:
        """Inject non-destructive canary payloads into query parameters and check for reflection."""
        findings: list[VulnerabilityFinding] = []
        parts = urlsplit(target_url)
        params = parse_qs(parts.query, keep_blank_values=True)

        # If no query parameters, test standard common input parameters
        test_params = list(params.keys()) if params else list(cls.DEFAULT_TEST_PARAMS)

        for param_name in test_params:
            modified_params = dict(params)
            modified_params[param_name] = [cls.CANARY_TAG]
            new_query = urlencode(modified_params, doseq=True)
            probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))

            try:
                resp = await requester.get(probe_url, follow_redirects=False)
                if resp.status_code == 200 and cls.CANARY_TAG in resp.text:
                    findings.append(
                        VulnerabilityFinding(
                            finding_id="FIND-XSS-001",
                            title=f"Reflected Cross-Site Scripting in Parameter '{param_name}'",
                            category=VulnerabilityCategory.XSS,
                            severity=Severity.HIGH,
                            cwe_id="CWE-79",
                            cvss_score=7.5,
                            target_url=probe_url,
                            parameter=param_name,
                            evidence=(
                                f"Injected canary '{cls.CANARY_TAG}' reflected unescaped "
                                f"in response body."
                            ),
                            description=(
                                f"The application reflects parameter '{param_name}' verbatim "
                                "without adequate HTML entity encoding."
                            ),
                            remediation=(
                                f"Ensure user input for '{param_name}' is context-aware "
                                "HTML-encoded before rendering."
                            ),
                        )
                    )
            except (httpx.HTTPError, TimeoutError) as exc:
                logger.debug("XSS probe failed on %s: %s", probe_url, exc)

        return findings
