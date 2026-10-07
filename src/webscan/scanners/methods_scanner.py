"""HTTP methods and dangerous verb scanner."""

import logging

import httpx

from webscan.core.requester import AsyncRequester
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

logger = logging.getLogger(__name__)


class MethodsScanner:
    """Probes web targets for dangerous or unnecessary HTTP methods."""

    @classmethod
    async def scan_methods(
        cls,
        target_url: str,
        requester: AsyncRequester,
    ) -> list[VulnerabilityFinding]:
        """Test OPTIONS, TRACE, and dangerous HTTP verbs."""
        findings: list[VulnerabilityFinding] = []

        # 1. Probe OPTIONS
        try:
            resp_options = await requester.request("OPTIONS", target_url, follow_redirects=False)
            allow_header = resp_options.headers.get("allow", "")
            if allow_header:
                allowed_verbs = {v.strip().upper() for v in allow_header.split(",")}
                if "TRACE" in allowed_verbs:
                    findings.append(
                        VulnerabilityFinding(
                            finding_id="FIND-METH-001",
                            title="HTTP TRACE Method Advertised in Allow Header",
                            category=VulnerabilityCategory.METHODS,
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-650",
                            cvss_score=5.3,
                            target_url=target_url,
                            evidence=f"Allow: {allow_header}",
                            description=(
                                "The server advertises support for HTTP TRACE, enabling "
                                "Cross-Site Tracing (XST) attacks."
                            ),
                            remediation="Disable HTTP TRACE/TRACK methods in server configuration.",
                        )
                    )
        except (httpx.HTTPError, TimeoutError) as exc:
            logger.debug("OPTIONS probe error on %s: %s", target_url, exc)

        # 2. Directly verify TRACE behavior
        try:
            resp_trace = await requester.request(
                "TRACE",
                target_url,
                headers={"X-Canary-Header": "WebScanTestToken"},
                follow_redirects=False,
            )
            if (
                resp_trace.status_code == 200
                and "WebScanTestToken" in resp_trace.text
                and not any(f.finding_id == "FIND-METH-001" for f in findings)
            ):
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-METH-001",
                        title="HTTP TRACE Method Enabled (Cross-Site Tracing)",
                        category=VulnerabilityCategory.METHODS,
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-650",
                        cvss_score=5.3,
                        target_url=target_url,
                        evidence="Reflected custom request header in TRACE response body",
                        description=(
                            "The server executed HTTP TRACE and echoed request headers back."
                        ),
                        remediation="Disable HTTP TRACE/TRACK methods in server configuration.",
                    )
                )
        except (httpx.HTTPError, TimeoutError) as exc:
            logger.debug("TRACE probe error on %s: %s", target_url, exc)

        # 3. Check for dangerous verbs (e.g. unauthenticated PUT)
        try:
            test_put_url = f"{target_url.rstrip('/')}/.webscan_probe_test"
            resp_put = await requester.request(
                "PUT",
                test_put_url,
                content=b"webscan_test",
                follow_redirects=False,
            )
            if resp_put.status_code in (200, 201, 204):
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-METH-002",
                        title="Unrestricted HTTP PUT Allowed",
                        category=VulnerabilityCategory.METHODS,
                        severity=Severity.HIGH,
                        cwe_id="CWE-650",
                        cvss_score=7.5,
                        target_url=test_put_url,
                        evidence=f"HTTP PUT returned status {resp_put.status_code}",
                        description="The server permitted an unauthenticated HTTP PUT request.",
                        remediation="Disable HTTP PUT or enforce strict authentication and ACLs.",
                    )
                )
        except (httpx.HTTPError, TimeoutError) as exc:
            logger.debug("PUT probe error on %s: %s", target_url, exc)

        return findings
