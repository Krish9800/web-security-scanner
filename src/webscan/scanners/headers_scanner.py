"""HTTP security headers and information disclosure scanner."""

import re
from collections.abc import Mapping

from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding


class HeadersScanner:
    """Evaluates HTTP response headers against OWASP security guidelines and CWE standards."""

    _VERSION_REGEX = re.compile(r"\b\d+\.\d+(\.\d+)?\b")

    @classmethod
    def scan_headers(
        cls,
        target_url: str,
        headers: Mapping[str, str],
    ) -> list[VulnerabilityFinding]:
        """Analyze HTTP headers and return list of discovered security weaknesses."""
        findings: list[VulnerabilityFinding] = []
        lower_headers = {k.lower(): v.strip() for k, v in headers.items()}
        is_https = target_url.lower().startswith("https://")

        # 1. HSTS (Strict-Transport-Security)
        hsts = lower_headers.get("strict-transport-security")
        if is_https and not hsts:
            findings.append(
                VulnerabilityFinding(
                    finding_id="FIND-HDR-001",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    category=VulnerabilityCategory.HEADERS,
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-693",
                    cvss_score=5.3,
                    target_url=target_url,
                    description="The web server does not enforce HTTPS via the HSTS header.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000'.",
                )
            )
        elif is_https and hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if max_age_match and int(max_age_match.group(1)) < 15552000:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-HDR-002",
                        title="Suboptimal HSTS Max-Age Duration",
                        category=VulnerabilityCategory.HEADERS,
                        severity=Severity.LOW,
                        cwe_id="CWE-693",
                        cvss_score=3.1,
                        target_url=target_url,
                        evidence=f"HSTS: {hsts}",
                        description="HSTS max-age is under 180 days (15552000 seconds).",
                        remediation="Increase max-age to at least 31536000 (1 year).",
                    )
                )

        # 2. Content-Security-Policy (CSP)
        csp = lower_headers.get("content-security-policy")
        if not csp:
            findings.append(
                VulnerabilityFinding(
                    finding_id="FIND-HDR-003",
                    title="Missing Content-Security-Policy (CSP) Header",
                    category=VulnerabilityCategory.HEADERS,
                    severity=Severity.HIGH,
                    cwe_id="CWE-693",
                    cvss_score=7.2,
                    target_url=target_url,
                    description="No Content-Security-Policy defined; increases XSS susceptibility.",
                    remediation="Implement strict CSP restricting external resource sources.",
                )
            )
        else:
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-HDR-004",
                        title="Insecure Directives in Content-Security-Policy",
                        category=VulnerabilityCategory.HEADERS,
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-693",
                        cvss_score=5.0,
                        target_url=target_url,
                        evidence=f"CSP: {csp}",
                        description="CSP contains 'unsafe-inline' or 'unsafe-eval' directives.",
                        remediation="Replace unsafe-inline/eval with nonces or hashes.",
                    )
                )

        # 3. X-Frame-Options (Clickjacking)
        xfo = lower_headers.get("x-frame-options")
        if not xfo or xfo.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(
                VulnerabilityFinding(
                    finding_id="FIND-HDR-005",
                    title="Missing or Ineffective X-Frame-Options Header",
                    category=VulnerabilityCategory.HEADERS,
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-693",
                    cvss_score=5.4,
                    target_url=target_url,
                    evidence=f"X-Frame-Options: {xfo or 'None'}",
                    description="Application vulnerable to Clickjacking UI redressing attacks.",
                    remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' on all HTML views.",
                )
            )

        # 4. X-Content-Type-Options (MIME Sniffing)
        xcto = lower_headers.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            findings.append(
                VulnerabilityFinding(
                    finding_id="FIND-HDR-006",
                    title="Missing X-Content-Type-Options: nosniff Header",
                    category=VulnerabilityCategory.HEADERS,
                    severity=Severity.LOW,
                    cwe_id="CWE-693",
                    cvss_score=3.7,
                    target_url=target_url,
                    evidence=f"X-Content-Type-Options: {xcto or 'None'}",
                    description="Browser may MIME-sniff response away from declared Content-Type.",
                    remediation="Send 'X-Content-Type-Options: nosniff' header on all responses.",
                )
            )

        # 5. Referrer-Policy
        ref_pol = lower_headers.get("referrer-policy")
        if not ref_pol or "unsafe-url" in ref_pol.lower():
            findings.append(
                VulnerabilityFinding(
                    finding_id="FIND-HDR-007",
                    title="Missing or Permissive Referrer-Policy",
                    category=VulnerabilityCategory.HEADERS,
                    severity=Severity.LOW,
                    cwe_id="CWE-200",
                    cvss_score=3.1,
                    target_url=target_url,
                    evidence=f"Referrer-Policy: {ref_pol or 'None'}",
                    description="Referrer header may leak sensitive URLs or query parameters.",
                    remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
                )
            )

        # 6. Information Disclosure: Server version banners
        server = lower_headers.get("server")
        if server and cls._VERSION_REGEX.search(server):
            findings.append(
                VulnerabilityFinding(
                    finding_id="FIND-HDR-008",
                    title="Detailed Server Banner Disclosure",
                    category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    severity=Severity.LOW,
                    cwe_id="CWE-200",
                    cvss_score=3.5,
                    target_url=target_url,
                    evidence=f"Server: {server}",
                    description="Web server reveals exact software version information.",
                    remediation="Disable detailed server banners (e.g. ServerTokens Prod).",
                )
            )

        # 7. Information Disclosure: Technology frameworks
        for tech_hdr in ("x-powered-by", "x-aspnet-version", "x-runtime"):
            if tech_hdr in lower_headers:
                val = lower_headers[tech_hdr]
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-HDR-009",
                        title=f"Technology Stack Disclosure ({tech_hdr})",
                        category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                        severity=Severity.LOW,
                        cwe_id="CWE-200",
                        cvss_score=3.5,
                        target_url=target_url,
                        evidence=f"{tech_hdr}: {val}",
                        description="Application framework header leaks technology fingerprint.",
                        remediation=f"Suppress or remove the '{tech_hdr}' header in configuration.",
                    )
                )

        return findings
