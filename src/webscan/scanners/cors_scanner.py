"""Cross-Origin Resource Sharing (CORS) misconfiguration auditor."""

import logging

import httpx

from webscan.core.requester import AsyncRequester
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

logger = logging.getLogger(__name__)


class CORSScanner:
    """Audits CORS headers for overly permissive or dangerous origin reflection policies."""

    EVIL_ORIGIN = "https://attacker-origin.evil"

    @classmethod
    async def scan_cors(
        cls,
        target_url: str,
        requester: AsyncRequester,
    ) -> list[VulnerabilityFinding]:
        """Send custom Origin headers and analyze Access-Control policies."""
        findings: list[VulnerabilityFinding] = []

        test_origins = [
            (cls.EVIL_ORIGIN, "Arbitrary Origin Reflection"),
            ("null", "Null Origin Trust"),
        ]

        for test_origin, label in test_origins:
            try:
                resp = await requester.get(
                    target_url,
                    headers={"Origin": test_origin},
                    follow_redirects=False,
                )
                acao = resp.headers.get("access-control-allow-origin", "").strip()
                acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()

                if not acao:
                    continue

                # Case 1: Reflecting untrusted origin with Allow-Credentials: true
                if acao == test_origin and acac == "true":
                    findings.append(
                        VulnerabilityFinding(
                            finding_id="FIND-CORS-001",
                            title=f"Critical CORS Misconfiguration ({label} with Credentials)",
                            category=VulnerabilityCategory.CORS,
                            severity=Severity.HIGH,
                            cwe_id="CWE-942",
                            cvss_score=8.1,
                            target_url=target_url,
                            evidence=(
                                f"Origin: {test_origin} -> "
                                f"Access-Control-Allow-Origin: {acao}, "
                                f"Access-Control-Allow-Credentials: {acac}"
                            ),
                            description=(
                                f"The server echoes untrusted Origin '{test_origin}' and enables "
                                "credentials, allowing cross-origin authenticated data theft."
                            ),
                            remediation=(
                                "Enforce a strict whitelist of authorized origins and avoid "
                                "dynamically echoing untrusted Origin headers."
                            ),
                        )
                    )
                # Case 2: Wildcard origin with credentials
                elif acao == "*" and acac == "true":
                    findings.append(
                        VulnerabilityFinding(
                            finding_id="FIND-CORS-002",
                            title="Wildcard CORS Origin Combined with Credentials",
                            category=VulnerabilityCategory.CORS,
                            severity=Severity.HIGH,
                            cwe_id="CWE-942",
                            cvss_score=7.5,
                            target_url=target_url,
                            evidence=(
                                "Access-Control-Allow-Origin: * with "
                                "Access-Control-Allow-Credentials: true"
                            ),
                            description=(
                                "The server specifies wildcard '*' while attempting to allow "
                                "authenticated cross-origin requests."
                            ),
                            remediation=(
                                "Never combine wildcard '*' with Access-Control-Allow-Credentials."
                            ),
                        )
                    )
                # Case 3: Reflecting arbitrary origin without credentials
                elif acao == test_origin and test_origin != "null":
                    findings.append(
                        VulnerabilityFinding(
                            finding_id="FIND-CORS-003",
                            title=f"Overly Permissive CORS Policy ({label})",
                            category=VulnerabilityCategory.CORS,
                            severity=Severity.LOW,
                            cwe_id="CWE-942",
                            cvss_score=4.3,
                            target_url=target_url,
                            evidence=f"Origin: {test_origin} -> ACAO: {acao}",
                            description=(
                                f"Server reflected arbitrary origin '{test_origin}' without auth."
                            ),
                            remediation=(
                                "Validate Origin headers against a strict domain whitelist."
                            ),
                        )
                    )
            except (httpx.HTTPError, TimeoutError) as exc:
                logger.debug("CORS probe error on %s: %s", target_url, exc)

        return findings
