"""Sensitive files, exposed version control, and administrative endpoint discovery."""

import logging
import re
from typing import ClassVar

import httpx

from webscan.core.requester import AsyncRequester
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

logger = logging.getLogger(__name__)


class SensitiveFilesScanner:
    """Probes for exposed secrets, Git repositories, backup archives, and policy files."""

    SENSITIVE_TARGETS: ClassVar[list[dict[str, str | Severity | float]]] = [
        {
            "path": "/.env",
            "finding_id": "FIND-FILE-001",
            "title": "Exposed Environment Configuration File (.env)",
            "severity": Severity.CRITICAL,
            "cwe_id": "CWE-200",
            "cvss_score": 9.1,
            "signature": r"(?i)(DB_|DATABASE|API_KEY|SECRET|PASSWORD|APP_KEY)[A-Z0-9_]*\s*=",
        },
        {
            "path": "/.git/HEAD",
            "finding_id": "FIND-FILE-002",
            "title": "Exposed Git Repository Metadata (.git/HEAD)",
            "severity": Severity.HIGH,
            "cwe_id": "CWE-200",
            "cvss_score": 7.5,
            "signature": r"ref:\s*refs/heads/",
        },
        {
            "path": "/robots.txt",
            "finding_id": "FIND-FILE-003",
            "title": "Robots Policy File Disclosed (robots.txt)",
            "severity": Severity.INFO,
            "cwe_id": "CWE-200",
            "cvss_score": 0.0,
            "signature": r"(?i)(User-agent|Disallow|Allow):",
        },
        {
            "path": "/.well-known/security.txt",
            "finding_id": "FIND-FILE-004",
            "title": "Security Contact Policy Located (security.txt)",
            "severity": Severity.INFO,
            "cwe_id": "CWE-200",
            "cvss_score": 0.0,
            "signature": r"(?i)Contact:\s*(mailto:|https://)",
        },
        {
            "path": "/backup.sql",
            "finding_id": "FIND-FILE-005",
            "title": "Exposed Database Backup File (backup.sql)",
            "severity": Severity.HIGH,
            "cwe_id": "CWE-200",
            "cvss_score": 7.5,
            "signature": r"(?i)(INSERT INTO|CREATE TABLE|DROP TABLE)",
        },
    ]

    @classmethod
    async def scan_sensitive_files(
        cls,
        base_url: str,
        requester: AsyncRequester,
    ) -> list[VulnerabilityFinding]:
        """Probe for sensitive file exposures using content signature matching."""
        findings: list[VulnerabilityFinding] = []
        root_url = base_url.rstrip("/")

        for target in cls.SENSITIVE_TARGETS:
            path = str(target["path"])
            probe_url = f"{root_url}{path}"

            try:
                resp = await requester.get(probe_url, follow_redirects=False)
                # Ignore non-200 responses
                if resp.status_code != 200:
                    continue

                content = resp.text
                signature = str(target["signature"])

                # Verify signature match to avoid soft-404 false positives
                if re.search(signature, content):
                    preview = content[:120].replace("\n", " ").strip()
                    findings.append(
                        VulnerabilityFinding(
                            finding_id=str(target["finding_id"]),
                            title=str(target["title"]),
                            category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                            severity=target["severity"],  # type: ignore[arg-type]
                            cwe_id=str(target["cwe_id"]),
                            cvss_score=float(target["cvss_score"]),
                            target_url=probe_url,
                            evidence=f"HTTP 200 OK with matching signature. Preview: {preview}",
                            description=(
                                f"The sensitive file '{path}' was directly accessible over HTTP."
                            ),
                            remediation=(
                                f"Restrict access to '{path}' in web server configuration or "
                                "remove the file from web root."
                            ),
                        )
                    )
            except (httpx.HTTPError, TimeoutError) as exc:
                logger.debug("Failed probing sensitive file %s: %s", probe_url, exc)

        return findings
