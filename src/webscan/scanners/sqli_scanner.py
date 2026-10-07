"""Error-based SQL injection heuristic scanner."""

import logging
import re
from typing import ClassVar
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from webscan.core.requester import AsyncRequester
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

logger = logging.getLogger(__name__)


class SQLiScanner:
    """Detects database error disclosures and SQL injection anomalies via benign syntax probes."""

    SQL_ERROR_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
        re.compile(r"Warning:\s*mysql_", re.IGNORECASE),
        re.compile(r"syntax error at or near", re.IGNORECASE),
        re.compile(r"PG::SyntaxError", re.IGNORECASE),
        re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
        re.compile(r"near \".*\": syntax error", re.IGNORECASE),
        re.compile(r"ORA-01756|ORA-00933", re.IGNORECASE),
        re.compile(r"Unclosed quotation mark before the character string", re.IGNORECASE),
        re.compile(r"SQLSTATE\[\w+\]", re.IGNORECASE),
        re.compile(r"unterminated quoted string", re.IGNORECASE),
    ]

    DEFAULT_TEST_PARAMS = ("id", "user", "account", "item", "page", "category")
    PROBE_PAYLOADS = ("'", "''", "1' OR '1'='1", "1 AND 1=2")

    @classmethod
    async def scan_url(
        cls,
        target_url: str,
        requester: AsyncRequester,
    ) -> list[VulnerabilityFinding]:
        """Inject syntax probes and detect database error signatures in responses."""
        findings: list[VulnerabilityFinding] = []
        parts = urlsplit(target_url)
        params = parse_qs(parts.query, keep_blank_values=True)

        test_params = list(params.keys()) if params else list(cls.DEFAULT_TEST_PARAMS)

        for param_name in test_params:
            for probe in cls.PROBE_PAYLOADS:
                modified_params = dict(params)
                orig_val = modified_params.get(param_name, ["1"])[0]
                modified_params[param_name] = [f"{orig_val}{probe}"]
                new_query = urlencode(modified_params, doseq=True)
                probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))

                try:
                    resp = await requester.get(probe_url, follow_redirects=False)
                    for pattern in cls.SQL_ERROR_PATTERNS:
                        match = pattern.search(resp.text)
                        if match:
                            snippet = match.group(0)
                            findings.append(
                                VulnerabilityFinding(
                                    finding_id="FIND-SQLI-001",
                                    title=f"SQL Error Disclosure in Param '{param_name}'",
                                    category=VulnerabilityCategory.SQLI,
                                    severity=Severity.HIGH,
                                    cwe_id="CWE-89",
                                    cvss_score=8.5,
                                    target_url=probe_url,
                                    parameter=param_name,
                                    evidence=(
                                        f"Probe '{probe}' triggered database error: '{snippet}'"
                                    ),
                                    description=(
                                        f"Database error revealed when injecting syntax probe "
                                        f"into parameter '{param_name}'."
                                    ),
                                    remediation=(
                                        "Use parameterized prepared statements and suppress "
                                        "database error messages from client responses."
                                    ),
                                )
                            )
                            return findings  # Return once confirmed on this parameter
                except (httpx.HTTPError, TimeoutError) as exc:
                    logger.debug("SQLi probe failed on %s: %s", probe_url, exc)

        return findings
