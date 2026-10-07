"""Open redirect and unvalidated URL parameter redirection scanner."""

import logging
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from webscan.core.requester import AsyncRequester
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

logger = logging.getLogger(__name__)


class OpenRedirectScanner:
    """Detects unvalidated redirects allowing attackers to steer users to phishing landing pages."""

    CANARY_DESTINATION = "https://evil-external-redirect.local/login"
    DEFAULT_REDIRECT_PARAMS = (
        "redirect",
        "url",
        "next",
        "return_to",
        "dest",
        "target",
        "r",
        "callback",
    )

    @classmethod
    async def scan_redirects(
        cls,
        target_url: str,
        requester: AsyncRequester,
    ) -> list[VulnerabilityFinding]:
        """Inject external destination into parameters and check for off-site 3xx Location."""
        findings: list[VulnerabilityFinding] = []
        parts = urlsplit(target_url)
        params = parse_qs(parts.query, keep_blank_values=True)

        test_params = list(params.keys()) if params else list(cls.DEFAULT_REDIRECT_PARAMS)

        for param_name in test_params:
            modified_params = dict(params)
            modified_params[param_name] = [cls.CANARY_DESTINATION]
            new_query = urlencode(modified_params, doseq=True)
            probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))

            try:
                # Do not follow redirects so we can inspect the raw Location header
                resp = await requester.get(probe_url, follow_redirects=False)
                if resp.is_redirect and "location" in resp.headers:
                    loc = resp.headers["location"].strip()
                    if "evil-external-redirect.local" in loc:
                        findings.append(
                            VulnerabilityFinding(
                                finding_id="FIND-REDIR-001",
                                title=f"Open Redirect Vulnerability in Parameter '{param_name}'",
                                category=VulnerabilityCategory.OPEN_REDIRECT,
                                severity=Severity.MEDIUM,
                                cwe_id="CWE-601",
                                cvss_score=6.1,
                                target_url=probe_url,
                                parameter=param_name,
                                evidence=f"Location: {loc} (HTTP Status {resp.status_code})",
                                description=(
                                    f"The application redirected user to arbitrary external URL "
                                    f"supplied in parameter '{param_name}'."
                                ),
                                remediation=(
                                    f"Validate '{param_name}' against an allowlist of relative "
                                    "paths or strictly authorized domains."
                                ),
                            )
                        )
            except (httpx.HTTPError, TimeoutError) as exc:
                logger.debug("Open redirect probe error on %s: %s", probe_url, exc)

        return findings
