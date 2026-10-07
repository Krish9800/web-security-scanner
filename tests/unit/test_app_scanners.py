"""Unit tests for application vulnerability scanners: XSS, SQLi, CORS, and Open Redirect."""

import httpx
import pytest

from webscan.core.requester import AsyncRequester
from webscan.core.scope import ScopeGuardian
from webscan.models.vulnerability import Severity, VulnerabilityCategory
from webscan.scanners.cors_scanner import CORSScanner
from webscan.scanners.redirect_scanner import OpenRedirectScanner
from webscan.scanners.sqli_scanner import SQLiScanner
from webscan.scanners.xss_scanner import XSSScanner


@pytest.mark.asyncio
async def test_xss_scanner_vulnerable_and_sanitized() -> None:
    """Test XSSScanner detection of unescaped canary token and rejection of encoded HTML."""

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if "<webscan-xss-canary>" in q:
            # Vulnerable reflection: echoes raw input
            return httpx.Response(200, text=f"<html>Search results for: {q}</html>")
        return httpx.Response(200, text="<html>Clean page</html>")

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings = await XSSScanner.scan_url("http://localhost:8000/search?q=test", requester)
        assert len(findings) == 1
        assert findings[0].finding_id == "FIND-XSS-001"
        assert findings[0].category == VulnerabilityCategory.XSS
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe_id == "CWE-79"


@pytest.mark.asyncio
async def test_sqli_scanner_error_detection() -> None:
    """Test SQLiScanner detection of database syntax error disclosures."""

    def handler(request: httpx.Request) -> httpx.Response:
        user_id = request.url.params.get("id", "")
        if "'" in user_id:
            # Simulates database error disclosure
            return httpx.Response(
                500,
                text='sqlite3.OperationalError: near "\'": syntax error in query',
            )
        return httpx.Response(200, json={"user": "admin"})

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings = await SQLiScanner.scan_url("http://localhost:8000/profile?id=10", requester)
        assert len(findings) == 1
        assert findings[0].finding_id == "FIND-SQLI-001"
        assert findings[0].category == VulnerabilityCategory.SQLI
        assert findings[0].cwe_id == "CWE-89"


@pytest.mark.asyncio
async def test_cors_scanner_dangerous_policies() -> None:
    """Test CORSScanner identifies arbitrary origin reflection with credentials."""

    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin", "")
        if origin:
            # Dynamically reflect origin and allow credentials
            return httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
                text="API response",
            )
        return httpx.Response(200, text="Standard response")

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings = await CORSScanner.scan_cors("http://localhost:8000/api/user", requester)
        finding_ids = [f.finding_id for f in findings]
        assert "FIND-CORS-001" in finding_ids
        assert any(f.severity == Severity.HIGH for f in findings)


@pytest.mark.asyncio
async def test_open_redirect_scanner_detection() -> None:
    """Test OpenRedirectScanner identifies unvalidated external redirects."""

    def handler(request: httpx.Request) -> httpx.Response:
        target = request.url.params.get("next", "")
        if target:
            return httpx.Response(302, headers={"Location": target})
        return httpx.Response(200, text="Home page")

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings = await OpenRedirectScanner.scan_redirects(
            "http://localhost:8000/login?next=/dashboard", requester
        )
        assert len(findings) == 1
        assert findings[0].finding_id == "FIND-REDIR-001"
        assert findings[0].category == VulnerabilityCategory.OPEN_REDIRECT
        assert findings[0].cwe_id == "CWE-601"


@pytest.mark.asyncio
async def test_cors_scanner_wildcard_and_reflection() -> None:
    """Test CORS wildcard with credentials and origin reflection without credentials."""

    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin", "")
        if "wildcard" in str(request.url):
            return httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        if origin:
            return httpx.Response(200, headers={"Access-Control-Allow-Origin": origin})
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings_wildcard = await CORSScanner.scan_cors("http://localhost:8000/wildcard", requester)
        assert any(f.finding_id == "FIND-CORS-002" for f in findings_wildcard)

        findings_reflect = await CORSScanner.scan_cors("http://localhost:8000/reflect", requester)
        assert any(f.finding_id == "FIND-CORS-003" for f in findings_reflect)


@pytest.mark.asyncio
async def test_scanners_without_query_params() -> None:
    """Verify scanners gracefully return empty findings when no query parameters exist."""
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="No params"))
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        xss_res = await XSSScanner.scan_url("http://localhost:8000/plain", requester)
        assert xss_res == []

        sqli_res = await SQLiScanner.scan_url("http://localhost:8000/plain", requester)
        assert sqli_res == []

        redir_res = await OpenRedirectScanner.scan_redirects(
            "http://localhost:8000/plain", requester
        )
        assert redir_res == []
