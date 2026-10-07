"""Unit tests for MethodsScanner and SensitiveFilesScanner."""

import httpx
import pytest

from webscan.core.requester import AsyncRequester
from webscan.core.scope import ScopeGuardian
from webscan.models.vulnerability import Severity, VulnerabilityCategory
from webscan.scanners.methods_scanner import MethodsScanner
from webscan.scanners.sensitive_files import SensitiveFilesScanner


@pytest.mark.asyncio
async def test_methods_scanner_trace_and_put() -> None:
    """Test detection of TRACE and unrestricted PUT verbs."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, POST, OPTIONS, TRACE"})
        elif request.method == "TRACE":
            return httpx.Response(200, text=f"TRACE / HTTP/1.1\n{request.headers}")
        elif request.method == "PUT":
            return httpx.Response(201, json={"status": "uploaded"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings = await MethodsScanner.scan_methods("http://localhost:8000/", requester)
        finding_ids = [f.finding_id for f in findings]

        # Expect TRACE detection
        assert "FIND-METH-001" in finding_ids
        # Expect PUT detection
        assert "FIND-METH-002" in finding_ids
        assert any(f.severity == Severity.HIGH for f in findings)


@pytest.mark.asyncio
async def test_methods_scanner_hardened() -> None:
    """Test MethodsScanner against hardened server where TRACE/PUT are disallowed."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, POST"})
        elif request.method == "TRACE":
            return httpx.Response(405)
        elif request.method == "PUT":
            return httpx.Response(403)
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings = await MethodsScanner.scan_methods("http://localhost:8000/", requester)
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_sensitive_files_scanner_detection_and_soft_404() -> None:
    """Test detection of sensitive files and verification against soft-404 false positives."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = str(request.url.path)
        if path == "/.env":
            return httpx.Response(200, text="DATABASE_URL=postgres://user:secret@db/prod\n")
        elif path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        elif path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin/\n")
        elif path == "/backup.sql":
            return httpx.Response(200, text="CREATE TABLE users (id INT, password VARCHAR);\n")
        elif path == "/.well-known/security.txt":
            # Soft-404 simulation: server returns 200 OK with generic HTML page
            return httpx.Response(200, text="<html><body><h1>404 Custom Error</h1></body></html>")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    requester = AsyncRequester(
        scope_guardian=ScopeGuardian(allowlist=["localhost"]),
        rate_limit_rps=100.0,
    )
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        findings = await SensitiveFilesScanner.scan_sensitive_files(
            "http://localhost:8000/", requester
        )
        finding_ids = [f.finding_id for f in findings]

        assert "FIND-FILE-001" in finding_ids  # .env detected
        assert "FIND-FILE-002" in finding_ids  # .git/HEAD detected
        assert "FIND-FILE-003" in finding_ids  # robots.txt detected
        assert "FIND-FILE-005" in finding_ids  # backup.sql detected

        # Soft-404 on security.txt should NOT be flagged because signature did not match
        assert "FIND-FILE-004" not in finding_ids

        for f in findings:
            assert f.category == VulnerabilityCategory.INFORMATION_DISCLOSURE
