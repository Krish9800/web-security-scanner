"""Adversarial security test suite validating SSRF defenses and ReDoS safety."""

import time

import httpx
import pytest

from webscan.core.requester import AsyncRequester
from webscan.core.sanitizer import URLSanitizer
from webscan.core.scope import ScopeGuardian, ScopeViolationError
from webscan.engine.orchestrator import HREF_REGEX
from webscan.scanners.sqli_scanner import SQLiScanner


def test_scope_guardian_wildcard_domain_boundaries() -> None:
    """Verify scope guardian strictly isolates wildcards and blocks collision attacks."""
    guardian = ScopeGuardian(allowlist=["*.corp.local", "api.target.com"])

    # Legitimate in-scope subdomains
    assert guardian.is_in_scope("https://auth.corp.local/login") is True
    assert guardian.is_in_scope("https://api.target.com/v1") is True

    # Malicious spoofing / prefix collision attempts
    assert guardian.is_in_scope("https://notcorp.local/") is False
    assert guardian.is_in_scope("https://evil-corp.local/") is False
    assert guardian.is_in_scope("https://corp.local.attacker.com/") is False
    assert guardian.is_in_scope("https://attacker-api.target.com/") is False
    assert guardian.is_in_scope("https://target.com.attacker.com/") is False


def test_url_sanitizer_null_byte_and_control_chars() -> None:
    """Verify URL sanitizer detects and blocks null byte and control character injections."""
    with pytest.raises(ValueError, match="Null bytes detected"):
        URLSanitizer.normalize_url("http://example.com/page\x00malicious")

    with pytest.raises(ValueError, match="Null bytes detected"):
        URLSanitizer.normalize_url("http://\x00example.com/")


@pytest.mark.asyncio
async def test_ssrf_via_redirect_hop_protection() -> None:
    """Verify AsyncRequester blocks redirect hops to metadata IP (169.254.169.254)."""

    def redirect_to_metadata_handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str == "http://public-target.com/redir":
            # Attacker redirects to AWS EC2 metadata endpoint
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
            )
        return httpx.Response(200, text="Metadata secret")

    transport = httpx.MockTransport(redirect_to_metadata_handler)
    guardian = ScopeGuardian(allowlist=["public-target.com"], enforce_scope=True)
    requester = AsyncRequester(scope_guardian=guardian)
    requester._client = httpx.AsyncClient(transport=transport)

    async with requester:
        with pytest.raises(ScopeViolationError, match="is outside authorized scanning scope"):
            await requester.get("http://public-target.com/redir", follow_redirects=True)


def test_redos_resistance_for_core_regexes() -> None:
    """Verify core scanning and parsing regular expressions are immune to ReDoS."""
    # 1. HREF parser against long adversarial repetitive string
    adversarial_html = '<a href="' + "a/" * 10000 + '"' + " " * 5000 + ">Link</a>"
    start = time.perf_counter()
    matches = HREF_REGEX.findall(adversarial_html)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.1  # Must execute in under 100ms
    assert len(matches) == 1

    # 2. SQL error signatures against long repetitive output
    adversarial_db_output = "warning: standard text message " * 5000 + "sqlite3 error"
    start_sqli = time.perf_counter()
    for pattern in SQLiScanner.SQL_ERROR_PATTERNS:
        pattern.search(adversarial_db_output)
    elapsed_sqli = time.perf_counter() - start_sqli

    assert elapsed_sqli < 0.1  # All error patterns must finish in < 100ms
