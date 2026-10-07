"""Unit tests for HeadersScanner and CookieScanner."""

from webscan.models.vulnerability import Severity, VulnerabilityCategory
from webscan.scanners.cookie_scanner import CookieScanner
from webscan.scanners.headers_scanner import HeadersScanner


def test_headers_scanner_vulnerable_response() -> None:
    """Test HeadersScanner flags missing and vulnerable HTTP security headers."""
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline';",
        "X-Frame-Options": "ALLOW-FROM https://partner.example.com",
    }
    findings = HeadersScanner.scan_headers("https://example.com/app", headers)
    finding_ids = [f.finding_id for f in findings]

    # Expect HSTS missing on HTTPS
    assert "FIND-HDR-001" in finding_ids
    # Expect CSP unsafe-inline flagged
    assert "FIND-HDR-004" in finding_ids
    # Expect ineffective X-Frame-Options flagged
    assert "FIND-HDR-005" in finding_ids
    # Expect missing nosniff
    assert "FIND-HDR-006" in finding_ids
    # Expect Server version disclosure
    assert "FIND-HDR-008" in finding_ids
    # Expect X-Powered-By disclosure
    assert "FIND-HDR-009" in finding_ids


def test_headers_scanner_hardened_response() -> None:
    """Test HeadersScanner produces zero findings for a fully hardened response."""
    hardened_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Server": "web-server",
    }
    findings = HeadersScanner.scan_headers("https://hardened.example.com/", hardened_headers)
    assert len(findings) == 0


def test_headers_scanner_suboptimal_hsts() -> None:
    """Test detection of HSTS with max-age under 180 days."""
    headers = {
        "Strict-Transport-Security": "max-age=86400",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    findings = HeadersScanner.scan_headers("https://example.com/", headers)
    assert any(f.finding_id == "FIND-HDR-002" for f in findings)


def test_cookie_scanner_insecure_flags() -> None:
    """Test CookieScanner identifies missing Secure, HttpOnly, and SameSite attributes."""
    cookies = [
        "session_id=abc123xyz456; Path=/; Domain=.example.com",
        "preferences=dark_theme; Path=/",
    ]
    findings = CookieScanner.scan_cookies("https://secure.example.com/login", cookies)
    finding_ids = [f.finding_id for f in findings]

    # session_id lacks Secure on HTTPS
    assert "FIND-CK-001" in finding_ids
    # session_id lacks HttpOnly
    assert "FIND-CK-002" in finding_ids
    # Both cookies lack SameSite
    assert "FIND-CK-003" in finding_ids

    # Check categories and severities
    for f in findings:
        assert f.category == VulnerabilityCategory.COOKIES
        assert f.severity in (Severity.MEDIUM, Severity.LOW)


def test_cookie_scanner_hardened_flags() -> None:
    """Test CookieScanner produces zero findings for secure, hardened cookies."""
    secure_cookies = [
        "session_id=token123; Secure; HttpOnly; SameSite=Strict; Path=/",
        "tracking=opt_out; Secure; SameSite=Lax; Path=/",
    ]
    findings = CookieScanner.scan_cookies("https://secure.example.com/", secure_cookies)
    assert len(findings) == 0
