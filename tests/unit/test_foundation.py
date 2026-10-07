"""Unit tests for settings, URL sanitizer, and scope guardian."""

import pytest

from webscan.config.settings import Settings, get_settings
from webscan.core.sanitizer import URLSanitizer
from webscan.core.scope import ScopeGuardian, ScopeViolationError


def test_settings_initialization() -> None:
    """Test default settings attributes."""
    settings = Settings()
    assert settings.app_name == "Web Security Assessment Scanner"
    assert settings.version == "0.1.0"
    assert settings.default_timeout_seconds > 0
    assert "127.0.0.1" in settings.default_allowlist
    assert get_settings() is get_settings()


def test_url_sanitizer_normalize_valid() -> None:
    """Test URL normalization across standard and non-standard URLs."""
    # Prepend missing scheme
    assert URLSanitizer.normalize_url("localhost:8080/test") == "http://localhost:8080/test"

    # Strip default port 80 for HTTP and 443 for HTTPS
    assert URLSanitizer.normalize_url("http://example.com:80/path") == "http://example.com/path"
    assert URLSanitizer.normalize_url("https://example.com:443/path") == "https://example.com/path"

    # Retain non-standard port
    assert URLSanitizer.normalize_url("https://example.com:8443/") == "https://example.com:8443/"

    # Strip credentials
    assert (
        URLSanitizer.normalize_url("http://user:secret@target.local/api")
        == "http://target.local/api"
    )

    # Collapse redundant slashes
    assert URLSanitizer.normalize_url("http://example.com///api//v1") == "http://example.com/api/v1"


def test_url_sanitizer_invalid_inputs() -> None:
    """Test error handling on invalid URL inputs."""
    with pytest.raises(ValueError, match="URL cannot be empty"):
        URLSanitizer.normalize_url("   ")

    with pytest.raises(ValueError, match="Null bytes detected"):
        URLSanitizer.normalize_url("http://example.com/page\x00.php")

    with pytest.raises(ValueError, match="Unsupported scheme"):
        URLSanitizer.normalize_url("ftp://example.com/file.txt")


def test_url_sanitizer_extract_domain_and_header_cleaning() -> None:
    """Test domain extraction and header sanitization."""
    assert URLSanitizer.extract_domain("http://api.target.local:9000/v1") == "api.target.local"
    assert URLSanitizer.extract_domain("https://example.org") == "example.org"

    # Header sanitization stripping CRLF
    dirty_header = "value\r\nSet-Cookie: session=hijacked\r\n"
    clean_header = URLSanitizer.sanitize_header_value(dirty_header)
    assert "\r" not in clean_header
    assert "\n" not in clean_header
    assert "Set-Cookie" in clean_header


def test_scope_guardian_allowlist_and_wildcards() -> None:
    """Test ScopeGuardian domain validation and wildcard patterns."""
    guardian = ScopeGuardian(allowlist=["127.0.0.1", "localhost", "*.target.local", ".example.org"])

    # In scope
    assert guardian.is_in_scope("http://127.0.0.1:8000/api") is True
    assert guardian.is_in_scope("https://localhost/login") is True
    assert guardian.is_in_scope("http://sub.target.local:3000/page") is True
    assert guardian.is_in_scope("https://app.example.org/dashboard") is True

    # Out of scope
    assert guardian.is_in_scope("https://google.com") is False
    assert guardian.is_in_scope("http://evil-attacker.com") is False

    # Assertion checks
    guardian.assert_in_scope("http://127.0.0.1:5000")
    with pytest.raises(ScopeViolationError, match="outside authorized scanning scope"):
        guardian.assert_in_scope("https://unauthorized-victim.com")


def test_scope_guardian_disabled_enforcement() -> None:
    """Test that disabling scope enforcement permits any URL."""
    guardian = ScopeGuardian(allowlist=["localhost"], enforce_scope=False)
    assert guardian.is_in_scope("https://external.domain.com") is True
    guardian.assert_in_scope("https://external.domain.com")


def test_scope_guardian_add_target_and_edge_cases() -> None:
    """Test default ScopeGuardian, adding targets dynamically, and invalid URLs."""
    default_guardian = ScopeGuardian()
    assert default_guardian.is_in_scope("http://localhost:8000") is True

    default_guardian.add_allowed_target("api.internal")
    assert default_guardian.is_in_scope("http://api.internal/v1") is True

    # Empty target add
    default_guardian.add_allowed_target("   ")

    # Invalid URL returns False
    assert default_guardian.is_in_scope("not a url \x00") is False
