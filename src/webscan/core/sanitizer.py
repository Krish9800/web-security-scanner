"""Defensive URL normalization, domain extraction, and header sanitization."""

import re
from urllib.parse import urlsplit, urlunsplit


class URLSanitizer:
    """Sanitizes, normalizes, and extracts structural elements from URLs."""

    _CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")

    @classmethod
    def normalize_url(cls, raw_url: str) -> str:
        """Normalize URL by stripping userinfo, lowercasing host, and fixing path."""
        if not raw_url or not raw_url.strip():
            raise ValueError("URL cannot be empty")

        clean_url = raw_url.strip()
        if "\x00" in clean_url:
            raise ValueError("Null bytes detected in URL")

        # Check scheme if present, otherwise default to http
        if "://" in clean_url:
            scheme_cand = clean_url.split("://", 1)[0].lower()
            if scheme_cand not in ("http", "https"):
                raise ValueError(f"Unsupported scheme: {scheme_cand}")
        else:
            clean_url = f"http://{clean_url}"

        parts = urlsplit(clean_url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme: {scheme}")

        hostname = parts.hostname
        if not hostname:
            raise ValueError(f"Invalid URL without valid host: {raw_url}")

        host_lower = hostname.lower()

        # Reconstruct netloc without credentials (user:pass)
        if parts.port:
            # Strip standard ports
            if (scheme == "http" and parts.port == 80) or (scheme == "https" and parts.port == 443):
                netloc = host_lower
            else:
                netloc = f"{host_lower}:{parts.port}"
        else:
            netloc = host_lower

        path = parts.path or "/"
        # Normalize redundant slashes in path
        path = re.sub(r"/{2,}", "/", path)

        return urlunsplit((scheme, netloc, path, parts.query, ""))

    @classmethod
    def extract_domain(cls, raw_url: str) -> str:
        """Extract lowercase domain/host without scheme, port, or path."""
        normalized = cls.normalize_url(raw_url)
        parts = urlsplit(normalized)
        return parts.hostname or ""

    @classmethod
    def sanitize_header_value(cls, value: str | None) -> str:
        """Strip CRLF and control characters to prevent HTTP response/header splitting."""
        if not value:
            return ""
        # Strip CRLF
        no_crlf = value.replace("\r", " ").replace("\n", " ")
        cleaned = cls._CONTROL_CHAR_PATTERN.sub("", no_crlf)
        return cleaned.strip()
