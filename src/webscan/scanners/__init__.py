"""Security scanner modules for web-security-scanner."""

from webscan.scanners.cookie_scanner import CookieScanner
from webscan.scanners.headers_scanner import HeadersScanner

__all__ = ["CookieScanner", "HeadersScanner"]
