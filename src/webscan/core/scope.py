"""Scope guardian enforcing authorized target allowlists and preventing out-of-scope scans."""

import fnmatch
from collections.abc import Iterable

from webscan.config.settings import get_settings
from webscan.core.sanitizer import URLSanitizer


class ScopeViolationError(Exception):
    """Raised when a request or scan targets a domain/IP outside the authorized scope."""


class ScopeGuardian:
    """Enforces target boundaries against an authorized domain/IP allowlist."""

    def __init__(
        self,
        allowlist: Iterable[str] | None = None,
        enforce_scope: bool | None = None,
    ) -> None:
        settings = get_settings()
        if allowlist is None:
            self.allowlist: set[str] = {item.lower() for item in settings.default_allowlist}
        else:
            self.allowlist = {item.strip().lower() for item in allowlist if item.strip()}

        if enforce_scope is None:
            self.enforce_scope: bool = settings.enforce_scope
        else:
            self.enforce_scope = enforce_scope

    def add_allowed_target(self, target: str) -> None:
        """Add a domain, IP, or wildcard pattern to the authorized allowlist."""
        clean = target.strip().lower()
        if clean:
            self.allowlist.add(clean)

    def is_in_scope(self, url: str) -> bool:
        """Check if target URL belongs to authorized domain/IP scope."""
        if not self.enforce_scope:
            return True

        try:
            domain = URLSanitizer.extract_domain(url).lower()
        except ValueError:
            return False

        if not domain:
            return False

        # Exact match
        if domain in self.allowlist:
            return True

        # Wildcard match (e.g. *.corp.local)
        for pattern in self.allowlist:
            if "*" in pattern and fnmatch.fnmatch(domain, pattern):
                return True
            # Match subdomains if pattern is domain with leading dot (.example.com)
            if pattern.startswith(".") and domain.endswith(pattern):
                return True

        return False

    def assert_in_scope(self, url: str) -> None:
        """Assert that URL is in scope, raising ScopeViolationError otherwise."""
        if not self.is_in_scope(url):
            raise ScopeViolationError(
                f"Target '{url}' is outside authorized scanning scope. "
                f"Allowlist: {sorted(self.allowlist)}"
            )
