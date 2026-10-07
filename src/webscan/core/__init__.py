"""Core engine components for web-security-scanner."""

from webscan.core.sanitizer import URLSanitizer
from webscan.core.scope import ScopeGuardian, ScopeViolationError

__all__ = ["ScopeGuardian", "ScopeViolationError", "URLSanitizer"]
