"""Domain and vulnerability taxonomy models for web-security-scanner."""

from webscan.models.report import ScanReport
from webscan.models.scan import ScanOptions, ScanProfile, ScanStatus
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding

__all__ = [
    "ScanOptions",
    "ScanProfile",
    "ScanReport",
    "ScanStatus",
    "ScanTarget",
    "Severity",
    "VulnerabilityCategory",
    "VulnerabilityFinding",
]
