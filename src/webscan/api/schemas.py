"""API request and response schemas for web-security-scanner microservice."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from webscan.models.report import ScanReport
from webscan.models.scan import ScanProfile, ScanStatus
from webscan.models.vulnerability import VulnerabilityFinding


class HealthResponse(BaseModel):
    """Health check endpoint status response."""

    status: str = Field(default="healthy", description="Service health state")
    version: str = Field(default="0.1.0", description="Application semantic version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Current UTC timestamp",
    )


class ScanRequest(BaseModel):
    """Payload to trigger an asynchronous web security scan."""

    target_url: str = Field(
        ..., description="Target base URL to assess", examples=["https://example.com/"]
    )
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Authorized domain boundaries for scope protection",
    )
    profile: ScanProfile = Field(
        default=ScanProfile.STANDARD,
        description="Scanning intensity profile",
    )
    concurrency: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum concurrent requests",
    )
    rate_limit_rps: float = Field(
        default=20.0,
        ge=1.0,
        le=100.0,
        description="Requests per second limit",
    )
    crawl_depth: int = Field(
        default=1,
        ge=0,
        le=3,
        description="Link crawling depth",
    )
    enabled_modules: list[str] = Field(
        default_factory=lambda: [
            "headers",
            "cookies",
            "methods",
            "sensitive_files",
            "xss",
            "sqli",
            "cors",
            "redirect",
        ],
        description="List of active scanning modules to execute",
    )


class QuickProbeRequest(BaseModel):
    """Payload to trigger an immediate single-target header and method probe."""

    target_url: str = Field(..., description="Target base URL to probe")


class QuickProbeResponse(BaseModel):
    """Results from immediate single-target probe."""

    target_url: str
    findings: list[VulnerabilityFinding]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanReportResponse(BaseModel):
    """High-level summary of a completed or executing scan."""

    scan_id: str
    target_url: str
    status: ScanStatus
    overall_score: int
    risk_rating: str
    findings_count: int
    summary_counts: dict[str, int]
    report: ScanReport
