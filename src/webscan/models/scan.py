"""Scan execution options, execution profiles, and lifecycle state."""

from enum import StrEnum

from pydantic import BaseModel, Field


class ScanStatus(StrEnum):
    """Lifecycle state of a security scan session."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanProfile(StrEnum):
    """Intensity and depth profile of a scan execution."""

    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"


class ScanOptions(BaseModel):
    """Execution options controlling concurrency, throttling, and active modules."""

    profile: ScanProfile = Field(
        default=ScanProfile.STANDARD,
        description="Scanning profile mode",
    )
    concurrency: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum concurrent asynchronous tasks",
    )
    rate_limit_rps: float = Field(
        default=20.0,
        ge=1.0,
        le=100.0,
        description="Rate limit in requests per second",
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
