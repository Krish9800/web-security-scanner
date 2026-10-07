"""Scan assessment report model consolidating findings and posture metrics."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from webscan.models.scan import ScanStatus
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import VulnerabilityFinding


class ScanReport(BaseModel):
    """Consolidated assessment report containing vulnerabilities and security metrics."""

    scan_id: str = Field(..., description="Unique UUID or identifier for the scan session")
    target: ScanTarget = Field(..., description="Target configuration under assessment")
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Scan start timestamp (UTC)",
    )
    end_time: datetime | None = Field(
        default=None,
        description="Scan completion timestamp (UTC)",
    )
    status: ScanStatus = Field(
        default=ScanStatus.COMPLETED,
        description="Final execution status",
    )
    findings: list[VulnerabilityFinding] = Field(
        default_factory=list,
        description="List of detected vulnerabilities and security weaknesses",
    )
    overall_score: int = Field(
        default=100,
        ge=0,
        le=100,
        description="Security posture score (0 - 100)",
    )
    risk_rating: str = Field(
        default="A",
        description="Qualitative letter rating (A, B, C, D, F)",
    )
    summary_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Finding counts grouped by severity",
    )
