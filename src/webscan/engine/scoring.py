"""Security posture scoring engine calculating quantitative metrics and grades."""

from enum import StrEnum
from typing import ClassVar

from webscan.models.vulnerability import Severity, VulnerabilityFinding


class PostureGrade(StrEnum):
    """Qualitative security rating grade."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class SecurityScorer:
    """Computes CVSS-weighted security posture scores, deductions, and risk grades."""

    SEVERITY_WEIGHTS: ClassVar[dict[Severity, int]] = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 7,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }

    @classmethod
    def calculate_score(cls, findings: list[VulnerabilityFinding]) -> int:
        """Calculate overall security posture score from 0 to 100 based on findings."""
        total_deductions = sum(cls.SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
        calculated = 100 - total_deductions
        return max(0, min(100, calculated))

    @classmethod
    def calculate_grade(cls, score: int) -> PostureGrade:
        """Map quantitative score (0-100) to a qualitative letter grade."""
        if score >= 90:
            return PostureGrade.A
        if score >= 80:
            return PostureGrade.B
        if score >= 70:
            return PostureGrade.C
        if score >= 60:
            return PostureGrade.D
        return PostureGrade.F

    @classmethod
    def calculate_summary_counts(cls, findings: list[VulnerabilityFinding]) -> dict[str, int]:
        """Aggregate finding counts grouped by severity level."""
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for finding in findings:
            key = finding.severity.value.lower()
            if key in counts:
                counts[key] += 1
            else:
                counts[key] = 1
        return counts
