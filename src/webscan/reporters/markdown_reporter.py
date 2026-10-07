"""Markdown report generator formatting scan assessments for human review and audits."""

from pathlib import Path

from webscan.models.report import ScanReport


class MarkdownReporter:
    """Generates human-readable GitHub-flavored Markdown security assessment reports."""

    @classmethod
    def render(cls, report: ScanReport) -> str:
        """Render complete Markdown assessment report."""
        lines: list[str] = [
            f"# Web Security Assessment Report: {report.target.url}",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Scan ID:** `{report.scan_id}`",
            f"- **Target URL:** `{report.target.url}`",
            f"- **Execution Status:** `{report.status.value}`",
            f"- **Start Time (UTC):** {report.start_time.isoformat()}",
            f"- **End Time (UTC):** {report.end_time.isoformat() if report.end_time else 'N/A'}",
            f"- **Security Posture Score:** **{report.overall_score} / 100**",
            f"- **Risk Rating Grade:** **Grade {report.risk_rating}**",
            "",
            "### Vulnerability Counts by Severity",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| **CRITICAL** | {report.summary_counts.get('critical', 0)} |",
            f"| **HIGH** | {report.summary_counts.get('high', 0)} |",
            f"| **MEDIUM** | {report.summary_counts.get('medium', 0)} |",
            f"| **LOW** | {report.summary_counts.get('low', 0)} |",
            f"| **INFO** | {report.summary_counts.get('info', 0)} |",
            f"| **TOTAL** | {len(report.findings)} |",
            "",
        ]

        # Table of Findings
        lines.extend(
            [
                "## 2. Findings Inventory",
                "",
            ]
        )

        if not report.findings:
            lines.extend(
                [
                    "No security vulnerabilities or weaknesses detected during this scan session.",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "| ID | Severity | Category | Title | CWE | CVSS |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for f in report.findings:
                lines.append(
                    f"| `{f.finding_id}` | `{f.severity.value}` | `{f.category.value}` | "
                    f"{f.title} | `{f.cwe_id}` | `{f.cvss_score:.1f}` |"
                )
            lines.append("")

            # Detailed Findings
            lines.extend(
                [
                    "## 3. Detailed Vulnerability Analyses & Remediations",
                    "",
                ]
            )

            for idx, f in enumerate(report.findings, start=1):
                lines.extend(
                    [
                        f"### {idx}. [{f.finding_id}] {f.title}",
                        "",
                        f"- **Severity:** `{f.severity.value}` (CVSS: `{f.cvss_score:.1f}`)",
                        f"- **Category:** `{f.category.value}`",
                        f"- **CWE:** `{f.cwe_id}`",
                        f"- **Target URL:** `{f.target_url}`",
                    ]
                )
                if f.parameter:
                    lines.append(f"- **Vulnerable Parameter:** `{f.parameter}`")

                lines.extend(
                    [
                        "",
                        "**Description:**",
                        f"{f.description}",
                        "",
                    ]
                )

                if f.evidence:
                    lines.extend(
                        [
                            "**Evidence / Proof of Concept:**",
                            "```text",
                            f"{f.evidence}",
                            "```",
                            "",
                        ]
                    )

                lines.extend(
                    [
                        "**Remediation Guidance:**",
                        f"> {f.remediation}",
                        "",
                        "---",
                        "",
                    ]
                )

        return "\n".join(lines)

    @classmethod
    def write_to_file(cls, report: ScanReport, output_path: str | Path) -> Path:
        """Write Markdown report to disk file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.render(report)
        path.write_text(content, encoding="utf-8")
        return path
