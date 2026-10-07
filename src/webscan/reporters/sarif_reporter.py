"""SARIF v2.1.0 report generator compatible with GitHub Code Scanning and OASIS standards."""

import json
from pathlib import Path
from typing import Any, ClassVar

from webscan.models.report import ScanReport
from webscan.models.vulnerability import Severity


class SARIFReporter:
    """Generates OASIS SARIF v2.1.0 documents for CI/CD DevSecOps integrations."""

    SEVERITY_TO_SARIF_LEVEL: ClassVar[dict[Severity, str]] = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    @classmethod
    def to_sarif_dict(cls, report: ScanReport) -> dict[str, Any]:
        """Convert a ScanReport into a SARIF v2.1.0 compliant dictionary structure."""
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for finding in report.findings:
            rule_id = finding.finding_id
            level = cls.SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": f"Remediation: {finding.remediation}\nCWE: {finding.cwe_id}",
                    },
                    "properties": {
                        "category": finding.category.value,
                        "cwe": finding.cwe_id,
                        "cvssScore": finding.cvss_score,
                    },
                    "defaultConfiguration": {
                        "level": level,
                    },
                }

            result_entry: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": (
                        f"{finding.title} detected at {finding.target_url}. "
                        f"Evidence: {finding.evidence or 'None'}"
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.target_url,
                            },
                        },
                    }
                ],
            }
            results.append(result_entry)

        sarif_doc: dict[str, Any] = {
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "web-security-scanner",
                            "informationUri": (
                                "https://github.com/cyber-portfolio/web-security-scanner"
                            ),
                            "version": "0.1.0",
                            "rules": list(rules_map.values()),
                        },
                    },
                    "results": results,
                }
            ],
        }

        return sarif_doc

    @classmethod
    def render(cls, report: ScanReport, indent: int = 2) -> str:
        """Render ScanReport as formatted SARIF JSON string."""
        return json.dumps(cls.to_sarif_dict(report), indent=indent)

    @classmethod
    def write_to_file(cls, report: ScanReport, output_path: str | Path, indent: int = 2) -> Path:
        """Write SARIF v2.1.0 report to disk file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.render(report, indent=indent)
        path.write_text(content, encoding="utf-8")
        return path
