"""JSON report generator serializing scan results to standard JSON format."""

import json
from pathlib import Path

from webscan.models.report import ScanReport


class JSONReporter:
    """Serializes ScanReport instances into standardized JSON representations."""

    @classmethod
    def render(cls, report: ScanReport, indent: int = 2) -> str:
        """Render ScanReport as formatted JSON string."""
        return json.dumps(report.model_dump(mode="json"), indent=indent)

    @classmethod
    def write_to_file(cls, report: ScanReport, output_path: str | Path, indent: int = 2) -> Path:
        """Write JSON report to disk file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.render(report, indent=indent)
        path.write_text(content, encoding="utf-8")
        return path
