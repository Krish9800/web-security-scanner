"""Factory for resolving and executing report generators by output format."""

from pathlib import Path

from webscan.models.report import ScanReport
from webscan.reporters.json_reporter import JSONReporter
from webscan.reporters.markdown_reporter import MarkdownReporter
from webscan.reporters.sarif_reporter import SARIFReporter


class ReporterFactory:
    """Dispatches report generation to format-specific reporters."""

    @classmethod
    def render(cls, report: ScanReport, format_type: str = "json") -> str:
        """Render report into specified format string ('json', 'markdown', 'sarif')."""
        fmt = format_type.strip().lower()
        if fmt in ("json", "application/json"):
            return JSONReporter.render(report)
        if fmt in ("markdown", "md", "text/markdown"):
            return MarkdownReporter.render(report)
        if fmt in ("sarif", "sarif-json"):
            return SARIFReporter.render(report)
        raise ValueError(
            f"Unsupported report format: '{format_type}'. Supported: 'json', 'markdown', 'sarif'."
        )

    @classmethod
    def write_to_file(
        cls,
        report: ScanReport,
        output_path: str | Path,
        format_type: str = "json",
    ) -> Path:
        """Write formatted assessment report to disk file."""
        fmt = format_type.strip().lower()
        if fmt in ("json", "application/json"):
            return JSONReporter.write_to_file(report, output_path)
        if fmt in ("markdown", "md", "text/markdown"):
            return MarkdownReporter.write_to_file(report, output_path)
        if fmt in ("sarif", "sarif-json"):
            return SARIFReporter.write_to_file(report, output_path)
        raise ValueError(
            f"Unsupported report format: '{format_type}'. Supported: 'json', 'markdown', 'sarif'."
        )
