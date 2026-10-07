"""Web Security Scanner Command Line Interface (CLI) powered by Typer and Rich."""

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from webscan.core.requester import AsyncRequester
from webscan.core.sanitizer import URLSanitizer
from webscan.core.scope import ScopeGuardian
from webscan.engine.orchestrator import ScanOrchestrator
from webscan.lab.vulnerable_app import run_lab_server
from webscan.models.report import ScanReport
from webscan.models.scan import ScanOptions, ScanProfile
from webscan.models.target import ScanTarget
from webscan.models.vulnerability import Severity
from webscan.reporters.factory import ReporterFactory
from webscan.scanners.headers_scanner import HeadersScanner
from webscan.scanners.methods_scanner import MethodsScanner

app = typer.Typer(
    name="webscan",
    help="Enterprise Web Vulnerability Assessment and Security Posture Scanner.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target_url: Annotated[str, typer.Argument(help="Target base URL to assess")],
    format_type: Annotated[
        str | None,
        typer.Option("--format", "-f", help="Report format (json, markdown, sarif)"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="File path to save the generated report"),
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-c", min=1, max=50, help="Max concurrent requests"),
    ] = 10,
    rate_limit: Annotated[
        float,
        typer.Option("--rate-limit", "-r", min=1.0, max=100.0, help="Max requests per second"),
    ] = 20.0,
    depth: Annotated[
        int,
        typer.Option("--depth", "-d", min=0, max=3, help="Link crawling depth"),
    ] = 1,
    allow_hosts: Annotated[
        list[str] | None,
        typer.Option("--allow-host", help="Explicit allowed hosts for scope boundary"),
    ] = None,
    no_scope: Annotated[
        bool,
        typer.Option("--no-scope", help="Disable strict scope boundary enforcement"),
    ] = False,
    profile: Annotated[
        ScanProfile,
        typer.Option("--profile", help="Scan intensity profile (quick, standard, deep)"),
    ] = ScanProfile.STANDARD,
    fail_on_high: Annotated[
        bool,
        typer.Option("--fail-on-high", help="Exit with code 1 if Critical or High findings occur"),
    ] = False,
) -> None:
    """Execute automated security vulnerability scan against an authorized web target."""
    try:
        normalized_url = URLSanitizer.normalize_url(target_url)
    except ValueError as exc:
        console.print(f"[bold red]Target URL Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    hosts = list(allow_hosts) if allow_hosts else []
    try:
        domain = URLSanitizer.extract_domain(normalized_url)
        if domain not in hosts:
            hosts.append(domain)
    except ValueError:
        pass

    target = ScanTarget(
        url=normalized_url,
        scope_allowlist=hosts,
    )

    options = ScanOptions(
        profile=profile,
        concurrency=concurrency,
        rate_limit_rps=rate_limit,
        crawl_depth=depth,
    )

    guardian = ScopeGuardian(
        allowlist=hosts,
        enforce_scope=not no_scope,
    )
    requester = AsyncRequester(
        scope_guardian=guardian,
        concurrency=concurrency,
        rate_limit_rps=rate_limit,
    )

    with console.status("[bold green]Running security vulnerability scan...", spinner="dots"):
        orchestrator = ScanOrchestrator(
            target=target,
            options=options,
            requester=requester,
        )
        report = asyncio.run(orchestrator.execute_scan())

    # Format / output handling
    if format_type and not output:
        # Print raw rendered format directly
        try:
            rendered = ReporterFactory.render(report, format_type)
            console.print(rendered)
        except ValueError as exc:
            console.print(f"[bold red]Format Error:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc
    else:
        # Display Rich terminal summary
        _render_terminal_summary(report)

    if output:
        target_fmt = format_type or _detect_format_from_extension(output)
        try:
            written_path = ReporterFactory.write_to_file(report, output, target_fmt)
            console.print(f"[bold green]Report saved to:[/bold green] [cyan]{written_path}[/cyan]")
        except ValueError as exc:
            console.print(f"[bold red]Report Error:[/bold red] {exc}")
            raise typer.Exit(code=2) from exc

    # CI/CD fail on high gate
    has_critical_or_high = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) for f in report.findings
    )
    if fail_on_high and has_critical_or_high:
        console.print(
            "[bold red]Security Gate Failed:[/bold red] High/Critical vulnerabilities detected."
        )
        raise typer.Exit(code=1)


@app.command()
def probe(
    target_url: Annotated[str, typer.Argument(help="Target URL to quickly probe")],
) -> None:
    """Quickly probe target HTTP headers, security flags, and supported methods."""
    try:
        normalized_url = URLSanitizer.normalize_url(target_url)
    except ValueError as exc:
        console.print(f"[bold red]URL Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    domain = URLSanitizer.extract_domain(normalized_url)
    guardian = ScopeGuardian(allowlist=[domain], enforce_scope=False)
    requester = AsyncRequester(scope_guardian=guardian)

    async def _run_probe() -> None:
        async with requester:
            resp = await requester.get(normalized_url, follow_redirects=True)
            hdr_findings = HeadersScanner.scan_headers(normalized_url, resp.headers)
            method_findings = await MethodsScanner.scan_methods(normalized_url, requester)

            table = Table(title=f"Security Probe: {normalized_url}")
            table.add_column("Category", style="cyan")
            table.add_column("Severity", style="magenta")
            table.add_column("Title", style="white")

            for f in hdr_findings + method_findings:
                table.add_row(f.category.value, f.severity.value, f.title)

            console.print(table)

    with console.status("[bold blue]Probing target server...", spinner="bouncingBar"):
        asyncio.run(_run_probe())


@app.command()
def lab(
    host: Annotated[str, typer.Option("--host", "-h", help="Lab host address")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Lab port number")] = 8888,
) -> None:
    """Launch the built-in deliberately vulnerable web security sandbox lab."""
    console.print(
        Panel.fit(
            f"[bold red]STARTING VULNERABLE SECURITY LAB TARGET[/bold red]\n"
            f"Address: [cyan]http://{host}:{port}[/cyan]\n"
            "[yellow]WARNING: Run ONLY for testing webscan in isolated environments.[/yellow]",
            title="WebScan Security Lab",
        )
    )
    run_lab_server(host=host, port=port)


@app.command()
def version() -> None:
    """Display web-security-scanner version and runtime configuration."""
    console.print("[bold cyan]web-security-scanner[/bold cyan] v0.1.0")
    console.print(f"Python runtime: [green]{sys.version.split()[0]}[/green]")
    console.print(
        "Active modules: headers, cookies, methods, sensitive_files, xss, sqli, cors, redirect"
    )


def _render_terminal_summary(report: ScanReport) -> None:
    """Render structured Rich panels and tables for terminal output."""
    score_color = (
        "green" if report.overall_score >= 90 else "yellow" if report.overall_score >= 70 else "red"
    )

    console.print(
        Panel.fit(
            f"Target URL: [bold cyan]{report.target.url}[/bold cyan]\n"
            f"Status: [bold green]{report.status.value}[/bold green]\n"
            f"Posture Score: [bold {score_color}]{report.overall_score}/100[/bold {score_color}] "
            f"(Grade [bold {score_color}]{report.risk_rating}[/bold {score_color}])\n"
            f"Total Findings: [bold]{len(report.findings)}[/bold]",
            title=f"Assessment Report: {report.scan_id[:8]}",
        )
    )

    if report.findings:
        table = Table(title="Detected Security Weaknesses")
        table.add_column("ID", style="dim", width=14)
        table.add_column("Severity", width=10)
        table.add_column("Category", width=18)
        table.add_column("Title")
        table.add_column("CWE", width=10)

        for f in report.findings:
            sev_color = (
                "bold red"
                if f.severity == Severity.CRITICAL
                else "red"
                if f.severity == Severity.HIGH
                else "yellow"
                if f.severity == Severity.MEDIUM
                else "blue"
            )
            table.add_row(
                f.finding_id,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                f.category.value,
                f.title,
                f.cwe_id,
            )

        console.print(table)


def _detect_format_from_extension(path: Path) -> str:
    """Infer report format from file extension."""
    suffix = path.suffix.lower()
    if suffix in (".json",):
        return "json"
    if suffix in (".md", ".markdown"):
        return "markdown"
    if suffix in (".sarif",):
        return "sarif"
    return "json"


if __name__ == "__main__":
    app()
