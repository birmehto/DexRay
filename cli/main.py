from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.columns import Columns
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from core.analysis_engine import AnalysisEngine
from config.settings import settings

app = typer.Typer(
    name="dexray",
    help="DexRay - APK static security scanner",
    add_completion=False,
)
console = Console()

logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, console=console)],
    force=True,
)


def _setup_logging(verbose: bool = False) -> None:
    if verbose:
        logging.getLogger("dexray").setLevel(logging.DEBUG)
        logging.getLogger("scanner").setLevel(logging.DEBUG)
        logging.getLogger("core").setLevel(logging.DEBUG)
    else:
        logging.getLogger("dexray").setLevel(logging.WARNING)
        logging.getLogger("scanner").setLevel(logging.WARNING)
        logging.getLogger("core").setLevel(logging.WARNING)


@app.callback()
def main_callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    _setup_logging(verbose)
    settings.ensure_directories()


def _validate_apk(apk_path: str) -> Path:
    path = Path(apk_path)
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {apk_path}")
        raise typer.Exit(1)
    if path.suffix.lower() != ".apk":
        console.print(f"[red]Error:[/red] File must have .apk extension: {apk_path}")
        raise typer.Exit(1)
    return path


def _risk_bar(score: int) -> str:
    filled = score // 5
    empty = 20 - filled
    return "█" * filled + "░" * empty


def _risk_label(score: int) -> tuple[str, str]:
    if score >= 70:
        return "red", "High Risk"
    if score >= 40:
        return "yellow", "Medium Risk"
    if score >= 20:
        return "blue", "Low Risk"
    return "green", "Safe"


def _build_vuln_tree(analysis) -> Tree:
    tree = Tree("[bold]Vulnerabilities by Category[/bold]")
    for cat, group in analysis.category_counts.items():
        color = {
            "Hardcoded Secrets": "red",
            "Network Security": "orange3",
            "WebView Vulnerabilities": "orange3",
            "Exported Components": "yellow",
            "Platform Misuse": "yellow",
            "Code Quality": "blue",
            "Configuration Issues": "blue",
            "Insecure Storage": "yellow",
        }.get(cat, "white")
        tree.add(f"[{color}]{cat}[/] [dim]({group})[/]")
    return tree


def _show_summary_table(analysis) -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold")
    t.add_column()
    pkg = analysis.manifest.package_name if analysis.manifest else "N/A"
    version = analysis.manifest.version_name if analysis.manifest and analysis.manifest.version_name else ""
    pkg_display = f"{pkg} {version}" if version else pkg
    t.add_row("Package", pkg_display)
    t.add_row("File Size", f"{analysis.file_size / 1024 / 1024:.2f} MB")
    if analysis.manifest:
        t.add_row("Min / Target SDK", f"{analysis.manifest.min_sdk or '?'} / {analysis.manifest.target_sdk or '?'}")
    t.add_row("SHA256", f"[dim]{analysis.sha256[:24] if analysis.sha256 else 'N/A'}...[/]")
    t.add_row("Scan Duration", f"{analysis.scan_duration:.2f}s")
    return t


def _show_stat_cards(analysis) -> Columns:
    def card(label: str, value: int, color: str) -> Panel:
        return Panel(Text(str(value), justify="center", style=f"bold {color}"), title=label, padding=(0, 2), border_style="dim")

    items = [
        card("Vulnerabilities", len(analysis.vulnerabilities), "red"),
        card("Secrets", len(analysis.secrets), "orange3"),
        card("Exported Comp.", len(analysis.exported_components), "yellow"),
    ]
    if analysis.manifest:
        items.append(card("Activities", len(analysis.manifest.activities), "blue"))
    if analysis.tracking_sdks:
        items.append(card("Tracking SDKs", len(analysis.tracking_sdks), "cyan"))
    if analysis.debug_tools:
        items.append(card("Debug Tools", len(analysis.debug_tools), "magenta"))
    if analysis.native_libraries:
        items.append(card("Native Libs", len(analysis.native_libraries), "green"))
    if analysis.deep_links:
        items.append(card("Deep Links", len(analysis.deep_links), "cyan"))
    return Columns(items, equal=True, expand=True)


def _show_vulnerability_table(analysis, limit: int = 5) -> Table:
    t = Table(box=None, padding=(0, 1))
    t.add_column("", width=2)
    t.add_column("ID", style="dim", width=10)
    t.add_column("Title", style="bold")
    t.add_column("Severity", no_wrap=True)
    for v in analysis.vulnerabilities[:limit]:
        color = {"Critical": "red", "High": "orange3", "Medium": "yellow", "Low": "blue", "Info": "grey"}.get(v.severity.value, "white")
        evidence = f"  [dim]{v.evidence[:80] if v.evidence else ''}[/dim]" if v.evidence else ""
        t.add_row(f"[{color}]■[/]", v.id, v.title + evidence, f"[{color}]{v.severity.value}[/]")
    if len(analysis.vulnerabilities) > limit:
        t.add_row("", "", f"[dim]... and {len(analysis.vulnerabilities) - limit} more[/dim]", "")
    return t


def _show_secrets_table(analysis, limit: int = 5) -> Table:
    t = Table(box=None, padding=(0, 1))
    t.add_column("", width=2)
    t.add_column("Type", style="bold")
    t.add_column("Confidence", no_wrap=True)
    t.add_column("Location", style="dim")
    for s in analysis.secrets[:limit]:
        pct = int(s.confidence * 100)
        conf_color = "green" if pct >= 95 else ("yellow" if pct >= 80 else "blue")
        t.add_row("●", s.secret_type, f"[{conf_color}]{pct}%[/]", s.file_path)
    if len(analysis.secrets) > limit:
        t.add_row("", f"[dim]... and {len(analysis.secrets) - limit} more[/dim]", "", "")
    return t


def _show_env_table(analysis) -> Optional[Table]:
    if not analysis.env_variables:
        return None
    t = Table(box=None, padding=(0, 1))
    t.add_column("", width=2)
    t.add_column("Key", style="bold")
    t.add_column("File")
    sensitive_count = 0
    for e in analysis.env_variables:
        icon = "🔒" if e.is_sensitive else " "
        t.add_row(icon, e.key, e.file_path)
        if e.is_sensitive:
            sensitive_count += 1
    return Panel(t, title=f"Env Variables ({len(analysis.env_variables)}, {sensitive_count} sensitive)")


def _show_debug_tools_table(analysis) -> Optional[Panel]:
    if not analysis.debug_tools:
        return None
    t = Table(box=None, padding=(0, 1))
    t.add_column("", width=2)
    t.add_column("Tool", style="bold")
    t.add_column("Library")
    t.add_column("Evidence", style="dim")
    for dt in analysis.debug_tools:
        t.add_row("⚙", dt.name, dt.library, dt.evidence)
    return Panel(t, title=f"Debug Tools ({len(analysis.debug_tools)})")


def _show_tracking_table(analysis) -> Optional[Panel]:
    if not analysis.tracking_sdks:
        return None
    t = Table(box=None, padding=(0, 1))
    t.add_column("", width=2)
    t.add_column("SDK", style="bold")
    t.add_column("Category")
    t.add_column("Evidence", style="dim")
    for sdk in analysis.tracking_sdks:
        t.add_row("📡", sdk.name, sdk.category, sdk.evidence)
    return Panel(t, title=f"Tracking SDKs ({len(analysis.tracking_sdks)})")


def _show_deep_links_table(analysis) -> Optional[Panel]:
    if not analysis.deep_links:
        return None
    t = Table(box=None, padding=(0, 1))
    t.add_column("", width=2)
    t.add_column("URI", style="bold")
    t.add_column("Type")
    t.add_column("Component")
    for dl in analysis.deep_links:
        uri = f"{dl.scheme}://{dl.host or '*'}{dl.path or '/'}"
        kind = "✓ App Link" if dl.is_app_link and dl.is_verified else ("◐ App Link" if dl.is_app_link else "◌ Deep Link")
        color = "green" if dl.is_app_link and dl.is_verified else "yellow"
        t.add_row("", f"[{color}]{uri}[/]", kind, dl.component or "")
    return Panel(t, title=f"Deep Links ({len(analysis.deep_links)})")


def _show_build_config_panel(analysis) -> Optional[Panel]:
    if not analysis.build_config:
        return None
    bc = analysis.build_config
    parts = [
        f"Min SDK: {bc.min_sdk or '?'}",
        f"Target: {bc.target_sdk or '?'}",
        f"Compile: {bc.compile_sdk or '?'}",
    ]
    parts.append(f"Minify: {'Yes' if bc.has_minify_enabled else 'No'}")
    parts.append(f"Debuggable: {'[red]Yes[/]' if bc.has_debuggable_build else 'No'}")
    if bc.signing_configs:
        parts.append(f"Signing: {', '.join(bc.signing_configs)}")
    if bc.build_types:
        parts.append(f"Build Types: {', '.join(bc.build_types)}")
    text = Text("  │  ").join(Text(p) for p in parts)
    return Panel(text, title="Build Config", border_style="dim")


def _show_apk_signer_panel(analysis) -> Optional[Panel]:
    if not analysis.apk_signer_version:
        return None
    color = "red" if "unsigned" in analysis.apk_signer_version.lower() else "green"
    return Panel(Text(f"[{color}]{analysis.apk_signer_version}[/]"), title="APK Signing", border_style="dim")


def _show_exports_panel(analysis) -> Optional[Panel]:
    exported = analysis.exported_components
    if not exported:
        return None
    t = Table(box=None, padding=(0, 1))
    t.add_column("Type", style="bold")
    t.add_column("Name", style="dim")
    for c in exported:
        t.add_row(c.component_type, c.name)
    return Panel(t, title=f"Exported Components ({len(exported)})")


def _show_security_config_panel(analysis) -> Optional[Panel]:
    if not analysis.network_security:
        return None
    ns = analysis.network_security
    parts = []
    parts.append(f"Cleartext: {'[red]Yes[/]' if ns.cleartext_traffic_allowed else 'No'}")
    parts.append(f"Pinning: {'Yes' if ns.certificate_pinning else '[red]No[/]'}")
    parts.append(f"Debug Overrides: {'[red]Yes[/]' if ns.debug_overrides else 'No'}")
    text = Text("  │  ").join(Text(p) for p in parts)
    return Panel(text, title="Network Security", border_style="dim")


@app.command()
def scan(
    apk_path: str = typer.Argument(..., help="Path to the APK file"),
    json_output: Optional[Path] = typer.Option(None, "--json", "-j", help="Output JSON report"),
    html_output: Optional[Path] = typer.Option(None, "--html", help="Output HTML report"),
    pdf_output: Optional[Path] = typer.Option(None, "--pdf", help="Output PDF report"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Directory for reports"),
):
    """Scan an APK file for security vulnerabilities."""
    path = _validate_apk(apk_path)

    engine = AnalysisEngine()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[yellow]Analyzing APK...", total=None)
        analysis = asyncio.run(engine.analyze(str(path)))
        progress.update(task, completed=True)

    console.print()
    score_color, score_label = _risk_label(analysis.risk_score)

    header = Panel(
        Columns([_show_summary_table(analysis)], equal=True, expand=True),
        title=f"Scan Complete  —  [bold {score_color}]{analysis.risk_score}/100[/] {_risk_bar(analysis.risk_score)} [{score_color}]{score_label}[/]",
        border_style=score_color,
        padding=(1, 2),
    )
    console.print(header)

    console.print()
    console.print(_show_stat_cards(analysis))

    for cat_name, group in sorted(analysis.category_counts.items(), key=lambda x: -x[1]):
        cat_color = {
            "Hardcoded Secrets": "red",
            "Network Security": "orange3",
            "WebView Vulnerabilities": "orange3",
            "Exported Components": "yellow",
            "Platform Misuse": "yellow",
            "Dangerous Permissions": "yellow",
            "Code Quality": "blue",
            "Configuration Issues": "blue",
            "Insecure Storage": "yellow",
            "Firebase Misconfiguration": "yellow",
        }.get(cat_name, "white")
        bar = "█" * min(group, 20) + "░" * max(0, 20 - group)
        console.print(f"  [{cat_color}]■[/] {cat_name}: {bar} [dim]({group})[/]")

    if analysis.vulnerabilities:
        console.print()
        console.print(Panel(_show_vulnerability_table(analysis), title="Top Vulnerabilities", border_style="dim"))

    if analysis.secrets:
        console.print()
        console.print(Panel(_show_secrets_table(analysis), title="Secrets Found", border_style="dim", title_align="left"))

    bc_panel = _show_build_config_panel(analysis)
    if bc_panel:
        console.print()
        console.print(bc_panel)

    signer_panel = _show_apk_signer_panel(analysis)
    if signer_panel:
        console.print()
        console.print(signer_panel)

    env_panel = _show_env_table(analysis)
    if env_panel:
        console.print()
        console.print(env_panel)

    dl_panel = _show_deep_links_table(analysis)
    if dl_panel:
        console.print()
        console.print(dl_panel)

    dt_panel = _show_debug_tools_table(analysis)
    if dt_panel:
        console.print()
        console.print(dt_panel)

    sdk_panel = _show_tracking_table(analysis)
    if sdk_panel:
        console.print()
        console.print(sdk_panel)

    ns_panel = _show_security_config_panel(analysis)
    if ns_panel:
        console.print()
        console.print(ns_panel)

    exports_panel = _show_exports_panel(analysis)
    if exports_panel:
        console.print()
        console.print(exports_panel)

    base_dir = output_dir or settings.output_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    base_name = path.stem

    if json_output:
        report_path = json_output if json_output.suffix else base_dir / f"{base_name}_report.json"
    else:
        report_path = base_dir / f"{base_name}_report.json"

    if html_output:
        html_path = html_output if html_output.suffix else base_dir / f"{base_name}_report.html"
    else:
        html_path = base_dir / f"{base_name}_report.html"

    if pdf_output:
        pdf_path = pdf_output if pdf_output.suffix else base_dir / f"{base_name}_report.pdf"
    else:
        pdf_path = base_dir / f"{base_name}_report.pdf"

    from reports import JSONReportGenerator, HTMLReportGenerator, PDFReportGenerator

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("[cyan]Generating reports...", total=None)

        json_gen = JSONReportGenerator()
        json_result = asyncio.run(json_gen.generate(analysis, str(report_path)))
        html_gen = HTMLReportGenerator()
        html_result = asyncio.run(html_gen.generate(analysis, str(html_path)))
        pdf_gen = PDFReportGenerator()
        pdf_result = asyncio.run(pdf_gen.generate(analysis, str(pdf_path)))

    console.print()
    console.print(Panel(
        f"[green]✓[/] JSON: {json_result}\n"
        f"[green]✓[/] HTML: {html_result}\n"
        f"[green]✓[/] PDF:  {pdf_result}",
        title="Reports Generated",
        border_style="green",
        padding=(1, 2),
    ))


@app.command()
def report(
    apk_path: str = typer.Argument(..., help="Path to the APK file"),
    json: bool = typer.Option(False, "--json", help="Generate JSON report"),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    pdf: bool = typer.Option(False, "--pdf", help="Generate PDF report"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory"),
):
    """Generate reports for a previously scanned APK."""
    path = _validate_apk(apk_path)

    if not json and not html and not pdf:
        json = html = pdf = True

    json_path = path.with_suffix(".report.json")
    if not json_path.exists():
        console.print("[yellow]No previous scan data found. Running scan first...[/yellow]")
        ctx = typer.Context(scan)
        ctx.invoke(scan, apk_path=apk_path)
        return

    console.print("[yellow]Previous scan data loaded from: " + str(json_path) + "[/yellow]")
    console.print("[yellow]Re-run scan to regenerate reports with: dexray scan " + apk_path + "[/yellow]")


@app.command()
def strings(
    apk_path: str = typer.Argument(..., help="Path to the APK file"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Search for specific strings"),
    count: int = typer.Option(50, "--count", "-n", help="Number of strings to show"),
):
    """Extract strings from an APK file."""
    path = _validate_apk(apk_path)

    from scanner.modules.strings_scanner import StringsScanner
    scanner = StringsScanner()
    extracted = asyncio.run(scanner.extract(str(path)))

    if search:
        extracted = [s for s in extracted if search.lower() in s.lower()]

    if not extracted:
        console.print("[yellow]No strings found.[/yellow]")
        return

    console.print(f"[bold]Found {len(extracted)} strings[/bold]")
    if search:
        console.print(f"[dim]Filtered by: '{search}'[/dim]")

    table = Table(show_header=False)
    table.add_column("#", style="dim", width=4)
    table.add_column("String")
    for i, s in enumerate(extracted[:count], 1):
        table.add_row(str(i), s.strip()[:200])
    console.print(table)

    if len(extracted) > count:
        console.print(f"[dim]... and {len(extracted) - count} more[/dim]")


@app.command()
def manifest(
    apk_path: str = typer.Argument(..., help="Path to the APK file"),
):
    """Display the AndroidManifest.xml contents."""
    path = _validate_apk(apk_path)

    from scanner.modules.manifest_scanner import ManifestScanner
    scanner = ManifestScanner()
    manifest = asyncio.run(scanner.extract(str(path)))

    if not manifest.package_name:
        console.print("[red]Could not parse AndroidManifest.xml[/red]")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold]Package:[/] {manifest.package_name}\n"
        f"[bold]Version:[/] {manifest.version_name or 'N/A'} ({manifest.version_code or 'N/A'})\n"
        f"[bold]Min SDK:[/] {manifest.min_sdk or 'N/A'}\n"
        f"[bold]Target SDK:[/] {manifest.target_sdk or 'N/A'}\n"
        f"[bold]Debuggable:[/] {'[red]Yes[/]' if manifest.debuggable else 'No'}\n"
        f"[bold]Allow Backup:[/] {'[red]Yes[/]' if manifest.allow_backup else 'No'}",
        title="AndroidManifest Summary",
    ))

    tree = Tree("[bold]Components[/bold]")
    for label, comps in [
        ("Activities", manifest.activities),
        ("Services", manifest.services),
        ("Receivers", manifest.receivers),
        ("Providers", manifest.providers),
    ]:
        if comps:
            branch = tree.add(f"[bold]{label}[/] ({len(comps)})")
            for c in comps[:10]:
                exported = "[red]exported[/]" if c.exported else ""
                branch.add(f"{c.name} {exported}")
    console.print(tree)

    if manifest.permissions:
        table = Table(title=f"Permissions ({len(manifest.permissions)})")
        table.add_column("Permission")
        table.add_column("Level", justify="center")
        for perm in manifest.permissions:
            danger = "[red]Dangerous[/]" if perm.dangerous else perm.protection_level or ""
            table.add_row(perm.name, danger)
        console.print(table)

    exported = [c for c in manifest.activities + manifest.services + manifest.receivers + manifest.providers if c.exported]
    if exported:
        console.print(Panel.fit(
            "\n".join(f"  [red]![/] {c.component_type}: {c.name}" for c in exported),
            title=f"[red]Exported Components ({len(exported)})[/red]",
        ))


@app.command()
def permissions(
    apk_path: str = typer.Argument(..., help="Path to the APK file"),
    dangerous_only: bool = typer.Option(False, "--dangerous", "-d", help="Show dangerous permissions only"),
):
    """Extract and display permissions from an APK."""
    path = _validate_apk(apk_path)

    from scanner.modules.manifest_scanner import ManifestScanner
    scanner = ManifestScanner()
    manifest = asyncio.run(scanner.extract(str(path)))

    if not manifest.permissions:
        console.print("[yellow]No permissions found.[/yellow]")
        return

    perms = [p for p in manifest.permissions if not dangerous_only or p.dangerous]

    table = Table(title=f"Permissions ({len(perms)} of {len(manifest.permissions)})")
    table.add_column("Permission", style="bold")
    table.add_column("Protection Level")
    table.add_column("Description")

    for perm in perms:
        level_color = "red" if perm.dangerous else "green"
        table.add_row(
            perm.name,
            f"[{level_color}]{perm.protection_level or 'Unknown'}[/]",
            perm.description or "",
        )
    console.print(table)


@app.command()
def info(
    apk_path: str = typer.Argument(..., help="Path to the APK file"),
):
    """Display general information about an APK file."""
    path = _validate_apk(apk_path)

    import hashlib
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)

    from zipfile import ZipFile
    with ZipFile(path) as zf:
        names = zf.namelist()

    dex_files = [n for n in names if n.endswith(".dex")]
    lib_files = [n for n in names if n.endswith(".so") and "/lib/" in n]
    res_files = [n for n in names if n.startswith("res/")]
    asset_files = [n for n in names if n.startswith("assets/") and not n.endswith("/")]

    table = Table(title=f"APK Info: {path.name}")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("File Size", f"{path.stat().st_size / 1024 / 1024:.2f} MB")
    table.add_row("SHA256", sha256.hexdigest())
    table.add_row("DEX Files", str(len(dex_files)))
    table.add_row("Native Libraries", str(len(lib_files)))
    table.add_row("Resource Files", str(len(res_files)))
    table.add_row("Assets", str(len(asset_files)))
    table.add_row("Total Entries", str(len(names)))
    console.print(table)


@app.command()
def quick(
    apk_path: str = typer.Argument(..., help="Path to the APK file"),
):
    """Quick scan showing only critical/high severity issues."""
    path = _validate_apk(apk_path)
    engine = AnalysisEngine()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("[yellow]Running quick scan...", total=None)
        analysis = asyncio.run(engine.analyze(str(path)))

    crit = [v for v in analysis.vulnerabilities if v.severity.value in ("Critical", "High")]
    score_color, score_label = _risk_label(analysis.risk_score)

    console.print()
    header = Panel.fit(
        f"[bold]Risk Score: [{score_color}]{analysis.risk_score}/100[/] {_risk_bar(analysis.risk_score)} [{score_color}]{score_label}[/]\n"
        f"[bold]Critical/High:[/] {len(crit)}  |  "
        f"[bold]Secrets:[/] {len(analysis.secrets)}  |  "
        f"[bold]Duration:[/] {analysis.scan_duration:.2f}s",
        title="Quick Scan Results",
        border_style=score_color,
    )
    console.print(header)

    if crit:
        console.print()
        t = Table(box=None, padding=(0, 1))
        t.add_column("", width=2)
        t.add_column("ID", style="dim", width=10)
        t.add_column("Title", style="bold")
        t.add_column("Recommendation")
        for v in crit:
            color = "red" if v.severity.value == "Critical" else "orange3"
            rec = (v.recommendation[:120] + "..." if v.recommendation and len(v.recommendation) > 120 else v.recommendation) or ""
            t.add_row(f"[{color}]■[/]", v.id, v.title, f"[dim]{rec}[/]")
        console.print(Panel(t, title="Critical & High Vulnerabilities", border_style="red"))

    if analysis.secrets:
        high_conf = [s for s in analysis.secrets if s.confidence >= 0.8]
        if high_conf:
            console.print()
            t = Table(box=None, padding=(0, 1))
            t.add_column("", width=2)
            t.add_column("Type", style="bold")
            t.add_column("Confidence")
            t.add_column("File")
            for s in high_conf:
                t.add_row("●", s.secret_type, f"{int(s.confidence * 100)}%", s.file_path)
            console.print(Panel(t, title=f"High-Confidence Secrets ({len(high_conf)})", border_style="orange3"))

    console.print()
    console.print(_show_stat_cards(analysis))


if __name__ == "__main__":
    app()
