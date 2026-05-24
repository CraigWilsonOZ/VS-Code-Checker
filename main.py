#!/usr/bin/env python3
"""
VS Code Security Checker

Audits your VS Code installation for security risks across two scan areas:
  1. Extensions - CVE lookups, AI extensions, dangerous API proposals, install source
  2. Settings   - Secrets, AI config, trusted folders, remote hosts, full inventory

Usage:
  python main.py                          full scan, all output formats
  python main.py --scan extensions        extension audit only
  python main.py --scan settings          settings audit only
  python main.py --no-cve                 skip CVE API lookups (offline mode)
  python main.py --threshold HIGH         console shows HIGH+ findings only
  python main.py --output-dir ./out       save reports to custom directory
  python main.py --config config.yaml     load options from a config file
  python main.py --github-token TOKEN     GitHub token for higher API rate limits
"""

import os
import sys
from datetime import datetime

import click


@click.command()
@click.option(
    "--scan",
    type=click.Choice(["extensions", "settings", "full"]),
    default="full",
    show_default=True,
    help="Which scan to run.",
)
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=True),
    default=None,
    help="Path to a config.yaml file.",
)
@click.option(
    "--extensions-dir",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    default=None,
    help="Override the VS Code extensions directory path.",
)
@click.option(
    "--settings-file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    default=None,
    help="Override the VS Code settings.json path.",
)
@click.option(
    "--output-dir",
    default="./reports",
    show_default=True,
    help="Directory for JSON and Markdown report files.",
)
@click.option(
    "--format",
    "output_formats",
    default="console,json,markdown",
    show_default=True,
    help="Comma-separated output formats: console, json, markdown, html.",
)
@click.option(
    "--threshold",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    default="INFO",
    show_default=True,
    help="Minimum severity level to include in console output.",
)
@click.option(
    "--no-cve",
    is_flag=True,
    default=False,
    help="Skip CVE/vulnerability API lookups (offline mode).",
)
@click.option(
    "--no-marketplace",
    is_flag=True,
    default=False,
    help="Skip VS Code Marketplace API queries.",
)
@click.option(
    "--no-github",
    is_flag=True,
    default=False,
    help="Skip GitHub Advisory Database queries.",
)
@click.option(
    "--github-token",
    default=None,
    envvar="GITHUB_TOKEN",
    help="GitHub token for higher API rate limits (or set GITHUB_TOKEN env var).",
)
@click.option(
    "--concurrency",
    type=click.IntRange(1, 50),
    default=5,
    show_default=True,
    help="Max concurrent CVE API requests.",
)
def main(
    scan,
    config_file,
    extensions_dir,
    settings_file,
    output_dir,
    output_formats,
    threshold,
    no_cve,
    no_marketplace,
    no_github,
    github_token,
    concurrency,
):
    """VS Code Security Checker - audit extensions and settings for risks."""

    from src.audit.extension_auditor import ExtensionAuditor
    from src.audit.settings_auditor import SettingsAuditor
    from src.config.settings import AppConfig
    from src.discovery.extension_scanner import ExtensionScanner
    from src.discovery.settings_scanner import SettingsScanner
    from src.models.findings import SEVERITY_ORDER, Severity
    from src.platform.base import AbstractPlatform
    from src.report.builder import ReportBuilder
    from src.report.console_renderer import ConsoleRenderer
    from src.report.html_renderer import HtmlRenderer
    from src.report.json_renderer import JSONRenderer
    from src.report.markdown_renderer import MarkdownRenderer

    # --- Build config: defaults -> file -> env -> CLI ---
    # Auto-discover config.yaml next to main.py if no --config flag given
    if config_file:
        app_config = AppConfig.from_file(config_file)
    else:
        import pathlib
        auto_cfg = pathlib.Path(__file__).parent / "config.yaml"
        app_config = AppConfig.from_file(str(auto_cfg)) if auto_cfg.exists() else AppConfig()

    app_config = AppConfig.from_env(app_config)

    if no_cve:
        app_config.check_cves = False
    if no_marketplace:
        app_config.check_marketplace = False
    if no_github:
        app_config.check_github_advisories = False
    if github_token:
        app_config.github_token = github_token
    if extensions_dir:
        app_config.extensions_dir = extensions_dir
    if settings_file:
        app_config.settings_file = settings_file
    app_config.output_dir = output_dir
    app_config.max_concurrent_api_requests = concurrency

    # --- Platform detection ---
    try:
        platform = AbstractPlatform.create()
        paths = platform.detect_vscode_paths()
    except RuntimeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if app_config.extensions_dir:
        paths.extensions_dir = app_config.extensions_dir
    if app_config.settings_file:
        paths.user_settings = app_config.settings_file

    threshold_sev = Severity[threshold]
    valid_formats = {"console", "json", "markdown", "html"}
    formats = {f.strip().lower() for f in output_formats.split(",") if f.strip()}
    invalid = formats - valid_formats
    if invalid:
        click.echo(f"Error: invalid format(s): {', '.join(invalid)}", err=True)
        click.echo(f"Valid formats: {', '.join(sorted(valid_formats))}", err=True)
        sys.exit(1)

    sections = []
    total_extensions = 0

    # --- Extension scan ---
    if scan in ("extensions", "full"):
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

        scanner = ExtensionScanner(platform, paths)
        click.echo("Scanning extensions directory...")
        extensions = scanner.scan()
        total_extensions = len(extensions)
        click.echo(f"Found {total_extensions} extensions.")

        auditor = ExtensionAuditor(app_config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ) as progress:
            task = progress.add_task(
                f"Auditing {total_extensions} extensions...",
                total=total_extensions,
            )

            def on_progress(current, total, ext_id):
                progress.update(
                    task,
                    advance=1,
                    description=f"Checking {ext_id} ({current}/{total})",
                )

            section = auditor.audit(extensions, progress_callback=on_progress)

        sections.append(section)

    # --- Settings scan ---
    if scan in ("settings", "full"):
        click.echo("Scanning VS Code settings...")
        settings_scanner = SettingsScanner(platform, paths)
        scan_data = settings_scanner.scan()
        settings_sections = SettingsAuditor().audit(scan_data)
        sections.extend(settings_sections)

    # --- Build report ---
    builder = ReportBuilder()
    report = builder.build(
        sections=sections,
        paths=paths,
        platform_name=platform.get_platform_name(),
        total_extensions=total_extensions,
        scan_type=scan,
    )

    # --- Render ---
    if "console" in formats:
        ConsoleRenderer(stale_days=app_config.stale_extension_days).render(report, threshold=threshold_sev)

    if formats - {"console"}:
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if "json" in formats:
        json_path = os.path.join(output_dir, f"vscode_security_{ts}.json")
        JSONRenderer().render(report, json_path)
        click.echo(f"JSON report saved: {json_path}")

    if "markdown" in formats:
        md_path = os.path.join(output_dir, f"vscode_security_{ts}.md")
        MarkdownRenderer(stale_days=app_config.stale_extension_days).render(report, md_path)
        click.echo(f"Markdown report saved: {md_path}")

    if "html" in formats:
        html_path = os.path.join(output_dir, f"vscode_security_{ts}.html")
        HtmlRenderer(stale_days=app_config.stale_extension_days).render(report, html_path)
        click.echo(f"HTML report saved: {html_path}")

    # Exit 2 when CRITICAL findings present (useful for CI gating)
    if report.critical_count > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
