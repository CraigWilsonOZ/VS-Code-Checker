from collections import defaultdict

from rich.console import Console
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table
from rich import box

from ..models.findings import FindingCategory, SEVERITY_ORDER, Severity
from ..models.report import Report, ReportSection

_SEV_COLOR = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH:     "bold red",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}

_SEV_TAG = {
    Severity.CRITICAL: "[bold white on red] CRITICAL [/bold white on red]",
    Severity.HIGH:     "[bold red]  HIGH    [/bold red]",
    Severity.MEDIUM:   "[bold yellow] MEDIUM  [/bold yellow]",
    Severity.LOW:      "[cyan]  LOW     [/cyan]",
    Severity.INFO:     "[dim]  INFO    [/dim]",
}

_GROUP_BY_SOURCE = {"Extension Security Audit"}


def _days_label(days: int) -> str:
    """Return a human-readable label like '6+ months' or '1+ year'."""
    if days >= 365:
        years = days // 365
        return f"{years}+ year{'s' if years != 1 else ''}"
    months = days // 30
    return f"{months}+ month{'s' if months != 1 else ''}"


class ConsoleRenderer:

    def __init__(self, stale_days: int = 365):
        self._console = Console(highlight=False)
        self._stale_days = stale_days

    def render(self, report: Report, threshold: Severity = Severity.INFO) -> None:
        self._header(report)
        self._summary(report)
        for section in report.sections:
            if section.title in _GROUP_BY_SOURCE:
                self._extension_section(section, threshold)
            elif section.title == "Settings Inventory":
                self._inventory_section(section, threshold)
            else:
                self._settings_section(section, threshold)
        self._action_summary(report, threshold)

    # ------------------------------------------------------------------ #
    # Header + summary                                                     #
    # ------------------------------------------------------------------ #

    def _header(self, report: Report) -> None:
        self._console.print()
        self._console.print(
            f"[bold white]VS Code Security Checker[/bold white]  "
            f"[dim]{report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}  "
            f"Platform: {report.platform}  "
            f"Extensions scanned: {report.total_extensions_scanned}[/dim]"
        )
        self._console.print()

    def _summary(self, report: Report) -> None:
        by_sev = report.findings_by_severity
        parts = []
        for sev in SEVERITY_ORDER:
            count = len(by_sev[sev])
            if count == 0:
                continue
            color = _SEV_COLOR[sev]
            parts.append(f"[{color}]{sev.value}: {count}[/{color}]")
        self._console.print("  " + "   ".join(parts))
        self._console.print()

    # ------------------------------------------------------------------ #
    # Extension section                                                    #
    # ------------------------------------------------------------------ #

    def _extension_section(self, section: ReportSection, threshold: Severity) -> None:
        threshold_idx = SEVERITY_ORDER.index(threshold)

        meta_by_source: dict = {}
        real_by_source: dict = defaultdict(list)
        for f in section.findings:
            if (f.category == FindingCategory.VERSION
                    and f.severity == Severity.INFO
                    and not f.recommendation):
                meta_by_source[f.source] = f.metadata
            elif SEVERITY_ORDER.index(f.severity) <= threshold_idx:
                real_by_source[f.source].append(f)

        sources = [s for s in real_by_source if real_by_source[s]]
        if not sources:
            return

        total = sum(len(real_by_source[s]) for s in sources)
        self._console.print(Rule(
            f"[bold]Extension Security Audit[/bold]  "
            f"[dim]{total} findings across {len(sources)} extensions[/dim]",
            style="dim"
        ))
        self._console.print()

        def worst_idx(src):
            return min(SEVERITY_ORDER.index(f.severity) for f in real_by_source[src])

        for source in sorted(sources, key=worst_idx):
            findings = sorted(real_by_source[source],
                              key=lambda f: SEVERITY_ORDER.index(f.severity))
            meta = meta_by_source.get(source, {})
            self._ext_header(source, findings[0].severity, meta)
            for f in findings:
                self._finding_row(f)
            self._console.print()

    def _ext_header(self, source: str, worst: Severity, meta: dict) -> None:
        color = _SEV_COLOR[worst]

        # Line 1: extension ID + version status
        installed = meta.get("installed_version", "")
        latest = meta.get("latest_version", "")
        is_outdated = meta.get("is_outdated", False)

        if installed and latest:
            if is_outdated:
                ver_str = f"[bold yellow]v{installed} -> v{latest}  OUTDATED[/bold yellow]"
            else:
                ver_str = f"[green]v{installed}  current[/green]"
        elif installed:
            ver_str = f"v{installed}"
        else:
            ver_str = ""

        self._console.print(
            f"  [{color}]{escape(source)}[/{color}]"
            + (f"   {ver_str}" if ver_str else "")
        )

        # Line 2: publisher meta
        pub = meta.get("publisher_display_name", "")
        installs = meta.get("install_count_fmt", "")
        rating = meta.get("avg_rating")
        rating_count = meta.get("rating_count")
        updated = meta.get("last_updated", "")
        repo = meta.get("repository_url", "")
        verified = meta.get("is_verified", None)

        meta_parts = []
        if pub:
            meta_parts.append(pub)
        if verified is False:
            meta_parts.append("[yellow]unverified publisher[/yellow]")
        if installs and installs != "unknown":
            meta_parts.append(f"{installs} installs")
        if rating is not None:
            r_str = f"★ {rating:.1f}"
            if rating_count:
                r_str += f" ({_fmt_num(rating_count)} ratings)"
            meta_parts.append(r_str)
        if updated:
            meta_parts.append(f"updated {updated}")
        if repo:
            meta_parts.append(f"[link={repo}][dim underline]repo[/dim underline][/link]")

        if meta_parts:
            self._console.print("  [dim]" + "  |  ".join(
                # strip rich tags for dim wrapper compatibility
                p for p in meta_parts
            ) + "[/dim]")

        self._console.print("  " + "─" * 74)

    def _finding_row(self, f) -> None:
        tag = _SEV_TAG[f.severity]
        title = escape(f.title)
        self._console.print(f"  {tag}  {title}")

        indent = "              "  # 14 spaces - aligns under the title
        cont   = "                       "  # 23 spaces - continuation after "Label : "

        def _print_field(label: str, text: str, style: str = "") -> None:
            lines = escape(text).split("\n")
            open_s  = f"[{style}]" if style else ""
            close_s = f"[/{style}]" if style else ""
            self._console.print(f"{indent}[dim]{label}[/dim] {open_s}{lines[0]}{close_s}")
            for line in lines[1:]:
                self._console.print(f"{cont}{open_s}{line}{close_s}")

        if f.detail:
            _print_field("Detail :", f.detail)

        if f.description and f.description != f.title:
            _print_field("Info   :", f.description)

        if f.recommendation:
            _print_field("Fix    :", f.recommendation, style="italic")

        if f.cve_ids:
            self._console.print(
                f"{indent}[dim]CVEs   :[/dim] {escape(', '.join(f.cve_ids))}"
            )

        if f.references:
            for i, ref in enumerate(f.references[:3]):
                label = "Ref    :" if i == 0 else "       :"
                self._console.print(
                    f"{indent}[dim]{label}[/dim] "
                    f"[link={ref}][underline dim]{escape(ref)}[/underline dim][/link]"
                )

        self._console.print()

    # ------------------------------------------------------------------ #
    # Settings security section                                            #
    # ------------------------------------------------------------------ #

    def _settings_section(self, section: ReportSection, threshold: Severity) -> None:
        threshold_idx = SEVERITY_ORDER.index(threshold)
        filtered = [
            f for f in section.findings
            if SEVERITY_ORDER.index(f.severity) <= threshold_idx
        ]
        if not filtered:
            return

        self._console.print(Rule(
            f"[bold]{escape(section.title)}[/bold]  "
            f"[dim]{len(filtered)} findings[/dim]",
            style="dim"
        ))
        self._console.print()

        sorted_findings = sorted(filtered, key=lambda f: SEVERITY_ORDER.index(f.severity))
        for f in sorted_findings:
            self._finding_row(f)

    # ------------------------------------------------------------------ #
    # Settings inventory table                                             #
    # ------------------------------------------------------------------ #

    def _inventory_section(self, section: ReportSection, threshold: Severity) -> None:
        threshold_idx = SEVERITY_ORDER.index(threshold)
        filtered = [
            f for f in section.findings
            if SEVERITY_ORDER.index(f.severity) <= threshold_idx
        ]
        if not filtered:
            return

        self._console.print(Rule(
            f"[bold]Settings Inventory[/bold]  "
            f"[dim]{len(filtered)} settings[/dim]",
            style="dim"
        ))
        self._console.print()

        table = Table(box=box.SIMPLE_HEAD, expand=True, show_lines=False, padding=(0, 1))
        table.add_column("Setting Key", style="cyan", no_wrap=True, min_width=30)
        table.add_column("Value", overflow="fold")

        for f in sorted(filtered, key=lambda x: x.source.lower()):
            detail = f.detail
            val = detail.split(" = ", 1)[1] if " = " in detail else detail
            table.add_row(escape(f.source), escape(val))

        self._console.print(table)
        self._console.print()

    # ------------------------------------------------------------------ #
    # Action summary                                                       #
    # ------------------------------------------------------------------ #

    def _action_summary(self, report: Report, threshold: Severity = Severity.INFO) -> None:
        all_findings = report.all_findings

        # Strip metadata-only VERSION/INFO findings (no recommendation = header-only)
        actionable = [
            f for f in all_findings
            if not (f.category == FindingCategory.VERSION
                    and f.severity == Severity.INFO
                    and not f.recommendation)
        ]

        if not actionable:
            return

        self._console.print(Rule("[bold]Recommended Actions[/bold]", style="dim"))
        self._console.print()

        # ── CVEs ──────────────────────────────────────────────────────────
        cves = [f for f in actionable if f.category == FindingCategory.CVE]
        if cves:
            self._console.print(f"  [bold red]Vulnerabilities ({len(cves)} CVE findings)[/bold red]")
            for f in sorted(cves, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                tag = _SEV_TAG[f.severity]
                self._console.print(f"    {tag}  {escape(f.title)}")
                # Show each vuln ID line with its detail
                for line in f.detail.splitlines():
                    if line.strip():
                        self._console.print(f"                 [dim]{escape(line.strip())}[/dim]")
                # Reference URLs
                for ref in f.references[:3]:
                    self._console.print(
                        f"                 [link={ref}][underline dim]{escape(ref)}[/underline dim][/link]"
                    )
                if f.recommendation:
                    self._console.print(f"              [dim]Fix:[/dim] [italic]{escape(f.recommendation)}[/italic]")
            self._console.print()

        # ── Deprecated extensions ─────────────────────────────────────────
        deprecated = [
            f for f in actionable
            if f.category == FindingCategory.VERSION and f.severity == Severity.HIGH
        ]
        if deprecated:
            self._console.print(f"  [bold red]Deprecated extensions ({len(deprecated)}) — find replacements[/bold red]")
            for f in deprecated:
                self._console.print(f"    [bold red]✗[/bold red]  {escape(f.source)}")
                if f.references:
                    self._console.print(
                        f"       [link={f.references[0]}][dim underline]{escape(f.references[0])}[/dim underline][/link]"
                    )
            self._console.print()

        # ── High-risk API permissions ─────────────────────────────────────
        api_findings = [f for f in actionable if f.category == FindingCategory.API_PERMISSIONS]
        if api_findings:
            self._console.print(
                f"  [bold red]High-risk experimental APIs ({len(api_findings)} extensions)[/bold red]"
            )
            self._console.print(
                "  [dim]These extensions use experimental VS Code APIs granting elevated access.[/dim]"
            )
            for f in api_findings:
                apis = [line.split(":")[0].strip() for line in f.detail.splitlines() if line.strip()]
                self._console.print(f"    [bold]{escape(f.source)}[/bold]  —  {escape(', '.join(apis))}")
            self._console.print()

        # ── Outdated extensions ───────────────────────────────────────────
        outdated = [
            f for f in actionable
            if f.category == FindingCategory.VERSION and f.severity == Severity.MEDIUM
        ]
        if outdated:
            self._console.print(f"  [bold yellow]Outdated extensions ({len(outdated)}) — update to get security patches[/bold yellow]")
            self._console.print("  [dim]Run in terminal or update via Extensions panel (Ctrl+Shift+X):[/dim]")
            self._console.print()
            for f in sorted(outdated, key=lambda x: x.source):
                meta = f.metadata
                installed = meta.get("installed_version", "?")
                latest = meta.get("latest_version", "?")
                self._console.print(
                    f"    [cyan]{escape(f.source)}[/cyan]  "
                    f"[dim]v{installed} -> v{latest}[/dim]"
                )
                self._console.print(
                    f"    [dim]code --install-extension {escape(f.source)} --force[/dim]"
                )
            self._console.print()

        # ── Stale extensions ──────────────────────────────────────────────
        stale = [
            f for f in actionable
            if f.category == FindingCategory.VERSION and f.severity == Severity.LOW
        ]
        if stale:
            self._console.print(
                f"  [bold]Stale extensions ({len(stale)}) — not updated in {_days_label(self._stale_days)}[/bold]"
            )
            self._console.print(
                "  [dim]Consider replacing these if they are unmaintained:[/dim]"
            )
            for f in sorted(stale, key=lambda x: x.metadata.get("last_updated", "") or ""):
                meta = f.metadata
                last_up = meta.get("last_updated", "unknown")
                self._console.print(
                    f"    [dim]{escape(f.source)}[/dim]  "
                    f"[dim]last updated {escape(last_up)}[/dim]"
                )
            self._console.print()

        # ── Settings findings (all severities, skip inventory INFO entries) ─
        settings_findings = [
            f for f in actionable
            if f.category in (FindingCategory.SETTINGS, FindingCategory.TRUST,
                              FindingCategory.REMOTE_HOST, FindingCategory.AI_CONFIG,
                              FindingCategory.SECRET, FindingCategory.MCP)
            and not (f.category == FindingCategory.SETTINGS and f.severity == Severity.INFO)
        ]
        if settings_findings:
            self._console.print(f"  [bold]Settings findings ({len(settings_findings)})[/bold]")
            for f in sorted(settings_findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                tag = _SEV_TAG[f.severity]
                self._console.print(f"    {tag}  {escape(f.title)}")
                if f.detail:
                    indent = "              "
                    cont = "                       "
                    lines = escape(f.detail).split("\n")
                    self._console.print(f"{indent}[dim]Detail :[/dim] {lines[0]}")
                    for line in lines[1:]:
                        self._console.print(f"{cont}[dim]{line}[/dim]")
                if f.recommendation:
                    self._console.print(f"              [dim]Fix    :[/dim] [italic]{escape(f.recommendation)}[/italic]")
            self._console.print()

        # ── Low-severity summary line (only when threshold hides them) ────────
        # When running at INFO threshold everything is already shown - don't
        # tell the user to re-run at a lower level they're already at.
        if threshold != Severity.INFO:
            low_info = [
                f for f in actionable
                if f.severity in (Severity.LOW, Severity.INFO)
                and not (f.category == FindingCategory.VERSION and f.severity == Severity.LOW)
            ]
            if low_info:
                cats = defaultdict(int)
                for f in low_info:
                    cats[f.category.value] += 1
                parts = [f"{count} {cat.lower().replace('_', ' ')}" for cat, count in sorted(cats.items())]
                self._console.print(
                    f"  [dim]{len(low_info)} lower-priority findings not shown: {', '.join(parts)}. "
                    f"Re-run with --threshold LOW to review.[/dim]"
                )
            self._console.print()


def _fmt_num(n) -> str:
    if n is None:
        return ""
    n = int(n)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}K"
    return str(n)
