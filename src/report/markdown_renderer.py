from collections import defaultdict

from ..models.findings import FindingCategory, SEVERITY_ORDER, Severity
from ..models.report import Report, ReportSection

_GROUP_BY_SOURCE_TITLES = {"Extension Security Audit"}

_SEVERITY_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
    "INFO":     "⚪ INFO",
}


def _badge(sev) -> str:
    return _SEVERITY_BADGE.get(sev.value, sev.value)


def _vuln_url(vid: str) -> str:
    if vid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vid}"
    return f"https://osv.dev/vulnerability/{vid}"


def _days_label(days: int) -> str:
    if days >= 365:
        years = days // 365
        return f"{years}+ year{'s' if years != 1 else ''}"
    months = days // 30
    return f"{months}+ month{'s' if months != 1 else ''}"


class MarkdownRenderer:

    def __init__(self, stale_days: int = 365):
        self._stale_days = stale_days

    def render(self, report: Report, output_path: str) -> None:
        lines = self._build_lines(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def _build_lines(self, report: Report) -> list:
        lines = [
            "# VS Code Security Report",
            "",
            "| | |",
            "|---|---|",
            f"| **Generated** | {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **Platform** | {report.platform} |",
            f"| **Scan type** | {report.scan_type} |",
            f"| **Extensions scanned** | {report.total_extensions_scanned} |",
            f"| **Extensions path** | `{report.vscode_extensions_path}` |",
            f"| **Settings path** | `{report.vscode_settings_path}` |",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|:---------|------:|",
        ]
        by_sev = report.findings_by_severity
        for sev in SEVERITY_ORDER:
            count = len(by_sev[sev])
            lines.append(f"| {_badge(sev)} | {count} |")
        lines += [
            f"| **TOTAL** | **{len(report.all_findings)}** |",
            "",
            "---",
            "",
            "## Contents",
            "",
        ]
        for section in report.sections:
            anchor = section.title.lower().replace(" ", "-")
            count = len(section.findings)
            lines.append(f"- [{section.title}](#{anchor}) ({count} findings)")
        lines.append("- [Recommended Actions](#recommended-actions)")
        lines += ["", "---", ""]

        for section in report.sections:
            if section.title in _GROUP_BY_SOURCE_TITLES:
                lines += self._render_extension_section(section)
            else:
                lines += self._render_settings_section(section)

        lines += self._render_action_summary(report)
        return lines

    # ------------------------------------------------------------------
    # Extension section - grouped by extension (source)
    # ------------------------------------------------------------------

    def _render_extension_section(self, section: ReportSection) -> list:
        lines = [f"## {section.title}", ""]
        if not section.findings:
            lines += ["_No findings._", "", "---", ""]
            return lines

        # Separate metadata findings from real findings
        meta_by_source: dict = {}
        real_by_source: dict = defaultdict(list)
        for f in section.findings:
            if (f.category == FindingCategory.VERSION
                    and f.severity == Severity.INFO
                    and not f.recommendation):
                meta_by_source[f.source] = f.metadata
            else:
                real_by_source[f.source].append(f)

        sources = [s for s in real_by_source if real_by_source[s]]

        def worst_idx(src):
            return min(SEVERITY_ORDER.index(f.severity) for f in real_by_source[src])

        sources = sorted(sources, key=worst_idx)
        if not sources:
            lines += ["_No actionable findings._", "", "---", ""]
            return lines

        total_real = sum(len(real_by_source[s]) for s in sources)
        worst_sev = SEVERITY_ORDER[worst_idx(sources[0])]
        lines.append(
            f"> {total_real} findings across {len(sources)} extensions. "
            f"Worst severity: **{worst_sev.value}**"
        )
        lines.append("")

        for source in sources:
            findings = sorted(real_by_source[source], key=lambda f: SEVERITY_ORDER.index(f.severity))
            worst = findings[0].severity
            meta = meta_by_source.get(source, {})

            lines.append(f"### {_badge(worst)} `{source}`")
            lines.append("")
            lines += self._ext_meta_table(source, meta)
            lines.append(f"_{len(findings)} finding{'s' if len(findings) != 1 else ''}_")
            lines.append("")

            for f in findings:
                lines += self._render_finding(f, level=4)

        lines += ["---", ""]
        return lines

    def _ext_meta_table(self, source: str, meta: dict) -> list:
        if not meta:
            return []
        lines = ["| | |", "|---|---|"]

        pub = meta.get("publisher_display_name", "")
        if pub:
            lines.append(f"| **Publisher** | {pub} |")

        installed = meta.get("installed_version", "")
        latest = meta.get("latest_version", "")
        is_outdated = meta.get("is_outdated", False)
        if installed and latest:
            if is_outdated:
                lines.append(
                    f"| **Version** | v{installed} -> **v{latest}** ⚠️ OUTDATED |"
                )
            else:
                lines.append(f"| **Version** | v{installed} (current) |")
        elif installed:
            lines.append(f"| **Version** | v{installed} |")

        installs = meta.get("install_count_fmt", "")
        if installs and installs != "unknown":
            lines.append(f"| **Installs** | {installs} |")

        rating = meta.get("rating_str", "")
        if rating:
            lines.append(f"| **Rating** | ★ {rating} |")

        updated = meta.get("last_updated", "")
        if updated:
            lines.append(f"| **Last updated** | {updated} |")

        verified = meta.get("is_verified", None)
        if verified is not None:
            lines.append(f"| **Verified publisher** | {'Yes' if verified else 'No'} |")

        repo = meta.get("repository_url", "")
        if repo:
            lines.append(f"| **Repository** | [{repo}]({repo}) |")

        lines.append(f"| **Marketplace** | [View listing](https://marketplace.visualstudio.com/items?itemName={source}) |")
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Settings section
    # ------------------------------------------------------------------

    def _render_settings_section(self, section: ReportSection) -> list:
        lines = [f"## {section.title}", ""]
        if not section.findings:
            lines += ["_No findings._", "", "---", ""]
            return lines

        if section.title == "Settings Inventory":
            return self._render_inventory_table(section)

        sorted_findings = sorted(
            section.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
        )
        lines.append(f"> {len(sorted_findings)} findings")
        lines.append("")
        for f in sorted_findings:
            lines += self._render_finding(f, level=3)

        lines += ["---", ""]
        return lines

    def _render_inventory_table(self, section: ReportSection) -> list:
        lines = [f"## {section.title}", ""]
        lines.append(
            f"> Complete inventory of {len(section.findings)} VS Code user settings."
        )
        lines.append("")
        lines.append("| Setting Key | Value |")
        lines.append("|:------------|:------|")
        for f in sorted(section.findings, key=lambda x: x.source.lower()):
            detail = f.detail
            val = detail.split(" = ", 1)[1] if " = " in detail else detail
            # Escape markdown table special characters
            val = val.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
            key = f.source.replace("|", "\\|")
            lines.append(f"| `{key}` | `{val}` |")
        lines += ["", "---", ""]
        return lines

    # ------------------------------------------------------------------
    # Recommended actions summary
    # ------------------------------------------------------------------

    def _render_action_summary(self, report: Report) -> list:
        all_findings = report.all_findings
        actionable = [
            f for f in all_findings
            if not (f.category == FindingCategory.VERSION
                    and f.severity == Severity.INFO
                    and not f.recommendation)
        ]
        if not actionable:
            return []

        lines = ["## Recommended Actions", ""]

        # CVEs
        cves = [f for f in actionable if f.category == FindingCategory.CVE]
        if cves:
            lines += [f"### Vulnerabilities ({len(cves)} findings)", ""]
            for f in sorted(cves, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                lines.append(f"- {_badge(f.severity)} **{f.title}**")
                # Each vuln ID with its summary and fix version
                for line in f.detail.splitlines():
                    if line.strip():
                        lines.append(f"  - `{line.strip()}`")
                # Reference links
                for ref in f.references:
                    label = ref.rstrip("/").split("/")[-1]
                    lines.append(f"  - [{label}]({ref})")
                if f.recommendation:
                    lines.append(f"  - **Fix:** {f.recommendation}")
            lines.append("")

        # Deprecated
        deprecated = [
            f for f in actionable
            if f.category == FindingCategory.VERSION and f.severity == Severity.HIGH
        ]
        if deprecated:
            lines += [f"### Deprecated extensions ({len(deprecated)}) - find replacements", ""]
            for f in deprecated:
                mp = f"https://marketplace.visualstudio.com/items?itemName={f.source}"
                lines.append(f"- **`{f.source}`** - {f.description} [Marketplace]({mp})")
            lines.append("")

        # High-risk APIs
        api_findings = [f for f in actionable if f.category == FindingCategory.API_PERMISSIONS]
        if api_findings:
            lines += [
                f"### High-risk experimental APIs ({len(api_findings)} extensions)",
                "",
                "These extensions use experimental VS Code APIs that grant elevated access "
                "to AI sessions, terminal I/O, or agent capabilities.",
                "",
                "| Extension | APIs |",
                "|:----------|:-----|",
            ]
            for f in api_findings:
                apis = ", ".join(
                    line.split(":")[0].strip()
                    for line in f.detail.splitlines() if line.strip()
                )
                lines.append(f"| `{f.source}` | {apis} |")
            lines.append("")

        # Outdated
        outdated = [
            f for f in actionable
            if f.category == FindingCategory.VERSION and f.severity == Severity.MEDIUM
        ]
        if outdated:
            lines += [
                f"### Outdated extensions ({len(outdated)}) - update to get security patches",
                "",
                "Run these commands in your terminal, or use the Extensions panel (`Ctrl+Shift+X`):",
                "",
                "```bash",
            ]
            for f in sorted(outdated, key=lambda x: x.source):
                meta = f.metadata
                installed = meta.get("installed_version", "?")
                latest = meta.get("latest_version", "?")
                lines.append(f"# {f.source}  v{installed} -> v{latest}")
                lines.append(f"code --install-extension {f.source} --force")
            lines += ["```", ""]

        # Stale
        stale = [
            f for f in actionable
            if f.category == FindingCategory.VERSION and f.severity == Severity.LOW
        ]
        if stale:
            lines += [
                f"### Stale extensions ({len(stale)}) - not updated in {_days_label(self._stale_days)}",
                "",
                "Consider finding alternatives for unmaintained extensions:",
                "",
            ]
            for f in sorted(stale, key=lambda x: x.metadata.get("last_updated", "") or ""):
                meta = f.metadata
                last_up = meta.get("last_updated", "unknown")
                lines.append(f"- `{f.source}` — last updated {last_up}")
            lines.append("")

        # Settings
        settings_to_fix = [
            f for f in actionable
            if f.category in (FindingCategory.SETTINGS, FindingCategory.TRUST,
                              FindingCategory.REMOTE_HOST, FindingCategory.AI_CONFIG)
            and f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]
        if settings_to_fix:
            lines += [f"### Settings to review ({len(settings_to_fix)} findings)", ""]
            for f in sorted(settings_to_fix, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                lines.append(f"- {_badge(f.severity)} **{f.title}**")
                if f.recommendation:
                    lines.append(f"  - {f.recommendation}")
            lines.append("")

        # MCP
        mcp_high = [
            f for f in actionable
            if f.category == FindingCategory.MCP
            and f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]
        if mcp_high:
            lines += [f"### MCP / extension concerns ({len(mcp_high)})", ""]
            for f in mcp_high:
                lines.append(f"- {_badge(f.severity)} **{f.title}**")
                if f.recommendation:
                    lines.append(f"  - {f.recommendation}")
            lines.append("")

        lines += ["---", ""]
        return lines

    # ------------------------------------------------------------------
    # Single finding block
    # ------------------------------------------------------------------

    def _render_finding(self, f, level: int = 3) -> list:
        hdr = "#" * level
        lines = [f"{hdr} {_badge(f.severity)} {f.title}", ""]

        rows = [f"| **Category** | {f.category.value} |"]
        rows.append(f"| **Source** | `{f.source}` |")

        if f.detail:
            # Multi-line details (OSV summaries) - render as separate lines in the cell
            detail_cell = f.detail.replace("\n", "<br>").replace("|", "\\|")
            rows.append(f"| **Detail** | {detail_cell} |")

        if f.description and f.description != f.title:
            rows.append(f"| **Description** | {f.description} |")

        if f.recommendation:
            rows.append(f"| **Recommendation** | {f.recommendation} |")

        lines.append("| | |")
        lines.append("|---|---|")
        lines += rows
        lines.append("")

        if f.cve_ids:
            links = ", ".join(
                f"[{c}]({_vuln_url(c)})" for c in f.cve_ids
            )
            lines.append(f"**CVE IDs:** {links}")
            lines.append("")

        if f.references:
            lines.append("**References:**")
            lines.append("")
            for ref in f.references:
                label = ref.rstrip("/").split("/")[-1]
                lines.append(f"- [{label}]({ref})")
            lines.append("")

        return lines
