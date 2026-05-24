import html
from collections import defaultdict

from ..models.findings import Finding, FindingCategory, Severity, SEVERITY_ORDER
from ..models.report import Report

_SEV_CLASS = {
    Severity.CRITICAL: "sev-critical",
    Severity.HIGH:     "sev-high",
    Severity.MEDIUM:   "sev-medium",
    Severity.LOW:      "sev-low",
    Severity.INFO:     "sev-info",
}

_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MEDIUM",
    Severity.LOW:      "LOW",
    Severity.INFO:     "INFO",
}

_CSS = """
:root {
  --bg: #0f1117;
  --surface: #1a1d27;
  --surface2: #22263a;
  --border: #2e3250;
  --text: #e2e8f0;
  --muted: #8892a4;
  --critical: #ff4d6d;
  --high: #ff7849;
  --medium: #fbbf24;
  --low: #60a5fa;
  --info: #94a3b8;
  --green: #34d399;
  --link: #7dd3fc;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  font-size: 15px;
}
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
code {
  font-family: 'Cascadia Code', 'Fira Code', monospace;
  background: var(--surface2);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 13px;
}
pre code { background: none; padding: 0; }

/* Layout */
.page { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }

/* Header */
.report-header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 24px;
  margin-bottom: 32px;
}
.report-header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
.report-meta {
  display: flex; flex-wrap: wrap; gap: 24px;
  color: var(--muted); font-size: 13px; margin-top: 12px;
}
.report-meta span strong { color: var(--text); }

/* Summary cards */
.summary-cards {
  display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 40px;
}
.sev-card {
  flex: 1; min-width: 100px;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 20px;
  text-align: center;
  background: var(--surface);
}
.sev-card .count { font-size: 36px; font-weight: 700; }
.sev-card .label { font-size: 12px; letter-spacing: .08em; color: var(--muted); margin-top: 2px; }
.sev-card.sev-critical .count { color: var(--critical); }
.sev-card.sev-high     .count { color: var(--high); }
.sev-card.sev-medium   .count { color: var(--medium); }
.sev-card.sev-low      .count { color: var(--low); }
.sev-card.sev-info     .count { color: var(--info); }

/* Section */
.section { margin-bottom: 48px; }
.section-title {
  font-size: 18px; font-weight: 600;
  border-bottom: 1px solid var(--border);
  padding-bottom: 10px; margin-bottom: 20px;
  display: flex; align-items: center; gap: 10px;
}
.section-count {
  font-size: 13px; font-weight: 400; color: var(--muted);
  background: var(--surface2); padding: 2px 10px;
  border-radius: 20px;
}

/* Extension card */
.ext-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 16px;
  overflow: hidden;
}
.ext-card-header {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
}
.ext-id { font-weight: 600; font-size: 15px; }
.ext-version { color: var(--muted); font-size: 13px; }
.ext-version .outdated { color: var(--medium); font-weight: 600; }
.ext-meta { color: var(--muted); font-size: 12px; display: flex; gap: 12px; flex-wrap: wrap; }
.badge-verified { color: var(--green); font-size: 12px; }
.badge-unverified { color: var(--medium); font-size: 12px; }
.ext-findings { padding: 4px 0; }

/* Finding row */
.finding {
  padding: 12px 18px;
  border-bottom: 1px solid var(--border);
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: 8px 14px;
}
.finding:last-child { border-bottom: none; }
.sev-badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .06em;
  text-align: center;
  align-self: start;
  margin-top: 2px;
}
.sev-critical .sev-badge { background: #ff4d6d22; color: var(--critical); border: 1px solid var(--critical); }
.sev-high     .sev-badge { background: #ff784922; color: var(--high);     border: 1px solid var(--high); }
.sev-medium   .sev-badge { background: #fbbf2422; color: var(--medium);   border: 1px solid var(--medium); }
.sev-low      .sev-badge { background: #60a5fa22; color: var(--low);      border: 1px solid var(--low); }
.sev-info     .sev-badge { background: #94a3b822; color: var(--info);     border: 1px solid var(--info); }

.finding-body { min-width: 0; }
.finding-title { font-weight: 600; margin-bottom: 4px; }
.finding-field { font-size: 13px; color: var(--muted); margin-top: 3px; }
.finding-field strong { color: var(--text); }
.finding-detail { font-size: 13px; white-space: pre-wrap; word-break: break-word; color: var(--text); margin-top: 4px; }
.finding-fix {
  font-size: 13px; margin-top: 6px;
  background: var(--surface2); border-left: 3px solid var(--medium);
  padding: 6px 10px; border-radius: 0 4px 4px 0;
  color: var(--text);
}
.finding-refs { margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }
.finding-refs a {
  font-size: 12px; background: var(--surface2);
  padding: 2px 8px; border-radius: 4px; color: var(--link);
}

/* Action summary */
.action-section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px 28px;
  margin-bottom: 24px;
}
.action-section h3 {
  font-size: 16px; font-weight: 600; margin-bottom: 16px;
  color: var(--text);
}
.action-section p.subtitle {
  font-size: 13px; color: var(--muted); margin-bottom: 12px; margin-top: -10px;
}

/* Outdated table */
.update-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.update-table th {
  text-align: left; color: var(--muted);
  font-weight: 500; padding: 6px 10px;
  border-bottom: 1px solid var(--border);
}
.update-table td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
.update-table tr:last-child td { border-bottom: none; }
.update-table code { font-size: 12px; }

/* Stale table */
.stale-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.stale-table th {
  text-align: left; color: var(--muted);
  font-weight: 500; padding: 6px 10px;
  border-bottom: 1px solid var(--border);
}
.stale-table td { padding: 7px 10px; border-bottom: 1px solid var(--border); }
.stale-table tr:last-child td { border-bottom: none; }

/* Settings table */
.settings-findings { display: flex; flex-direction: column; gap: 10px; }
.setting-item {
  background: var(--surface2);
  border-radius: 6px;
  padding: 12px 14px;
}
.setting-item .title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
.setting-item .detail { font-size: 13px; white-space: pre-wrap; color: var(--muted); }
.setting-item .fix {
  font-size: 13px; margin-top: 6px;
  border-left: 3px solid var(--medium);
  padding-left: 8px;
}

/* Inventory table */
.inv-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.inv-table th {
  text-align: left; color: var(--muted); font-weight: 500;
  padding: 6px 10px; border-bottom: 1px solid var(--border);
}
.inv-table td {
  padding: 6px 10px; border-bottom: 1px solid var(--border);
  vertical-align: top; word-break: break-all;
}
.inv-table tr:last-child td { border-bottom: none; }
.inv-table td:first-child { white-space: nowrap; color: var(--link); }

/* TOC */
.toc {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 20px 24px; margin-bottom: 40px;
}
.toc h2 { font-size: 15px; margin-bottom: 10px; color: var(--muted); }
.toc ul { list-style: none; display: flex; flex-wrap: wrap; gap: 8px 24px; }
.toc a { font-size: 14px; }
"""


def _h(text: str) -> str:
    return html.escape(str(text))


def _days_label(days: int) -> str:
    if days >= 365:
        years = days // 365
        return f"{years}+ year{'s' if years != 1 else ''}"
    months = days // 30
    return f"{months}+ month{'s' if months != 1 else ''}"


class HtmlRenderer:

    def __init__(self, stale_days: int = 365):
        self._stale_days = stale_days

    def render(self, report: Report, output_path: str) -> None:
        body = self._build_body(report)
        page = self._wrap(report, body)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(page)

    # ------------------------------------------------------------------ #

    def _wrap(self, report: Report, body: str) -> str:
        title = f"VS Code Security Report - {report.generated_at.strftime('%Y-%m-%d')}"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_h(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">
{body}
</div>
</body>
</html>"""

    def _build_body(self, report: Report) -> str:
        parts = [
            self._header(report),
            self._toc(report),
            self._summary_cards(report),
        ]
        for section in report.sections:
            if section.title == "Extension Security Audit":
                parts.append(self._extension_section(section))
            elif section.title == "Settings Inventory":
                parts.append(self._inventory_section(section))
            else:
                parts.append(self._settings_section(section))
        parts.append(self._action_summary(report))
        return "\n".join(parts)

    # ------------------------------------------------------------------ #
    # Header                                                               #
    # ------------------------------------------------------------------ #

    def _header(self, report: Report) -> str:
        return f"""
<div class="report-header">
  <h1>VS Code Security Report</h1>
  <div class="report-meta">
    <span><strong>Generated:</strong> {_h(report.generated_at.strftime('%Y-%m-%d %H:%M:%S'))}</span>
    <span><strong>Platform:</strong> {_h(report.platform)}</span>
    <span><strong>Scan:</strong> {_h(report.scan_type)}</span>
    <span><strong>Extensions:</strong> {report.total_extensions_scanned}</span>
    <span><strong>Settings:</strong> <code>{_h(report.vscode_settings_path)}</code></span>
  </div>
</div>"""

    def _toc(self, report: Report) -> str:
        links = []
        for section in report.sections:
            anchor = section.title.lower().replace(" ", "-")
            links.append(f'<li><a href="#{_h(anchor)}">{_h(section.title)}</a></li>')
        links.append('<li><a href="#recommended-actions">Recommended Actions</a></li>')
        return f"""
<nav class="toc">
  <h2>Contents</h2>
  <ul>{"".join(links)}</ul>
</nav>"""

    # ------------------------------------------------------------------ #
    # Summary cards                                                        #
    # ------------------------------------------------------------------ #

    def _summary_cards(self, report: Report) -> str:
        by_sev = report.findings_by_severity
        cards = []
        for sev in SEVERITY_ORDER:
            count = len(by_sev[sev])
            cls = _SEV_CLASS[sev]
            label = _SEV_LABEL[sev]
            cards.append(f"""
    <div class="sev-card {cls}">
      <div class="count">{count}</div>
      <div class="label">{label}</div>
    </div>""")
        return f'<div class="summary-cards">{"".join(cards)}\n</div>'

    # ------------------------------------------------------------------ #
    # Extension section                                                    #
    # ------------------------------------------------------------------ #

    def _extension_section(self, section) -> str:
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
        if not sources:
            return ""

        def worst_idx(src):
            return min(SEVERITY_ORDER.index(f.severity) for f in real_by_source[src])

        cards = []
        for source in sorted(sources, key=worst_idx):
            findings = sorted(real_by_source[source],
                              key=lambda f: SEVERITY_ORDER.index(f.severity))
            meta = meta_by_source.get(source, {})
            cards.append(self._ext_card(source, findings, meta))

        anchor = "extension-security-audit"
        total = sum(len(real_by_source[s]) for s in sources)
        return f"""
<div class="section" id="{anchor}">
  <div class="section-title">
    Extension Security Audit
    <span class="section-count">{total} findings across {len(sources)} extensions</span>
  </div>
  {"".join(cards)}
</div>"""

    def _ext_card(self, source: str, findings: list, meta: dict) -> str:
        worst = findings[0].severity
        cls = _SEV_CLASS[worst]

        installed = meta.get("installed_version", "")
        latest = meta.get("latest_version", "")
        is_outdated = meta.get("is_outdated", False)
        pub = meta.get("publisher_display_name", "")
        installs = meta.get("install_count_fmt", "")
        rating = meta.get("avg_rating")
        updated = meta.get("last_updated", "")
        is_verified = meta.get("is_verified")
        repo = meta.get("repository_url", "")

        ver_html = ""
        if installed and latest:
            if is_outdated:
                ver_html = f'<span class="ext-version"><span class="outdated">v{_h(installed)} → v{_h(latest)}</span></span>'
            else:
                ver_html = f'<span class="ext-version">v{_h(installed)}</span>'
        elif installed:
            ver_html = f'<span class="ext-version">v{_h(installed)}</span>'

        meta_parts = []
        if pub:
            meta_parts.append(_h(pub))
        if is_verified is True:
            meta_parts.append('<span class="badge-verified">✓ Verified Publisher</span>')
        elif is_verified is False:
            meta_parts.append('<span class="badge-unverified">⚠ Unverified Publisher</span>')
        if installs and installs != "unknown":
            meta_parts.append(f"{_h(installs)} installs")
        if rating is not None:
            meta_parts.append(f"★ {rating:.1f}")
        if updated:
            meta_parts.append(f"Updated {_h(updated)}")
        if repo:
            meta_parts.append(f'<a href="{_h(repo)}" target="_blank">repo ↗</a>')

        meta_html = f'<div class="ext-meta">{"  |  ".join(meta_parts)}</div>' if meta_parts else ""

        finding_rows = "".join(self._finding_row(f) for f in findings)

        return f"""
<div class="ext-card">
  <div class="ext-card-header">
    <span class="ext-id {cls}">{_h(source)}</span>
    {ver_html}
    {meta_html}
  </div>
  <div class="ext-findings">
    {finding_rows}
  </div>
</div>"""

    def _finding_row(self, f: Finding) -> str:
        cls = _SEV_CLASS[f.severity]
        label = _SEV_LABEL[f.severity]

        detail_html = ""
        if f.detail:
            detail_html = f'<div class="finding-detail">{_h(f.detail)}</div>'

        desc_html = ""
        if f.description and f.description != f.title:
            desc_html = f'<div class="finding-field"><strong>Info:</strong> {_h(f.description)}</div>'

        fix_html = ""
        if f.recommendation:
            fix_html = f'<div class="finding-fix">{_h(f.recommendation)}</div>'

        refs_html = ""
        if f.references:
            links = " ".join(
                f'<a href="{_h(r)}" target="_blank">{_h(r.rstrip("/").split("/")[-1])}</a>'
                for r in f.references[:3]
            )
            refs_html = f'<div class="finding-refs">{links}</div>'

        return f"""
<div class="finding {cls}">
  <span class="sev-badge">{label}</span>
  <div class="finding-body">
    <div class="finding-title">{_h(f.title)}</div>
    {detail_html}{desc_html}{fix_html}{refs_html}
  </div>
</div>"""

    # ------------------------------------------------------------------ #
    # Settings section                                                     #
    # ------------------------------------------------------------------ #

    def _settings_section(self, section) -> str:
        findings = sorted(section.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
        if not findings:
            return ""
        anchor = section.title.lower().replace(" ", "-")
        rows = "".join(self._finding_row(f) for f in findings)
        return f"""
<div class="section" id="{anchor}">
  <div class="section-title">
    {_h(section.title)}
    <span class="section-count">{len(findings)} findings</span>
  </div>
  {rows}
</div>"""

    # ------------------------------------------------------------------ #
    # Settings inventory                                                   #
    # ------------------------------------------------------------------ #

    def _inventory_section(self, section) -> str:
        if not section.findings:
            return ""
        rows = []
        for f in sorted(section.findings, key=lambda x: x.source.lower()):
            detail = f.detail
            val = detail.split(" = ", 1)[1] if " = " in detail else detail
            rows.append(
                f'<tr><td><code>{_h(f.source)}</code></td>'
                f'<td><code>{_h(val)}</code></td></tr>'
            )
        return f"""
<div class="section" id="settings-inventory">
  <div class="section-title">
    Settings Inventory
    <span class="section-count">{len(section.findings)} settings</span>
  </div>
  <table class="inv-table">
    <thead><tr><th>Key</th><th>Value</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>"""

    # ------------------------------------------------------------------ #
    # Action summary                                                       #
    # ------------------------------------------------------------------ #

    def _action_summary(self, report: Report) -> str:
        all_findings = report.all_findings
        actionable = [
            f for f in all_findings
            if not (f.category == FindingCategory.VERSION
                    and f.severity == Severity.INFO
                    and not f.recommendation)
        ]

        parts = ['<div class="section" id="recommended-actions">',
                 '<div class="section-title">Recommended Actions</div>']

        # CVEs
        cves = [f for f in actionable if f.category == FindingCategory.CVE]
        if cves:
            rows = []
            for f in sorted(cves, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                cls = _SEV_CLASS[f.severity]
                label = _SEV_LABEL[f.severity]
                refs = " ".join(
                    f'<a href="{_h(r)}" target="_blank">{_h(r.rstrip("/").split("/")[-1])}</a>'
                    for r in f.references[:3]
                )
                detail_lines = "<br>".join(_h(l) for l in f.detail.splitlines() if l.strip()) if f.detail else ""
                rows.append(f"""
<tr>
  <td><span class="sev-badge {cls}">{label}</span></td>
  <td><strong>{_h(f.title)}</strong>
    {"<br><small>" + detail_lines + "</small>" if detail_lines else ""}
    {"<br><small>" + _h(f.recommendation) + "</small>" if f.recommendation else ""}
  </td>
  <td class="finding-refs">{refs}</td>
</tr>""")
            parts.append(f"""
<div class="action-section">
  <h3>Vulnerabilities ({len(cves)} CVE findings)</h3>
  <table class="update-table">
    <thead><tr><th>Severity</th><th>Finding</th><th>References</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>""")

        # Deprecated
        deprecated = [f for f in actionable
                      if f.category == FindingCategory.VERSION and f.severity == Severity.HIGH]
        if deprecated:
            rows = [f'<tr><td><code>{_h(f.source)}</code></td>'
                    f'<td><a href="{_h(f.references[0])}" target="_blank">Marketplace ↗</a></td></tr>'
                    for f in deprecated]
            parts.append(f"""
<div class="action-section">
  <h3>Deprecated extensions ({len(deprecated)}) - find replacements</h3>
  <table class="update-table">
    <thead><tr><th>Extension</th><th>Link</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>""")

        # High-risk APIs
        api_findings = [f for f in actionable if f.category == FindingCategory.API_PERMISSIONS]
        if api_findings:
            rows = []
            for f in api_findings:
                apis = ", ".join(l.split(":")[0].strip() for l in f.detail.splitlines() if l.strip())
                rows.append(f'<tr><td><code>{_h(f.source)}</code></td><td>{_h(apis)}</td></tr>')
            parts.append(f"""
<div class="action-section">
  <h3>High-risk experimental APIs ({len(api_findings)} extensions)</h3>
  <p class="subtitle">These extensions use experimental VS Code APIs granting elevated access.</p>
  <table class="update-table">
    <thead><tr><th>Extension</th><th>APIs used</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>""")

        # Outdated
        outdated = [f for f in actionable
                    if f.category == FindingCategory.VERSION and f.severity == Severity.MEDIUM]
        if outdated:
            rows = []
            for f in sorted(outdated, key=lambda x: x.source):
                meta = f.metadata
                inst = meta.get("installed_version", "?")
                lat = meta.get("latest_version", "?")
                rows.append(
                    f'<tr>'
                    f'<td><code>{_h(f.source)}</code></td>'
                    f'<td>v{_h(inst)}</td>'
                    f'<td>v{_h(lat)}</td>'
                    f'<td><code>code --install-extension {_h(f.source)} --force</code></td>'
                    f'</tr>'
                )
            parts.append(f"""
<div class="action-section">
  <h3>Outdated extensions ({len(outdated)}) - update to get security patches</h3>
  <p class="subtitle">Run each command in your terminal, or use the Extensions panel (Ctrl+Shift+X).</p>
  <table class="update-table">
    <thead><tr><th>Extension</th><th>Installed</th><th>Latest</th><th>Update command</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>""")

        # Stale
        stale = [f for f in actionable
                 if f.category == FindingCategory.VERSION and f.severity == Severity.LOW]
        if stale:
            rows = []
            for f in sorted(stale, key=lambda x: x.metadata.get("last_updated", "") or ""):
                meta = f.metadata
                last_up = meta.get("last_updated", "unknown")
                rows.append(
                    f'<tr>'
                    f'<td><code>{_h(f.source)}</code></td>'
                    f'<td>{_h(last_up)}</td>'
                    f'<td><a href="{_h(f.references[0])}" target="_blank">Marketplace ↗</a></td>'
                    f'</tr>'
                )
            parts.append(f"""
<div class="action-section">
  <h3>Stale extensions ({len(stale)}) - not updated in {_days_label(self._stale_days)}</h3>
  <p class="subtitle">Consider finding alternatives for unmaintained extensions.</p>
  <table class="stale-table">
    <thead><tr><th>Extension</th><th>Last updated</th><th>Link</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>""")

        # Settings
        settings_findings = [
            f for f in actionable
            if f.category in (FindingCategory.SETTINGS, FindingCategory.TRUST,
                              FindingCategory.REMOTE_HOST, FindingCategory.AI_CONFIG,
                              FindingCategory.SECRET, FindingCategory.MCP)
            and not (f.category == FindingCategory.SETTINGS and f.severity == Severity.INFO)
        ]
        if settings_findings:
            items = []
            for f in sorted(settings_findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                cls = _SEV_CLASS[f.severity]
                label = _SEV_LABEL[f.severity]
                detail_html = f'<div class="detail">{_h(f.detail)}</div>' if f.detail else ""
                fix_html = f'<div class="fix">{_h(f.recommendation)}</div>' if f.recommendation else ""
                items.append(f"""
<div class="setting-item">
  <div class="title"><span class="sev-badge {cls}">{label}</span> {_h(f.title)}</div>
  {detail_html}{fix_html}
</div>""")
            parts.append(f"""
<div class="action-section">
  <h3>Settings findings ({len(settings_findings)})</h3>
  <div class="settings-findings">{"".join(items)}</div>
</div>""")

        parts.append("</div>")
        return "\n".join(parts)
