from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
}


def _vuln_url(vid: str) -> str:
    if vid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vid}"
    return f"https://osv.dev/vulnerability/{vid}"


class CVECheck(BaseCheck):
    check_id = "EXT-CVE-001"

    def __init__(self, apis: list):
        self._apis = apis

    def run(self, target) -> list:
        findings = []
        manifest = target.manifest
        seen_ids: set = set()

        for api in self._apis:
            try:
                result = api.query_extension(
                    extension_id=target.extension_id,
                    package_name=manifest.name,
                    version=manifest.version,
                    repo_url=manifest.repository_url,
                )
            except Exception:
                continue

            if not result.has_vulns:
                continue

            new_ids = [i for i in result.vuln_ids if i and i not in seen_ids]
            if not new_ids:
                continue
            seen_ids.update(new_ids)

            sev = _SEVERITY_MAP.get(result.severity, Severity.MEDIUM)

            # Build per-vuln detail lines from OSV summaries
            detail_lines = []
            cve_ids = []
            refs = []
            for item in result.details:
                vid = item.get("id", "")
                if not vid or vid not in new_ids:
                    continue
                summary = item.get("summary", "")
                fix = item.get("fix_version", "")
                cve_alias = item.get("cve_alias", "")
                severity_str = item.get("severity", "")

                line = f"{vid}"
                if severity_str:
                    line += f" [{severity_str}]"
                if summary:
                    line += f" - {summary}"
                if fix:
                    line += f" (fix: v{fix})"
                detail_lines.append(line)

                refs.append(_vuln_url(vid))
                if cve_alias:
                    cve_ids.append(cve_alias)
                    refs.append(_vuln_url(cve_alias))

            # If we didn't get summaries (e.g. GitHub Advisory), fall back to IDs only
            if not detail_lines:
                for vid in new_ids:
                    refs.append(_vuln_url(vid))
                    if vid.startswith("CVE-"):
                        cve_ids.append(vid)

            detail = "\n".join(detail_lines) if detail_lines else ", ".join(new_ids)

            # Description: first vuln summary or the api summary
            first_summary = next(
                (d.get("summary") for d in result.details if d.get("summary")), ""
            )
            description = first_summary or result.summary

            # Note if this is an OSV match (npm name collision risk)
            is_osv = result.source == "osv"
            if is_osv:
                rec = (
                    f"Verify this advisory applies to the VS Code extension and not "
                    f"an unrelated npm package with the same name ('{manifest.name}'). "
                    f"If confirmed, update or replace the extension."
                )
            else:
                rec = (
                    "Update to the latest version or replace the extension. "
                    "Check the references for affected version ranges."
                )

            findings.append(Finding(
                category=FindingCategory.CVE,
                severity=sev,
                title=f"Vulnerabilities in {manifest.display_name} v{manifest.version}",
                description=description,
                detail=detail,
                source=target.extension_id,
                recommendation=rec,
                references=list(dict.fromkeys(refs)),
                cve_ids=list(dict.fromkeys(cve_ids)),
            ))

        return findings
