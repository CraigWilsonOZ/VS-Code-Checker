import json

from ..models.findings import Finding, SEVERITY_ORDER
from ..models.report import Report


class JSONRenderer:

    def render(self, report: Report, output_path: str) -> None:
        data = {
            "generated_at": report.generated_at.isoformat(),
            "scan_type": report.scan_type,
            "platform": report.platform,
            "vscode_extensions_path": report.vscode_extensions_path,
            "vscode_settings_path": report.vscode_settings_path,
            "summary": {
                "total_extensions_scanned": report.total_extensions_scanned,
                "total_findings": len(report.all_findings),
                "critical": report.critical_count,
                "by_severity": {
                    sev.value: len(findings)
                    for sev, findings in report.findings_by_severity.items()
                },
            },
            "sections": [
                {
                    "title": section.title,
                    "finding_count": len(section.findings),
                    "findings": [self._finding_to_dict(f) for f in section.findings],
                }
                for section in report.sections
            ],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict:
        return {
            "category": f.category.value,
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "detail": f.detail,
            "source": f.source,
            "recommendation": f.recommendation,
            "references": f.references,
            "cve_ids": f.cve_ids,
        }
