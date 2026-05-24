from dataclasses import dataclass, field
from datetime import datetime
from .findings import Finding, Severity, SEVERITY_ORDER


@dataclass
class ReportSection:
    title: str
    findings: list = field(default_factory=list)


@dataclass
class Report:
    generated_at: datetime
    scan_type: str
    platform: str
    vscode_extensions_path: str
    vscode_settings_path: str
    total_extensions_scanned: int
    sections: list = field(default_factory=list)

    @property
    def all_findings(self) -> list:
        return [f for s in self.sections for f in s.findings]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL)

    @property
    def findings_by_severity(self) -> dict:
        result = {s: [] for s in SEVERITY_ORDER}
        for f in self.all_findings:
            result[f.severity].append(f)
        return result
