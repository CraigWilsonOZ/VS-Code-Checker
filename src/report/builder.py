from datetime import datetime

from ..models.report import Report, ReportSection
from ..platform.base import VSCodePaths


class ReportBuilder:

    def build(
        self,
        sections: list,
        paths: VSCodePaths,
        platform_name: str,
        total_extensions: int,
        scan_type: str = "full",
    ) -> Report:
        return Report(
            generated_at=datetime.now(),
            scan_type=scan_type,
            platform=platform_name,
            vscode_extensions_path=paths.extensions_dir,
            vscode_settings_path=paths.user_settings,
            total_extensions_scanned=total_extensions,
            sections=sections,
        )
