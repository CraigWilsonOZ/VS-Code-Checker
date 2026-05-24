import json

from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity


def _format_value(val) -> str:
    if isinstance(val, bool):
        return str(val).lower()
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return repr(val)
    if isinstance(val, (list, dict)):
        return json.dumps(val, ensure_ascii=False, indent=None)
    return repr(val)


class SettingsInventoryCheck(BaseCheck):
    """Produces one INFO finding per settings key as a full audit inventory."""

    check_id = "SETTINGS-INVENTORY-001"

    def run(self, target: dict) -> list:
        findings = []
        settings = target.get("settings", {})

        for key, value in sorted(settings.items()):
            findings.append(Finding(
                category=FindingCategory.SETTINGS,
                severity=Severity.INFO,
                title=f"Setting: {key}",
                description="VS Code user setting documented for audit purposes.",
                detail=f"{key} = {_format_value(value)}",
                source=key,
                recommendation="",
            ))

        return findings
