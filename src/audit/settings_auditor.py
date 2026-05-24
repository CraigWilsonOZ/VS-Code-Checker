from ..models.report import ReportSection
from .checks.settings_ai_check import AIConfigCheck
from .checks.settings_inventory_check import SettingsInventoryCheck
from .checks.settings_remote_check import RemoteHostCheck
from .checks.settings_secrets_check import SecretsCheck
from .checks.settings_trust_check import TrustCheck


class SettingsAuditor:

    def __init__(self):
        self._security_checks = [
            SecretsCheck(),
            AIConfigCheck(),
            TrustCheck(),
            RemoteHostCheck(),
        ]
        self._inventory_check = SettingsInventoryCheck()

    def audit(self, scan_data: dict) -> list:
        """Returns two ReportSections: security findings + full settings inventory."""
        security_findings = []
        for check in self._security_checks:
            security_findings.extend(check.run(scan_data))

        inventory_findings = self._inventory_check.run(scan_data)

        return [
            ReportSection(
                title="Settings Security Audit",
                findings=security_findings,
            ),
            ReportSection(
                title="Settings Inventory",
                findings=inventory_findings,
            ),
        ]
