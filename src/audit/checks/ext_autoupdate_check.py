from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity


class AutoUpdateCheck(BaseCheck):
    """
    Checks the extension's install source and pre-release status.
    Note: the global extensions.autoUpdate setting is checked separately
    in settings_trust_check.py and applies to all gallery extensions.
    """
    check_id = "EXT-UPDATE-001"

    def run(self, target) -> list:
        findings = []
        manifest = target.manifest

        if manifest.install_source not in ("gallery", ""):
            findings.append(Finding(
                category=FindingCategory.AUTO_UPDATE,
                severity=Severity.MEDIUM,
                title=f"Non-gallery install: {manifest.display_name}",
                description=(
                    "This extension was not installed from the VS Code Marketplace. "
                    "It will NOT receive automatic updates and cannot be verified "
                    "against marketplace security checks."
                ),
                detail=(
                    f"install_source='{manifest.install_source}' | "
                    f"v{manifest.version} | "
                    f"path: {target.directory}"
                ),
                source=target.extension_id,
                recommendation=(
                    "If installed via VSIX, verify the file came from the official publisher. "
                    "Consider reinstalling from the Marketplace to enable auto-updates."
                ),
            ))

        if manifest.is_pre_release:
            findings.append(Finding(
                category=FindingCategory.AUTO_UPDATE,
                severity=Severity.LOW,
                title=f"Pre-release version installed: {manifest.display_name}",
                description=(
                    "Pre-release extensions may contain unstable or unreviewed code "
                    "and may update more frequently."
                ),
                detail=f"v{manifest.version} (pre-release)",
                source=target.extension_id,
                recommendation=(
                    "Switch to the stable release channel unless you specifically "
                    "need pre-release features."
                ),
            ))

        return findings
