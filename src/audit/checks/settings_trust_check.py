from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity

TRUSTED_FOLDER_KEYS = [
    "security.workspace.trust.trustedUris",
    "snyk.trustedFolders",
    "security.workspace.trust.untrustedFiles",
]

AUTO_UPDATE_KEYS = [
    ("extensions.autoUpdate", Severity.MEDIUM,
     "Extensions update automatically without manual review. "
     "A malicious update can run code on your machine the moment it is pushed."),
    ("extensions.autoCheckUpdates", Severity.LOW,
     "VS Code checks for extension updates automatically."),
    ("update.mode", Severity.INFO,
     "VS Code application update mode is configured."),
]

GIT_KEYS = [
    ("git.autofetch", True, Severity.MEDIUM,
     "git.autofetch is enabled - VS Code silently fetches from all remotes on a timer. "
     "This can trigger credential prompts or expose activity to remote servers without user action."),
    ("git.enableSmartCommit", True, Severity.LOW,
     "git.enableSmartCommit is enabled - commits all changes without requiring staged files. "
     "This can bypass pre-commit hooks that run only on staged content."),
    ("git.confirmSync", False, Severity.LOW,
     "git.confirmSync is disabled - git push and pull run without a confirmation prompt."),
]


class TrustCheck(BaseCheck):
    check_id = "SETTINGS-TRUST-001"

    def run(self, target: dict) -> list:
        findings = []
        settings = target.get("settings", {})

        # Trusted folder keys - one finding per key listing ALL paths
        for key in TRUSTED_FOLDER_KEYS:
            if key not in settings:
                continue
            values = settings[key]
            if isinstance(values, list) and values:
                path_lines = "\n".join(str(p) for p in values)
                findings.append(Finding(
                    category=FindingCategory.TRUST,
                    severity=Severity.LOW,
                    title=f"Trusted paths: {key} ({len(values)} {'path' if len(values) == 1 else 'paths'})",
                    description=(
                        f"{len(values)} path{'s are' if len(values) != 1 else ' is'} explicitly "
                        f"trusted via '{key}'. VS Code grants elevated permissions to code in these locations."
                    ),
                    detail=path_lines,
                    source=key,
                    recommendation=(
                        "Remove any paths you no longer use, paths in shared or temp directories, "
                        "or paths you did not intentionally add."
                    ),
                ))
            elif isinstance(values, str):
                findings.append(Finding(
                    category=FindingCategory.TRUST,
                    severity=Severity.LOW,
                    title=f"Trust setting configured: {key}",
                    description="Workspace trust behavior is explicitly configured.",
                    detail=f"{key} = {values!r}",
                    source=key,
                    recommendation="Review this trust setting carefully.",
                ))

        # Auto-update settings
        for key, sev, desc in AUTO_UPDATE_KEYS:
            if key not in settings:
                continue
            val = settings[key]
            findings.append(Finding(
                category=FindingCategory.AUTO_UPDATE,
                severity=sev,
                title=f"Extension update setting: {key} = {val!r}",
                description=desc,
                detail=f"{key} = {val!r}",
                source=key,
                recommendation=(
                    "Set extensions.autoUpdate = false to review extension changes "
                    "before they are applied. Use the Extensions panel to update manually."
                ),
            ))

        # Git security settings
        for key, risky_val, sev, desc in GIT_KEYS:
            if key not in settings:
                continue
            val = settings[key]
            if val == risky_val:
                findings.append(Finding(
                    category=FindingCategory.SETTINGS,
                    severity=sev,
                    title=f"Git security setting: {key} = {val!r}",
                    description=desc,
                    detail=f"Current value: {val!r}  |  Recommended: {not risky_val!r}",
                    source=key,
                    recommendation=f"Set '{key}' to {not risky_val!r} in your settings.json.",
                ))

        return findings
