from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity

AI_KEY_PREFIXES = (
    "copilot",
    "github.copilot",
    "claude",
    "claudecode",
    "gitlens.ai",
    "continue.",
    "openai.",
    "chatgpt.",
    "tabnine.",
    "codeium.",
    "amazonq.",
    "aws.codewhisperer",
    "ms-windows-ai-studio",
)

TELEMETRY_CHECKS = {
    "telemetry.telemetryLevel": {
        "safe_values": {"off", "error"},
        "description": "VS Code telemetry is enabled - usage data is sent to Microsoft.",
        "detail_fn": lambda val: f"Current value: {val!r}  |  Privacy-safe values: 'off' or 'error'",
    },
    "gitlens.telemetry.enabled": {
        "safe_values": {False},
        "description": "GitLens telemetry is enabled - usage data is sent to GitKraken.",
        "detail_fn": lambda val: f"gitlens.telemetry.enabled = {val!r}  |  Set to false to disable",
    },
    "continue.telemetryEnabled": {
        "safe_values": {False},
        "description": "Continue AI extension telemetry is enabled.",
        "detail_fn": lambda val: f"continue.telemetryEnabled = {val!r}  |  Set to false to disable",
    },
}


class AIConfigCheck(BaseCheck):
    check_id = "SETTINGS-AI-001"

    def run(self, target: dict) -> list:
        findings = []
        settings = target.get("settings", {})

        # Collect all AI-related config keys
        seen_keys = set()
        ai_keys_found = {}
        for key in sorted(settings.keys()):
            key_lower = key.lower()
            for prefix in AI_KEY_PREFIXES:
                if key_lower.startswith(prefix.lower()) or prefix.lower() in key_lower:
                    if key not in seen_keys:
                        seen_keys.add(key)
                        ai_keys_found[key] = settings[key]
                    break

        # Emit a single consolidated finding if any AI keys present
        if ai_keys_found:
            detail_lines = [f"{k} = {v!r}" for k, v in ai_keys_found.items()]
            findings.append(Finding(
                category=FindingCategory.AI_CONFIG,
                severity=Severity.INFO,
                title=f"AI tool configuration: {len(ai_keys_found)} settings found",
                description=(
                    "AI assistant settings are configured in VS Code. "
                    "Review data sharing, telemetry, and model endpoint settings."
                ),
                detail="\n".join(detail_lines),
                source="AI configuration",
                recommendation=(
                    "Check each AI tool's telemetry and data sharing settings. "
                    "Disable telemetry if you work with sensitive code."
                ),
            ))

        # Telemetry-specific findings (individually actionable)
        for key, check in TELEMETRY_CHECKS.items():
            if key not in settings:
                continue
            val = settings[key]
            safe = check["safe_values"]
            if safe and val in safe:
                continue
            findings.append(Finding(
                category=FindingCategory.AI_CONFIG,
                severity=Severity.MEDIUM,
                title=f"Telemetry enabled: {key}",
                description=check["description"],
                detail=check["detail_fn"](val),
                source=key,
                recommendation=f"Set '{key}' to a privacy-preserving value to stop sending usage data.",
            ))

        return findings
