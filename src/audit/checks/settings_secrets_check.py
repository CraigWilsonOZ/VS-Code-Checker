import re

from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity

# (label, pattern, severity, description)
SECRET_PATTERNS = [
    (
        "OpenAI API Key",
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        Severity.CRITICAL,
        "OpenAI API key found in VS Code settings",
    ),
    (
        "Anthropic API Key",
        re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
        Severity.CRITICAL,
        "Anthropic API key found in VS Code settings",
    ),
    (
        "GitHub PAT (classic)",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        Severity.CRITICAL,
        "GitHub classic personal access token found in VS Code settings",
    ),
    (
        "GitHub PAT (fine-grained)",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        Severity.CRITICAL,
        "GitHub fine-grained personal access token found in VS Code settings",
    ),
    (
        "AWS Access Key ID",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
        "AWS access key ID found in VS Code settings",
    ),
    (
        "AWS Secret Key",
        re.compile(r"(?i)aws[_\s]?secret[_\s]?access[_\s]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
        Severity.CRITICAL,
        "Possible AWS secret access key found in VS Code settings",
    ),
    (
        "Bearer Token",
        re.compile(r"Bearer [A-Za-z0-9\-_.]{20,}"),
        Severity.HIGH,
        "Bearer token value found in VS Code settings",
    ),
    (
        "Proxy with Credentials",
        re.compile(r"https?://[^:@\s]+:[^@\s]+@"),
        Severity.HIGH,
        "Proxy URL with embedded credentials found in VS Code settings",
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Private key material found in VS Code settings",
    ),
    (
        "Generic API Key Pattern",
        re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}"),
        Severity.HIGH,
        "Possible API key assignment found in VS Code settings value",
    ),
]


def _redact(value: str, pattern: re.Pattern) -> str:
    m = pattern.search(value)
    if not m:
        return value[:6] + "***"
    s = m.group(0)
    if len(s) > 8:
        return value.replace(s, s[:3] + "***" + s[-3:])
    return value[:3] + "***"


class SecretsCheck(BaseCheck):
    check_id = "SETTINGS-SECRET-001"

    def run(self, target: dict) -> list:
        settings = target.get("settings", {})
        return self._scan_dict(settings, prefix="")

    def _scan_dict(self, d: dict, prefix: str) -> list:
        findings = []
        for key, value in d.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                findings.extend(self._scan_dict(value, full_key))
            elif isinstance(value, str):
                findings.extend(self._check_value(full_key, value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        findings.extend(self._check_value(full_key, item))
        return findings

    def _check_value(self, key: str, value: str) -> list:
        for label, pattern, severity, desc in SECRET_PATTERNS:
            if pattern.search(value):
                redacted = _redact(value, pattern)
                return [Finding(
                    category=FindingCategory.SECRET,
                    severity=severity,
                    title=f"{label} detected in settings",
                    description=desc,
                    detail=f"Key: '{key}' = '{redacted}'",
                    source=key,
                    recommendation=(
                        "Remove secrets from settings.json immediately. "
                        "Use environment variables, a secrets manager, or "
                        "VS Code's built-in credential storage instead."
                    ),
                )]
        return []
