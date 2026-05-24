import re

from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_PRIVATE_RANGES = [
    re.compile(r"^192\.168\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^127\."),
]


def _is_private_ip(host: str) -> bool:
    return any(p.match(host) for p in _PRIVATE_RANGES)


class RemoteHostCheck(BaseCheck):
    check_id = "SETTINGS-REMOTE-001"

    def run(self, target: dict) -> list:
        findings = []
        settings = target.get("settings", {})
        mcp = target.get("mcp_config", {})

        # SSH remote hosts enumerated in settings
        remote_platforms = settings.get("remote.SSH.remotePlatform", {})
        if isinstance(remote_platforms, dict):
            for host, platform in remote_platforms.items():
                if _IPV4_RE.match(host):
                    is_private = _is_private_ip(host)
                    findings.append(Finding(
                        category=FindingCategory.REMOTE_HOST,
                        severity=Severity.MEDIUM if is_private else Severity.HIGH,
                        title=f"Remote SSH host recorded in settings: {host}",
                        description=(
                            "VS Code settings enumerate SSH remote host addresses. "
                            "If settings are synced, this exposes your network topology."
                        ),
                        detail=f"remote.SSH.remotePlatform['{host}'] = '{platform}'",
                        source="remote.SSH.remotePlatform",
                        recommendation=(
                            "Remove host mappings from settings.json if settings sync "
                            "is enabled, or use an SSH config file instead."
                        ),
                    ))
                else:
                    # Hostname (not IP) - lower risk but still worth noting
                    findings.append(Finding(
                        category=FindingCategory.REMOTE_HOST,
                        severity=Severity.LOW,
                        title=f"Remote SSH hostname recorded in settings: {host}",
                        description=(
                            "A remote SSH hostname is stored in VS Code settings."
                        ),
                        detail=f"remote.SSH.remotePlatform['{host}'] = '{platform}'",
                        source="remote.SSH.remotePlatform",
                        recommendation=(
                            "Consider whether this hostname should be in synced settings."
                        ),
                    ))

        # MCP server configuration
        for server_name, server_cfg in mcp.get("servers", {}).items():
            if not isinstance(server_cfg, dict):
                continue
            url = server_cfg.get("url", "")
            server_type = server_cfg.get("type", "")

            if url.startswith("http://"):
                findings.append(Finding(
                    category=FindingCategory.MCP,
                    severity=Severity.HIGH,
                    title=f"MCP server uses plain HTTP: {server_name}",
                    description=(
                        "An MCP server is configured with an unencrypted HTTP connection. "
                        "Requests and responses (including AI context) are sent in plain text."
                    ),
                    detail=f"mcp.servers.{server_name}.url = {url!r}",
                    source=f"mcp.servers.{server_name}",
                    recommendation="Use HTTPS for all MCP server connections.",
                ))

            findings.append(Finding(
                category=FindingCategory.MCP,
                severity=Severity.INFO,
                title=f"MCP server configured: {server_name}",
                description="An MCP server is registered and accessible to AI assistants.",
                detail=(
                    f"mcp.servers.{server_name}: "
                    f"type={server_type!r}, url={url!r}"
                ),
                source=f"mcp.servers.{server_name}",
                recommendation=(
                    "Ensure you trust this MCP server. It can expose tools to all "
                    "AI assistants configured in VS Code."
                ),
            ))

        return findings
