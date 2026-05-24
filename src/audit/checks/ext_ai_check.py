from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity

AI_CATEGORIES = {"ai", "chat", "machine learning"}

HIGH_RISK_API_PROPOSALS = {
    "terminalDataWriteEvent":          "Can read all terminal I/O (passwords, tokens)",
    "languageModelProxy":              "Can proxy requests to LLMs on your behalf",
    "chatParticipantAdditions":        "Can inject participants into all AI chat sessions",
    "chatSessionsProvider":            "Can read and modify all AI chat sessions",
    "remoteCodingAgents":              "Can spawn remote coding agents",
    "languageModelToolResultAudience": "Can read every LLM tool-call result",
    "aiRelatedInformation":            "Can access AI-related context from the editor",
    "chatParticipantPrivate":          "Can participate in private AI chat channels",
}


class AIExtensionCheck(BaseCheck):
    check_id = "EXT-AI-001"

    def run(self, target) -> list:
        findings = []
        manifest = target.manifest

        # Consolidate all high-risk API proposals into one finding
        risky = [
            (p, HIGH_RISK_API_PROPOSALS[p])
            for p in manifest.enabled_api_proposals
            if p in HIGH_RISK_API_PROPOSALS
        ]
        if risky:
            detail_lines = [f"{p}: {desc}" for p, desc in risky]
            repo = manifest.repository_url
            rec = "Review the extension source to confirm these APIs are used legitimately."
            if repo:
                rec += f" Source: {repo}"
            findings.append(Finding(
                category=FindingCategory.API_PERMISSIONS,
                severity=Severity.HIGH,
                title=(
                    f"{len(risky)} high-risk experimental API"
                    f"{'s' if len(risky) != 1 else ''}: {manifest.display_name}"
                ),
                description=(
                    f"Uses {len(risky)} experimental VS Code API"
                    f"{'s' if len(risky) != 1 else ''} that grant elevated access "
                    f"to AI sessions, terminal I/O, or agent capabilities."
                ),
                detail="\n".join(detail_lines),
                source=target.extension_id,
                recommendation=rec,
                references=[
                    "https://code.visualstudio.com/api/advanced-topics/using-proposed-api"
                ],
            ))

        if manifest.has_mcp_providers:
            findings.append(Finding(
                category=FindingCategory.MCP,
                severity=Severity.MEDIUM,
                title=f"Extension provides MCP server definitions: {manifest.display_name}",
                description=(
                    "This extension injects MCP tool definitions accessible to all "
                    "AI assistants in VS Code. Any AI assistant can invoke these tools."
                ),
                detail="contributes.mcpServerDefinitionProviders present in package.json",
                source=target.extension_id,
                recommendation=(
                    "Verify you trust this extension to define MCP tools. "
                    "Check what tools it exposes and whether they have network or file access."
                ),
            ))

        return findings
