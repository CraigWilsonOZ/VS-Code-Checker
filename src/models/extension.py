from dataclasses import dataclass, field


@dataclass
class ExtensionManifest:
    name: str
    display_name: str
    version: str
    publisher: str
    description: str
    categories: list
    enabled_api_proposals: list
    contributes_config_keys: list
    repository_url: str
    license: str
    engines_vscode: str
    extension_dependencies: list
    has_mcp_providers: bool
    install_source: str
    is_pre_release: bool
    installed_timestamp: int
    raw: dict = field(default_factory=dict, repr=False)


@dataclass
class ExtensionInfo:
    extension_id: str
    uuid: str
    directory: str
    manifest: ExtensionManifest
