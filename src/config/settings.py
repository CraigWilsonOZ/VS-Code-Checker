import copy
import dataclasses
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AppConfig:
    # Path overrides (None = auto-detect via platform layer)
    extensions_dir: Optional[str] = None
    settings_file: Optional[str] = None
    mcp_config_file: Optional[str] = None

    # Scan toggles
    check_cves: bool = True
    check_marketplace: bool = True
    check_github_advisories: bool = True

    # Network
    max_concurrent_api_requests: int = 5
    api_timeout_seconds: int = 10

    # Output
    output_dir: str = "./reports"
    output_formats: list = field(default_factory=lambda: ["console", "json", "markdown"])
    severity_threshold: str = "INFO"

    # Thresholds
    stale_extension_days: int = 365           # flag extensions not updated in this many days

    # Optional auth
    github_token: Optional[str] = None

    @classmethod
    def from_file(cls, path: str) -> "AppConfig":
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        valid_keys = {f.name for f in dataclasses.fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    @classmethod
    def from_env(cls, base: "AppConfig") -> "AppConfig":
        cfg = copy.copy(base)
        for f in dataclasses.fields(cls):
            env_key = f"VSCCHECK_{f.name.upper()}"
            val = os.environ.get(env_key)
            if val is not None:
                # Coerce booleans
                if isinstance(getattr(cfg, f.name), bool):
                    setattr(cfg, f.name, val.lower() not in ("0", "false", "no"))
                elif isinstance(getattr(cfg, f.name), int):
                    setattr(cfg, f.name, int(val))
                else:
                    setattr(cfg, f.name, val)
        # GitHub token also readable from standard GITHUB_TOKEN env var
        if not cfg.github_token:
            cfg.github_token = os.environ.get("GITHUB_TOKEN")
        return cfg
