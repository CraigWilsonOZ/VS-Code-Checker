import json
import os
from pathlib import Path

from .base import AbstractPlatform, VSCodePaths


class LinuxPlatform(AbstractPlatform):

    def detect_vscode_paths(self) -> VSCodePaths:
        home = Path.home()
        config_base = home / ".config"

        user_dir = None
        for variant in ["Code", "Code - Insiders", "code"]:
            candidate = config_base / variant / "User"
            if candidate.exists():
                user_dir = candidate
                break

        if user_dir is None:
            raise RuntimeError(
                "VS Code user config not found. Checked: "
                "~/.config/Code/User, ~/.config/Code - Insiders/User"
            )

        return VSCodePaths(
            extensions_dir=str(home / ".vscode" / "extensions"),
            user_settings=str(user_dir / "settings.json"),
            mcp_config=str(user_dir / "mcp.json"),
            global_storage=str(user_dir / "globalStorage"),
            cli_executable="code",
        )

    def get_platform_name(self) -> str:
        return "linux"

    def path_exists(self, path: str) -> bool:
        return os.path.exists(path)

    def list_directory(self, path: str) -> list:
        return os.listdir(path)

    def read_json_file(self, path: str) -> dict:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
