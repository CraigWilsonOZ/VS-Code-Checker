import json
import os
from pathlib import Path

from .base import AbstractPlatform, VSCodePaths


class WindowsPlatform(AbstractPlatform):
    """Windows platform support - stub for future implementation."""

    def detect_vscode_paths(self) -> VSCodePaths:
        appdata = os.environ.get("APPDATA", "")
        userprofile = os.environ.get("USERPROFILE", str(Path.home()))

        if not appdata:
            raise RuntimeError("APPDATA environment variable not set.")

        user_dir = Path(appdata) / "Code" / "User"
        if not user_dir.exists():
            user_dir_insiders = Path(appdata) / "Code - Insiders" / "User"
            if user_dir_insiders.exists():
                user_dir = user_dir_insiders
            else:
                raise RuntimeError(
                    "VS Code user config not found. "
                    "Checked %%APPDATA%%\\Code\\User and "
                    "%%APPDATA%%\\Code - Insiders\\User"
                )

        return VSCodePaths(
            extensions_dir=str(Path(userprofile) / ".vscode" / "extensions"),
            user_settings=str(user_dir / "settings.json"),
            mcp_config=str(user_dir / "mcp.json"),
            global_storage=str(user_dir / "globalStorage"),
            cli_executable="code.cmd",
        )

    def get_platform_name(self) -> str:
        return "windows"

    def path_exists(self, path: str) -> bool:
        return os.path.exists(path)

    def list_directory(self, path: str) -> list:
        return os.listdir(path)

    def read_json_file(self, path: str) -> dict:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
