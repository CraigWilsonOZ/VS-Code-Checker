import json
import re

from ..platform.base import AbstractPlatform, VSCodePaths

# Matches // line comments that are not inside a string value.
# Good enough heuristic for VS Code settings files.
_COMMENT_RE = re.compile(r"^\s*//.*$", re.MULTILINE)
# Block comments /* ... */
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
# Trailing commas before } or ]
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


_MAX_SETTINGS_SIZE = 10 * 1024 * 1024  # 10 MB


def _parse_jsonc(text: str) -> dict:
    if len(text) > _MAX_SETTINGS_SIZE:
        return {}
    text = _BLOCK_COMMENT_RE.sub("", text)
    text = _COMMENT_RE.sub("", text)
    text = _TRAILING_COMMA_RE.sub(r"\1", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


class SettingsScanner:

    def __init__(self, platform: AbstractPlatform, paths: VSCodePaths):
        self._platform = platform
        self._paths = paths

    def scan(self) -> dict:
        settings = self._read_jsonc(self._paths.user_settings)

        mcp = {}
        if self._platform.path_exists(self._paths.mcp_config):
            mcp = self._read_jsonc(self._paths.mcp_config)

        return {
            "settings": settings,
            "mcp_config": mcp,
            "settings_path": self._paths.user_settings,
            "mcp_path": self._paths.mcp_config,
        }

    def _read_jsonc(self, path: str) -> dict:
        if not self._platform.path_exists(path):
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            return _parse_jsonc(text)
        except OSError:
            return {}
