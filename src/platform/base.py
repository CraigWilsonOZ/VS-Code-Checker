from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class VSCodePaths:
    extensions_dir: str
    user_settings: str
    mcp_config: str
    global_storage: str
    cli_executable: str


class AbstractPlatform(ABC):

    @abstractmethod
    def detect_vscode_paths(self) -> VSCodePaths:
        ...

    @abstractmethod
    def get_platform_name(self) -> str:
        ...

    @abstractmethod
    def path_exists(self, path: str) -> bool:
        ...

    @abstractmethod
    def list_directory(self, path: str) -> list:
        ...

    @abstractmethod
    def read_json_file(self, path: str) -> dict:
        ...

    @classmethod
    def create(cls) -> "AbstractPlatform":
        import platform as _platform
        if _platform.system() == "Windows":
            from .windows import WindowsPlatform
            return WindowsPlatform()
        else:
            from .linux import LinuxPlatform
            return LinuxPlatform()
