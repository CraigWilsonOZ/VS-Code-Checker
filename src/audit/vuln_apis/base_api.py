from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class VulnResult:
    source: str
    extension_id: str
    has_vulns: bool
    vuln_ids: list = field(default_factory=list)
    severity: str = "NONE"
    summary: str = ""
    details: list = field(default_factory=list)


class BaseVulnAPI(ABC):

    @abstractmethod
    def query_extension(
        self,
        extension_id: str,
        package_name: str,
        version: str,
        repo_url: str,
    ) -> VulnResult:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...
