from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class FindingCategory(Enum):
    CVE = "CVE"
    AI_EXTENSION = "AI_EXTENSION"
    AUTO_UPDATE = "AUTO_UPDATE"
    API_PERMISSIONS = "API_PERMISSIONS"
    SECRET = "SECRET"
    AI_CONFIG = "AI_CONFIG"
    TRUST = "TRUST"
    REMOTE_HOST = "REMOTE_HOST"
    MCP = "MCP"
    SETTINGS = "SETTINGS"
    VERSION = "VERSION"


@dataclass
class Finding:
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    detail: str
    source: str
    recommendation: str
    references: list = field(default_factory=list)
    cve_ids: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
