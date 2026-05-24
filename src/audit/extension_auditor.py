from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config.settings import AppConfig
from ..models.report import ReportSection
from .checks.ext_ai_check import AIExtensionCheck
from .checks.ext_autoupdate_check import AutoUpdateCheck
from .checks.ext_cve_check import CVECheck
from .checks.ext_version_check import VersionCheck
from .vuln_apis.github_advisory_client import GitHubAdvisoryClient
from .vuln_apis.marketplace_client import MarketplaceClient
from .vuln_apis.osv_client import OSVClient


def _run_all_network_checks(checks: list, ext) -> list:
    """Run all network checks for one extension, collecting findings."""
    findings = []
    for check in checks:
        try:
            findings.extend(check.run(ext))
        except Exception:
            pass
    return findings


class ExtensionAuditor:

    def __init__(self, config: AppConfig):
        self._config = config
        self._marketplace_client = (
            MarketplaceClient(timeout=config.api_timeout_seconds)
            if config.check_marketplace else None
        )
        self._network_checks = self._build_network_checks()
        self._local_checks = [AIExtensionCheck(), AutoUpdateCheck()]

    def _build_network_checks(self) -> list:
        checks = []

        cve_apis = []
        if self._config.check_cves:
            cve_apis.append(OSVClient(timeout=self._config.api_timeout_seconds))
        if self._marketplace_client:
            cve_apis.append(self._marketplace_client)
        if self._config.check_github_advisories:
            cve_apis.append(GitHubAdvisoryClient(
                token=self._config.github_token,
                timeout=self._config.api_timeout_seconds,
            ))
        if cve_apis:
            checks.append(CVECheck(apis=cve_apis))

        # VersionCheck uses its own marketplace client so it doesn't conflict with CVECheck
        if self._config.check_marketplace:
            checks.append(VersionCheck(
                MarketplaceClient(timeout=self._config.api_timeout_seconds),
                stale_days=self._config.stale_extension_days,
            ))

        return checks

    def audit(self, extensions: list, progress_callback=None) -> ReportSection:
        all_findings = []
        total = len(extensions)

        with ThreadPoolExecutor(max_workers=self._config.max_concurrent_api_requests) as pool:
            future_to_ext = {
                pool.submit(_run_all_network_checks, self._network_checks, ext): ext
                for ext in extensions
            }
            for i, future in enumerate(as_completed(future_to_ext)):
                ext = future_to_ext[future]
                try:
                    all_findings.extend(future.result())
                except Exception:
                    pass
                if progress_callback:
                    progress_callback(i + 1, total, ext.extension_id)

        for ext in extensions:
            for check in self._local_checks:
                all_findings.extend(check.run(ext))

        return ReportSection(
            title="Extension Security Audit",
            findings=all_findings,
        )
