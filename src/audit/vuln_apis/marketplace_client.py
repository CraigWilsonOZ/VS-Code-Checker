import requests

from .base_api import BaseVulnAPI, VulnResult

GALLERY_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
API_VERSION = "7.2-preview.1"
FILTER_EXTENSION_NAME = 7
# IncludeVersions(2) | IncludeFiles(4) | IncludeCategoryAndTags(8)
# | IncludeVersionProperties(32) | IncludeInstallationTargets(128)
# | IncludeAssetUri(256) | IncludeStatistics(512)
FLAGS = 914 | 32  # 946


def _get_stat(stats: list, name: str):
    for s in stats:
        if s.get("statisticName") == name:
            v = s.get("value")
            return int(v) if v is not None else None
    return None


def _is_prerelease(version_entry: dict) -> bool:
    """Return True if this version entry is marked as a pre-release."""
    for prop in version_entry.get("properties", []):
        if (prop.get("key") == "Microsoft.VisualStudio.Code.PreRelease"
                and prop.get("value") == "true"):
            return True
    return False


def _get_latest_version(versions: list) -> str:
    """
    Pick the latest stable universal version (no targetPlatform).
    Pre-release versions appear first in the list but should not be
    compared against stable installs - they cause false 'outdated' findings.
    Falls back to pre-release only if no stable version exists.
    """
    universal = [v for v in versions if not v.get("targetPlatform")]
    candidates = universal if universal else versions
    stable = [v for v in candidates if not _is_prerelease(v)]
    chosen = stable if stable else candidates
    if not chosen:
        return ""
    return chosen[0].get("version", "")


class MarketplaceClient(BaseVulnAPI):
    """
    Queries VS Code Marketplace for extension metadata:
    latest version, publisher, install count, rating, last update date,
    deprecated/unverified flags.
    """

    def __init__(self, timeout: int = 10):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": f"application/json;api-version={API_VERSION}",
            # Required to avoid 429 rate limiting from Marketplace
            "User-Agent": "VSCode/1.95.0",
        })

    def query_extension(
        self,
        extension_id: str,
        package_name: str,
        version: str,
        repo_url: str,
    ) -> VulnResult:
        payload = {
            "filters": [{
                "criteria": [
                    {"filterType": FILTER_EXTENSION_NAME, "value": extension_id}
                ],
                "pageSize": 1,
                "pageNumber": 1,
            }],
            "flags": FLAGS,
        }
        try:
            resp = self._session.post(GALLERY_URL, json=payload, timeout=self._timeout)
            if not resp.ok:
                return self._not_found(extension_id)
            data = resp.json()
        except requests.RequestException:
            return self._not_found(extension_id)

        results = (data.get("results") or [{}])[0]
        extensions = results.get("extensions", [])
        if not extensions:
            return self._not_found(extension_id)

        ext = extensions[0]
        flags = ext.get("flags", 0)
        if isinstance(flags, str):
            flags = 0
        is_deprecated = bool(flags & 128)

        pub = ext.get("publisher", {})
        publisher_name = pub.get("publisherName", "")
        publisher_display = pub.get("displayName", publisher_name)
        # Verified publisher badge = publisher has verified domain ownership
        is_verified = bool(pub.get("isDomainVerified", False))

        versions = ext.get("versions", [])
        latest_version = _get_latest_version(versions)
        # lastUpdated lives on the extension root (ISO 8601)
        last_updated = ext.get("lastUpdated", "")

        stats = ext.get("statistics", [])
        install_count = _get_stat(stats, "install")
        avg_rating = _get_stat(stats, "averagerating")
        rating_count = _get_stat(stats, "ratingcount")

        marketplace_display_name = ext.get("displayName", "")

        issues = []
        has_vulns = False
        severity = "NONE"
        if is_deprecated:
            issues.append("Extension is marked DEPRECATED in Marketplace")
            has_vulns = True
            severity = "HIGH"
        if not is_verified:
            issues.append("Publisher is not verified in Marketplace")
            if severity == "NONE":
                severity = "LOW"

        return VulnResult(
            source="marketplace",
            extension_id=extension_id,
            has_vulns=has_vulns,
            severity=severity,
            summary="; ".join(issues) if issues else "No Marketplace flags",
            details=[{
                "found": True,
                "deprecated": is_deprecated,
                "verified_publisher": is_verified,
                "flags": flags,
                "latest_version": latest_version,
                "last_updated": last_updated,
                "publisher_name": publisher_name,
                "publisher_display_name": publisher_display,
                "marketplace_display_name": marketplace_display_name,
                "install_count": install_count,
                "avg_rating": avg_rating,
                "rating_count": rating_count,
            }],
        )

    def _not_found(self, extension_id: str) -> VulnResult:
        return VulnResult(
            source="marketplace",
            extension_id=extension_id,
            has_vulns=False,
            summary="Not found in Marketplace",
            details=[{"found": False}],
        )

    def is_available(self) -> bool:
        try:
            r = requests.head(
                "https://marketplace.visualstudio.com",
                headers={"User-Agent": "VSCode/1.95.0"},
                timeout=self._timeout,
            )
            return r.status_code < 500
        except Exception:
            return False
