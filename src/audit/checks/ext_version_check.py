from .base_check import BaseCheck
from ...models.findings import Finding, FindingCategory, Severity
from ..vuln_apis.marketplace_client import MarketplaceClient


def _parse_version(v: str):
    """Parse a version string into a comparable tuple, ignoring pre-release suffixes."""
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:
        pass
    # Fallback: split on dots/dashes, take leading integers
    parts = []
    for segment in v.replace("-", ".").split("."):
        try:
            parts.append(int(segment))
        except ValueError:
            break
    return tuple(parts)


def _fmt_installs(n) -> str:
    if n is None:
        return "unknown"
    n = int(n)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}K"
    return str(n)


def _fmt_date(iso: str) -> str:
    if not iso:
        return "unknown"
    return iso[:10]  # YYYY-MM-DD


class VersionCheck(BaseCheck):
    """
    Fetches Marketplace metadata for each extension and produces:
    - A VERSION/INFO finding with full extension metadata (used by renderers for headers)
    - A MEDIUM finding if the installed version is outdated
    - A HIGH finding if the extension is deprecated
    """
    check_id = "EXT-VERSION-001"

    def __init__(self, marketplace: MarketplaceClient, stale_days: int = 180):
        self._marketplace = marketplace
        self._stale_days = stale_days

    def run(self, target) -> list:
        manifest = target.manifest
        findings = []

        try:
            result = self._marketplace.query_extension(
                extension_id=target.extension_id,
                package_name=manifest.name,
                version=manifest.version,
                repo_url=manifest.repository_url,
            )
        except Exception:
            # Network unavailable - emit a minimal metadata finding from local info only
            findings.append(self._local_only_finding(target))
            return findings

        details = result.details[0] if result.details else {}
        found = details.get("found", False)

        if not found:
            findings.append(self._local_only_finding(target))
            return findings

        latest_version = details.get("latest_version", "")
        last_updated = details.get("last_updated", "")
        publisher_display = details.get("publisher_display_name", manifest.publisher)
        install_count = details.get("install_count")
        avg_rating = details.get("avg_rating")
        rating_count = details.get("rating_count")
        is_deprecated = details.get("deprecated", False)
        is_verified = details.get("verified_publisher", False)

        # Determine if outdated
        installed = manifest.version
        is_outdated = False
        if latest_version and installed:
            try:
                is_outdated = _parse_version(installed) < _parse_version(latest_version)
            except Exception:
                is_outdated = installed != latest_version

        # Rating string
        rating_str = ""
        if avg_rating is not None:
            stars = f"{avg_rating:.1f}/5"
            if rating_count:
                stars += f" ({_fmt_installs(rating_count)} ratings)"
            rating_str = stars

        metadata = {
            "installed_version": installed,
            "latest_version": latest_version,
            "is_outdated": is_outdated,
            "publisher_display_name": publisher_display,
            "publisher_id": manifest.publisher,
            "install_count": install_count,
            "install_count_fmt": _fmt_installs(install_count),
            "avg_rating": avg_rating,
            "rating_str": rating_str,
            "last_updated": _fmt_date(last_updated),
            "is_deprecated": is_deprecated,
            "is_verified": is_verified,
            "repository_url": manifest.repository_url,
        }

        # Always emit the metadata finding (INFO) - renderers use this for headers
        version_label = f"v{installed}"
        if latest_version:
            if is_outdated:
                version_label += f" -> v{latest_version} (OUTDATED)"
            else:
                version_label += " (current)"

        findings.append(Finding(
            category=FindingCategory.VERSION,
            severity=Severity.INFO,
            title=f"Extension metadata: {manifest.display_name}",
            description=(
                f"Publisher: {publisher_display} | "
                f"Installs: {_fmt_installs(install_count)} | "
                f"Rating: {rating_str or 'n/a'} | "
                f"Last updated: {_fmt_date(last_updated)}"
            ),
            detail=version_label,
            source=target.extension_id,
            recommendation="",
            metadata=metadata,
        ))

        # Outdated finding
        if is_outdated:
            findings.append(Finding(
                category=FindingCategory.VERSION,
                severity=Severity.MEDIUM,
                title=f"Outdated extension: {manifest.display_name}",
                description=(
                    f"Installed v{installed} but Marketplace has v{latest_version}. "
                    f"Outdated extensions may miss security patches."
                ),
                detail=f"Installed: v{installed}  |  Latest: v{latest_version}  |  Last updated: {_fmt_date(last_updated)}",
                source=target.extension_id,
                recommendation=(
                    f"Update via Extensions panel or run: "
                    f"code --install-extension {target.extension_id} --force"
                ),
                references=[
                    f"https://marketplace.visualstudio.com/items?itemName={target.extension_id}"
                ],
                metadata=metadata,
            ))

        # Stale finding - not updated in over 6 months
        if last_updated:
            from datetime import datetime, timezone
            try:
                updated_dt = datetime.fromisoformat(last_updated.rstrip("Z")).replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - updated_dt).days
                if age_days > self._stale_days:
                    age_months = age_days // 30
                    findings.append(Finding(
                        category=FindingCategory.VERSION,
                        severity=Severity.LOW,
                        title=f"Stale extension: {manifest.display_name} ({age_months} months since last update)",
                        description=(
                            f"This extension has not been updated in {age_months} months. "
                            f"Unmaintained extensions may contain unpatched vulnerabilities."
                        ),
                        detail=(
                            f"Last updated: {_fmt_date(last_updated)}  |  "
                            f"Installed: v{installed}  |  Publisher: {publisher_display}"
                        ),
                        source=target.extension_id,
                        recommendation=(
                            "Check if the extension is still actively maintained. "
                            "Consider finding an alternative if development has stopped."
                        ),
                        references=[
                            f"https://marketplace.visualstudio.com/items?itemName={target.extension_id}"
                        ],
                        metadata=metadata,
                    ))
            except (ValueError, TypeError):
                pass

        # Deprecated finding
        if is_deprecated:
            findings.append(Finding(
                category=FindingCategory.VERSION,
                severity=Severity.HIGH,
                title=f"Deprecated extension: {manifest.display_name}",
                description="This extension is marked as deprecated in the VS Code Marketplace.",
                detail=f"v{installed} installed | Publisher: {publisher_display}",
                source=target.extension_id,
                recommendation="Find a replacement extension as this one is no longer maintained.",
                references=[
                    f"https://marketplace.visualstudio.com/items?itemName={target.extension_id}"
                ],
                metadata=metadata,
            ))

        return findings

    def _local_only_finding(self, target) -> Finding:
        manifest = target.manifest
        return Finding(
            category=FindingCategory.VERSION,
            severity=Severity.INFO,
            title=f"Extension metadata: {manifest.display_name}",
            description="Marketplace data unavailable (offline or extension not in Marketplace).",
            detail=f"v{manifest.version} (latest: unknown)",
            source=target.extension_id,
            recommendation="",
            metadata={
                "installed_version": manifest.version,
                "latest_version": "",
                "is_outdated": False,
                "publisher_display_name": manifest.publisher,
                "publisher_id": manifest.publisher,
                "install_count": None,
                "install_count_fmt": "unknown",
                "avg_rating": None,
                "rating_str": "",
                "last_updated": "",
                "is_deprecated": False,
                "is_verified": False,
                "repository_url": manifest.repository_url,
            },
        )
