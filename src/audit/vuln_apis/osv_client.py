import requests

from .base_api import BaseVulnAPI, VulnResult

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _highest_severity(vulns: list) -> str:
    best = "NONE"
    for v in vulns:
        for sev in v.get("severity", []):
            s = sev.get("score", "").upper()
            if _SEVERITY_ORDER.get(s, 0) > _SEVERITY_ORDER.get(best, 0):
                best = s
        db_sev = v.get("database_specific", {}).get("severity", "").upper()
        if _SEVERITY_ORDER.get(db_sev, 0) > _SEVERITY_ORDER.get(best, 0):
            best = db_sev
    return best


def _extract_fix_version(vuln: dict) -> str:
    """Pull the 'fixed' version from the first SEMVER range we find."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return ""


def _summarise_vuln(vuln: dict) -> dict:
    """Return a compact dict with the most useful fields from an OSV vuln entry."""
    fix = _extract_fix_version(vuln)
    aliases = vuln.get("aliases", [])
    cve = next((a for a in aliases if a.startswith("CVE-")), "")
    return {
        "id": vuln.get("id", ""),
        "summary": vuln.get("summary", "") or vuln.get("details", "")[:200],
        "fix_version": fix,
        "cve_alias": cve,
        "severity": vuln.get("database_specific", {}).get("severity", ""),
        "aliases": aliases,
    }


class OSVClient(BaseVulnAPI):
    """Queries api.osv.dev for npm package vulnerabilities."""

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: int = 10):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    def query_extension(
        self,
        extension_id: str,
        package_name: str,
        version: str,
        repo_url: str,
    ) -> VulnResult:
        # Only query with an exact version — the broadened name-only query returns
        # hits for unrelated npm packages that happen to share the extension's
        # package name, producing false positives.
        vulns = self._query(package_name, version) if version else []

        summaries = [_summarise_vuln(v) for v in vulns]
        ids = [s["id"] for s in summaries if s["id"]]

        return VulnResult(
            source="osv",
            extension_id=extension_id,
            has_vulns=bool(vulns),
            vuln_ids=ids,
            severity=_highest_severity(vulns),
            summary=(
                f"{len(vulns)} finding(s) found via OSV"
                if vulns else "No OSV findings"
            ),
            details=summaries,
        )

    def _query(self, package_name: str, version) -> list:
        payload: dict = {"package": {"name": package_name, "ecosystem": "npm"}}
        if version:
            payload["version"] = version
        try:
            resp = self._session.post(
                f"{self.BASE_URL}/query",
                json=payload,
                timeout=self._timeout,
            )
            if resp.ok:
                return resp.json().get("vulns", [])
        except requests.RequestException:
            pass
        return []

    def is_available(self) -> bool:
        try:
            r = requests.get(
                f"{self.BASE_URL}/vulns/OSV-2020-111",
                timeout=self._timeout,
            )
            return r.status_code == 200
        except Exception:
            return False
