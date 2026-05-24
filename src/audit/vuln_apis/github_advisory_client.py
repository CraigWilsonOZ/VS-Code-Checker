import requests

from .base_api import BaseVulnAPI, VulnResult

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _highest_severity(advisories: list) -> str:
    best = "NONE"
    for a in advisories:
        s = a.get("severity", "").upper()
        if _SEVERITY_ORDER.get(s, 0) > _SEVERITY_ORDER.get(best, 0):
            best = s
    return best


class GitHubAdvisoryClient(BaseVulnAPI):
    """Queries the GitHub Advisory Database for npm package advisories."""

    BASE_URL = "https://api.github.com/advisories"

    def __init__(self, token: str = None, timeout: int = 10):
        self._timeout = timeout
        self._session = requests.Session()
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._session.headers.update(headers)

    def query_extension(
        self,
        extension_id: str,
        package_name: str,
        version: str,
        repo_url: str,
    ) -> VulnResult:
        params = {
            "affects": package_name,
            "ecosystem": "npm",
            "per_page": 10,
        }
        try:
            resp = self._session.get(self.BASE_URL, params=params, timeout=self._timeout)
            advisories = resp.json() if resp.ok else []
            if not isinstance(advisories, list):
                advisories = []
        except requests.RequestException:
            advisories = []

        ghsa_ids = [a.get("ghsa_id", "") for a in advisories if a.get("ghsa_id")]
        cve_ids = [a.get("cve_id") for a in advisories if a.get("cve_id")]
        all_ids = ghsa_ids + cve_ids

        return VulnResult(
            source="github_advisory",
            extension_id=extension_id,
            has_vulns=bool(advisories),
            vuln_ids=all_ids,
            severity=_highest_severity(advisories),
            summary=(
                f"{len(advisories)} GitHub advisory/ies"
                if advisories else "No GitHub advisories"
            ),
            details=advisories,
        )

    def is_available(self) -> bool:
        try:
            r = requests.get("https://api.github.com/rate_limit", timeout=self._timeout)
            return r.status_code == 200
        except Exception:
            return False
