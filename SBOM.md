# Software Bill of Materials (SBOM)

> Last updated: 24/05/2026

## Project

| Field | Value |
| --- | --- |
| Name | `vscode-security-checker` |
| Python | `>=3.10` |
| Licence | MIT |
| Repository | `https://github.com/CraigWilsonOZ/VS-Code-Checker` |

## Runtime Dependencies

All five packages are installed into an isolated virtual environment by
`setup.sh` using `pip install -r requirements.txt`. They are not installed
system-wide.

| Package | Constraint | Installed | Purpose | PyPI |
| --- | --- | --- | --- | --- |
| `requests` | `>=2.31.0` | 2.34.2 | HTTP client for API calls | [requests](https://pypi.org/project/requests/) |
| `rich` | `>=13.7.0` | 15.0.0 | Terminal colour output | [rich](https://pypi.org/project/rich/) |
| `click` | `>=8.1.0` | 8.4.1 | CLI argument parsing | [click](https://pypi.org/project/click/) |
| `pyyaml` | `>=6.0` | 6.0.3 | YAML config loading | [PyYAML](https://pypi.org/project/PyYAML/) |
| `packaging` | `>=23.0` | 26.2 | Version comparison | [packaging](https://pypi.org/project/packaging/) |

## External API Integrations

The tool makes outbound HTTPS calls to the following external services during
a scan. All queries are read-only. Credentials are only transmitted if a
GitHub token is explicitly provided by the user.

| Service | Auth | Data Sent |
| --- | --- | --- |
| [OSV.dev](https://api.osv.dev) | None | Package name and version |
| [VS Code Marketplace](https://marketplace.visualstudio.com) | None | Publisher and extension name |
| [GitHub Advisory DB](https://github.com/advisories) | Optional token | npm package name |

All three integrations fail gracefully on network error or rate limit. No
extension source code, settings values, or user credentials are transmitted
to any external service.

## Supply Chain Controls

| Control | Implementation | Status |
| --- | --- | --- |
| Isolated dependency environment | `setup.sh` creates `.venv/` | Active |
| Pinned minimum versions | `requirements.txt` `>=` bounds | Active |
| No install-time code execution | No `setup.py`; `pip install -r` | Active |
| Download validation | `export-extensions.sh` zip magic check | Active |
| Secrets redaction | `SecretsCheck` redacts to `abc***xyz` | Active |

## Licence Summary

| Package | Licence |
| --- | --- |
| `requests` | Apache-2.0 |
| `rich` | MIT |
| `click` | BSD-3-Clause |
| `pyyaml` | MIT |
| `packaging` | Apache-2.0 OR BSD-2-Clause |

> Licence information is sourced from installed package metadata via
> `pip show`. Verify before redistribution.
