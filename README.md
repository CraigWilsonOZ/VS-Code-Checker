# VS Code Security Checker

A command-line security audit tool for Visual Studio Code installations.
It scans every installed extension and your VS Code settings, queries
public vulnerability databases and the Marketplace API, and produces
findings sorted by severity. Output is available as a Rich terminal view,
JSON, Markdown, and a self-contained HTML report suitable for presentations
or sharing with a team.

---

## Disclaimer and Scope of Coverage

This tool is designed to assist with the identification of known security
risks in a VS Code installation. It is not a guarantee of security and will
not detect all possible issues. Like any automated scanning tool, it works
from a defined set of checks, known vulnerability databases, and observable
metadata - it cannot identify novel threats, zero-day vulnerabilities that
have not yet been disclosed, or malicious behaviour that occurs entirely at
runtime without leaving evidence in the extension manifest or settings files.

Findings produced by this tool should be treated as a starting point for
investigation, not a definitive verdict. A finding does not necessarily mean
an extension or setting is actively being exploited; equally, the absence of
findings does not mean an installation is free of risk. Deprecated extensions
and outdated versions represent elevated risk, but not all of them contain
exploitable vulnerabilities. Unverified publishers are flagged because they
have not completed domain verification with Microsoft - this is a signal to
review, not proof of malicious intent.

This tool is intended for use by developers and security teams who have
authorisation to audit the VS Code installation being scanned. Running it
against someone else's environment without permission is not a supported or
endorsed use case. The information it surfaces - extension lists, settings
keys, SSH hosts, MCP server endpoints - should be treated as sensitive and
handled in accordance with your organisation's data classification policies.

The authors make no warranty, express or implied, regarding the completeness,
accuracy, or fitness for purpose of the findings this tool produces. Use it
as one layer of a broader security programme, not as a standalone assurance
mechanism.

---

## Why This Tool Exists

The VS Code extension ecosystem has grown to tens of thousands of packages,
and the Marketplace does not apply the same level of scrutiny as, say, the
Apple App Store or a curated Linux package repository. Extensions execute
with the same privileges as the VS Code process itself, meaning they have
read/write access to your entire file system, can spawn arbitrary processes,
make outbound network connections, and intercept terminal input and output.

The threat is not hypothetical. There have been documented cases of
typosquatted extensions, extensions that were legitimate at publication and
later updated with malicious code, and extensions that exfiltrate environment
variables or source code to remote servers. The MITRE ATT&CK framework
categorises several of these patterns explicitly:

- **T1195.001 - Supply Chain Compromise: Develop with Malicious Code** -
  an attacker contributes a legitimate-looking extension that carries a
  hidden payload, or takes over a popular extension after the original
  maintainer abandons it.
- **T1552.001 - Unsecured Credentials: Credentials in Files** - API keys,
  tokens, and passwords stored directly in `settings.json` are readable by
  any extension and by any process running as the same user.
- **T1071 - Application Layer Protocol** - extensions using HTTP (not HTTPS)
  MCP server endpoints, or connecting to remote SSH hosts over unencrypted
  channels, expose credentials and session data in transit.
- **T1059 - Command and Interpreter Scripting** - extensions that register
  high-risk API proposals gain the ability to execute arbitrary shell
  commands through experimental VS Code extension APIs.
- **T1190 - Exploit Public-Facing Application** - deprecated or unmaintained
  extensions that are no longer receiving security patches represent an
  unpatched attack surface inside the developer environment.

Beyond active threats, there are operational risks that are easy to overlook.
Extensions installed directly from `.vsix` files are not covered by
Marketplace update notifications, so they silently fall behind while the
maintained Marketplace version receives security fixes. Settings files
accumulate over time and frequently contain credentials left over from
previous projects. Remote SSH hosts configured in settings persist long after
the systems they pointed to have been decommissioned or repurposed.

This tool exists to give developers and security teams a repeatable,
automated way to surface these risks before they become incidents.

---

## Features

The tool covers two distinct audit domains: the extension installation itself
and the user settings that control VS Code's behaviour.

**Extension auditing** checks each installed extension against the Marketplace
to confirm it is current, not deprecated, and published by a verified
publisher. It queries OSV.dev and the GitHub Advisory Database for known
vulnerabilities in the extension's npm packages. It inspects the extension
manifest for high-risk `enabledApiProposals` entries that grant elevated
access to VS Code internals, and flags any extension that provides MCP server
definitions to connected AI tools. Extensions installed from `.vsix` files
rather than the Marketplace are flagged because they do not receive automatic
updates and cannot be verified against Marketplace security metadata.

**Settings auditing** walks the entire `settings.json` file recursively and
applies regex patterns to find values that look like API keys, bearer tokens,
AWS access keys, GitHub personal access tokens, and other credentials. It
documents every AI-related configuration key (Copilot, Claude, Continue,
OpenAI, Gitlens AI, and others) for review. It flags git settings that
silently bypass confirmation prompts, remote SSH hosts defined in the
settings, and any MCP server definition that uses an unencrypted `http://`
endpoint rather than `https://`.

Output is available in four formats: a colour-coded Rich terminal view
filtered by severity threshold, a JSON file suitable for ingestion by
dashboards or other tooling, a Markdown report for wikis and pull requests,
and a self-contained HTML report with a dark theme and no external
dependencies, intended for presentations.

---

## Requirements

- Python 3.10 or later
- Visual Studio Code with the `code` CLI available on `PATH`
- `curl` (required by the export script on Linux and macOS)
- Internet access for CVE and Marketplace lookups (optional - offline mode
  skips all network calls)

---

## Installation

```bash
git clone https://github.com/CraigWilsonOZ/VS-Code-Checker.git
cd VS-Code-Checker
bash setup.sh
source .venv/bin/activate
```

`setup.sh` creates a Python virtual environment under `.venv/` and installs
the five dependencies listed in `requirements.txt`. No system-level packages
are installed.

---

## Quick Start

```bash
source .venv/bin/activate

# Full scan - all checks, console + JSON + Markdown output
python main.py

# Offline scan - no network calls, completes in seconds
python main.py --no-cve --no-marketplace --no-github

# Only show findings at MEDIUM severity or above
python main.py --threshold MEDIUM

# Audit extensions only, skip settings
python main.py --scan extensions

# Audit settings only, skip extensions
python main.py --scan settings
```

Reports are written to `./reports/` as `.json` and `.md` files by default.
Use `--output-dir` to change the location.

---

## CLI Reference

```text
python main.py [OPTIONS]
```

| Option | Default | Description |
| --- | --- | --- |
| `--scan` | `full` | Scope: `full`, `extensions`, or `settings` |
| `--config PATH` | auto | Path to a `config.yaml` file |
| `--extensions-dir PATH` | auto | Override the extensions directory |
| `--settings-file PATH` | auto | Override the `settings.json` path |
| `--output-dir PATH` | `./reports` | Directory for report files |
| `--format LIST` | `console,json,markdown` | Comma-separated output formats |
| `--threshold LEVEL` | `INFO` | Minimum severity for console output |
| `--no-cve` | off | Skip CVE/vulnerability API lookups |
| `--no-marketplace` | off | Skip VS Code Marketplace queries |
| `--no-github` | off | Skip GitHub Advisory Database queries |
| `--github-token TOKEN` | env | GitHub token for higher rate limits |
| `--concurrency N` | `5` | Max concurrent API requests (1-50) |

### Severity Levels

Findings are assigned one of five severity levels, ordered from highest to
lowest: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

The `--threshold` flag controls which findings appear in the terminal output.
Setting it to `MEDIUM` hides LOW and INFO findings from the console view
while still writing the complete set to the JSON and Markdown reports. This
is useful in environments where the full inventory of INFO-level settings
creates visual noise, but you still need a complete record in the output
files.

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, no CRITICAL findings |
| `1` | Tool error (missing VS Code, bad config, etc.) |
| `2` | One or more CRITICAL findings found |

Exit code `2` allows CI pipelines to fail automatically when a critical
issue is detected, without needing to parse the output.

---

## Configuration

`config.yaml` is auto-discovered next to `main.py` - no flag required. Copy
the example file and adjust the values for your environment:

```bash
cp config.yaml.example config.yaml
```

| Setting | Default | Description |
| --- | --- | --- |
| `extensions_dir` | auto | Override extension directory path |
| `settings_file` | auto | Override `settings.json` path |
| `check_cves` | `true` | Query OSV.dev for npm vulnerabilities |
| `check_marketplace` | `true` | Query VS Code Marketplace API |
| `check_github_advisories` | `true` | Query GitHub Advisory Database |
| `max_concurrent_api_requests` | `5` | Parallel CVE API request limit |
| `api_timeout_seconds` | `10` | Per-request network timeout |
| `output_dir` | `./reports` | Report output directory |
| `severity_threshold` | `INFO` | Default console threshold |
| `stale_extension_days` | `180` | Days before flagging as stale |
| `github_token` | `null` | GitHub token (or `GITHUB_TOKEN` env var) |

Any setting can also be overridden with an environment variable prefixed
`VSCCHECK_`. For example, `VSCCHECK_OUTPUT_DIR=./out` takes effect without
modifying `config.yaml`. CLI flags take final precedence over both the config
file and environment variables.

---

## What Gets Checked

### Extensions

The extension audit runs a set of checks against every installed extension.
Network-bound checks (CVE lookups, Marketplace queries) run concurrently
via a thread pool to keep scan time reasonable even with 100+ extensions.

| Check | Severity | Description |
| --- | --- | --- |
| Outdated version | MEDIUM | Behind the latest stable Marketplace release |
| Stale extension | LOW | Not updated in the configured number of days |
| Deprecated | HIGH | Marked deprecated in the Marketplace |
| CVE / vulnerability | HIGH-CRITICAL | Found in OSV.dev or GitHub Advisory DB |
| Unverified publisher | LOW | Publisher has not verified domain ownership |
| AI / Chat extension | INFO | Categorised as AI or Chat tooling |
| High-risk API proposals | HIGH | Uses elevated experimental VS Code APIs |
| MCP server provider | MEDIUM | Contributes MCP server definitions |
| Non-gallery install | MEDIUM | Not installed from the VS Code Marketplace |

The CVE check queries OSV.dev using the npm package name and version. The
Marketplace check reads the `deprecated` flag and `publisher.isDomainVerified`
field directly from the Gallery API, so the verified publisher status
reflects the actual badge rather than a proxy metric like install count.

Extensions with `enabledApiProposals` entries are flagged at HIGH because
these experimental APIs grant capabilities not available to standard
extensions - including direct file system access patterns, terminal
interception, and workspace trust overrides. Proposals are evaluated against
a known list of high-risk identifiers.

### Settings

The settings audit is entirely local with no network calls. It walks the
full `settings.json` tree recursively and applies checks to every key-value
pair, not just a predefined subset.

| Check | Severity | Description |
| --- | --- | --- |
| Secrets detected | HIGH | Values matching API key or token patterns |
| AI configuration | INFO | Keys referencing AI tools |
| Trusted URIs | MEDIUM | Trusted workspace URIs and folder paths |
| Auto-fetch / smart commit | LOW-MEDIUM | Git settings that bypass prompts |
| Remote SSH hosts | MEDIUM-HIGH | Each host in `remote.SSH.remotePlatform` |
| HTTP MCP servers | HIGH | MCP servers using unencrypted `http://` URLs |

Secret values are redacted in the output - the finding shows the first three
and last three characters of the detected value (e.g. `sk-***key`) so the
finding is actionable without exposing the full credential in a report file.

Remote SSH hosts are classified MEDIUM if they resolve to a private IP range
and HIGH if they resolve to a public address, on the basis that a public
remote host represents a larger attack surface if the SSH key is compromised.

MCP servers configured with `http://` endpoints rather than `https://` are
flagged HIGH because these endpoints typically carry authentication tokens
and model context in plaintext. This maps to **MITRE T1071** - use of
standard application-layer protocols to transmit data in a way that may
evade inspection.

---

## Output Formats

### Console

The terminal output uses the Rich library to render colour-coded severity
badges, extension metadata cards (publisher, install count, star rating,
last updated date, and a link to the repository), and an action summary
table at the end of the scan. The summary groups extensions by issue type -
outdated, stale, deprecated, flagged API proposals, and so on - and lists
the affected extension IDs so they can be acted on directly.

### JSON

A structured JSON file is written to the `--output-dir` with a timestamped
filename. It contains the full finding set regardless of the `--threshold`
setting, making it suitable for feeding into a SIEM, a dashboard, or a
script that takes automated action on specific finding types.

### Markdown

A human-readable Markdown report with the same content as the JSON output.
Intended for pasting into a wiki, attaching to a pull request, or committing
alongside the `settings.json` as a record of the audit.

### HTML

A self-contained HTML file with inline CSS and no external dependencies.
The dark theme is designed to be readable in presentations. The file can be
attached to an email, dropped into a shared drive, or opened directly in a
browser without a web server.

```bash
python main.py --format html
python main.py --format console,json,markdown,html
```

---

## Extension Management Scripts

Three companion scripts handle the operational side of managing extensions
across machines or after a fresh OS install.

### Export extensions for offline use

The export script reads your VS Code extensions catalog, downloads every
installed extension as a `.vsix` file from the Marketplace, and generates
two installer scripts in the output directory. For extensions that have
platform-specific builds (native binaries compiled for `linux-x64`,
`darwin-arm64`, `win32-x64`, etc.), both the universal and the
platform-specific build are downloaded so the archive works on any target.

```bash
# Linux / macOS
bash scripts/export-extensions.sh
bash scripts/export-extensions.sh ./my-backup

# Windows (PowerShell)
.\scripts\export-extensions.ps1
.\scripts\export-extensions.ps1 -OutputDir .\my-backup
```

Already-downloaded files are validated by checking the zip magic bytes
(`PK\x03\x04`) and skipped if valid, so re-running the script after an
interruption is safe and only fetches what is missing.

The output directory contains:

| File | Purpose |
| --- | --- |
| `vsix/` | One `.vsix` per extension (universal + platform builds) |
| `install.sh` / `install.ps1` | Offline installer, no internet required |
| `install-from-marketplace.sh` / `.ps1` | Online installer, resets source |

### Install from the Marketplace (reset install source)

When extensions are installed from `.vsix` files, VS Code records
`install_source='vsix'` in its extensions catalog. This flag persists even
after a force-reinstall with `--force`, and it prevents automatic updates
from the Marketplace. The only way to reset it is to uninstall the extension
and reinstall it fresh from the gallery.

The `install-from-marketplace` scripts do exactly that. They iterate the
full extension list, uninstall each one, and immediately reinstall from
the Marketplace. Because the uninstall and reinstall happen in sequence for
each extension, the window where any given extension is absent is brief.

> **Close VS Code before running this script.** Your settings, keybindings,
> and workspace configuration are stored separately from the extension
> directories and will not be affected.

```bash
# Linux / macOS
bash vscode-extensions-export/install-from-marketplace.sh

# Windows (PowerShell)
.\vscode-extensions-export\install-from-marketplace.ps1
```

### Update all extensions

A simpler script that calls `code --install-extension <id> --force` for
every installed extension. This updates each extension to the current
Marketplace version without changing the install source. Useful as a
regular maintenance script, though it will not reset `install_source='vsix'`
for extensions that were installed from files.

```bash
# Linux / macOS
bash scripts/update-extensions.sh

# Windows (PowerShell)
.\scripts\update-extensions.ps1
```

---

## API Sources

The tool queries three external sources for vulnerability and metadata
information. All queries are read-only and unauthenticated by default.

| Source | Auth | Rate Limit |
| --- | --- | --- |
| [OSV.dev](https://osv.dev) | None | Generous |
| [VS Code Marketplace](https://marketplace.visualstudio.com) | None | Generous |
| [GitHub Advisory DB](https://github.com/advisories) | Optional token | 60/hr anon, 5000/hr auth |

OSV.dev covers vulnerabilities in npm packages (the runtime environment for
VS Code extensions) and is free to query without authentication. The GitHub
Advisory Database provides additional coverage and supports a personal access
token for higher rate limits - useful when scanning a large number of
extensions. The token can be provided via the `--github-token` flag or the
`GITHUB_TOKEN` environment variable; a CI environment with a default GitHub
Actions token has the 5000/hr limit automatically.

All three clients catch network errors and return gracefully. A failed query
produces a warning in the output but does not abort the scan or cause the
tool to exit with an error code.

---

## MITRE ATT&CK Coverage

The checks in this tool map to the following ATT&CK techniques, which can
be used to contextualise findings in a threat model or security report.

| Technique | ID | Addressed by |
| --- | --- | --- |
| Supply Chain Compromise | T1195.001 | Deprecated, unverified publisher, CVE |
| Unsecured Credentials | T1552.001 | Secrets detection in settings |
| Application Layer Protocol | T1071 | HTTP MCP server check |
| Command and Interpreter | T1059 | High-risk API proposals check |
| Exploit Public-Facing App | T1190 | Stale and outdated version checks |
| Valid Accounts | T1078 | Remote SSH host documentation |

---

## Running in CI

```yaml
# GitHub Actions example
- name: VS Code security audit
  run: |
    bash setup.sh
    source .venv/bin/activate
    python main.py --no-github --threshold HIGH --format json
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The tool exits with code `2` if any CRITICAL finding is found, which causes
the workflow step to fail. Combine with `--threshold HIGH` to fail on HIGH
findings as well. The JSON output file is available as an artifact for
downstream processing or retention.

---

## Directory Structure

```text
VS-Code-Checker/
├── main.py               # CLI entry point
├── setup.sh              # creates .venv and installs dependencies
├── requirements.txt
├── config.yaml.example   # documented example - copy to config.yaml
├── config.yaml           # your local config (gitignored)
├── scripts/
│   ├── export-extensions.sh    # export as .vsix (Linux/macOS)
│   ├── export-extensions.ps1   # export as .vsix (Windows)
│   ├── update-extensions.sh    # update from Marketplace (Linux/macOS)
│   └── update-extensions.ps1   # update from Marketplace (Windows)
├── src/
│   ├── platform/         # OS path detection (Linux + Windows stub)
│   ├── config/           # AppConfig dataclass and YAML/env loading
│   ├── discovery/        # filesystem readers (extensions, settings)
│   ├── audit/
│   │   ├── checks/       # individual check implementations
│   │   └── vuln_apis/    # CVE and Marketplace API clients
│   ├── models/           # Finding, ExtensionInfo, Report dataclasses
│   └── report/           # console, JSON, Markdown, HTML renderers
└── reports/              # generated report files (gitignored)
```

---

## Architecture Overview

The tool is structured as five layers with a clear left-to-right data flow.

```text
Platform -> Config -> Discovery -> Audit -> Report
```

| Layer | Location | Responsibility |
| --- | --- | --- |
| Platform | `src/platform/` | Auto-detect VS Code paths per OS |
| Config | `src/config/settings.py` | Load chain: yaml -> env vars -> CLI |
| Discovery | `src/discovery/` | Read filesystem only, no analysis |
| Audit | `src/audit/` | Orchestrate checks, network via thread pool |
| Report | `src/report/` | Four renderers, one `Report` object |

The platform layer is the only place that knows about operating system paths.
Everything downstream receives a `VSCodePaths` dataclass and treats paths as
opaque strings. This makes it straightforward to add a new platform or to
override paths for testing without touching audit or report logic.

The discovery layer reads the filesystem and returns data structures. It does
not apply any judgement or analysis. This keeps the parsers simple and makes
it easy to test them in isolation with fixture files.

The audit layer owns all the business logic. Checks are implemented as small
independent classes that each receive a single target (`ExtensionInfo` or
`scan_data`) and return a list of `Finding` objects. The orchestrators
(`ExtensionAuditor`, `SettingsAuditor`) decide which checks to run, handle
concurrency for network-bound checks, and aggregate the results into
`ReportSection` objects.

### Adding a Check

Create a new file in `src/audit/checks/` subclassing `BaseCheck`. The class
needs a `check_id` string and a `run(target)` method that returns
`list[Finding]`. For extension checks `target` is an `ExtensionInfo`
instance; for settings checks it is the `scan_data` dict returned by
`SettingsScanner`. Wire the new class into `ExtensionAuditor._local_checks`
or `SettingsAuditor._security_checks` depending on the target type.

### Adding a Vulnerability API Source

Create a new client in `src/audit/vuln_apis/` subclassing `BaseVulnAPI`.
Implement `query_extension(extension_id, package_name, version, repo_url)`
returning a `VulnResult`, and `is_available()` returning a bool. Add an
instance of the client to `ExtensionAuditor._build_network_checks()`. The
`CVECheck` class will pick it up automatically and include its results in the
deduplicated finding output.

---

## Windows Support

The Python audit tool is developed and tested on Linux. `WindowsPlatform` in
`src/platform/windows.py` provides the correct path resolution for Windows
(`%APPDATA%\Code\User\` and `%USERPROFILE%\.vscode\extensions`) but has not
been verified on a real Windows system. The PowerShell scripts in `scripts/`
are fully functional on Windows and are the recommended tooling for
extension export and update operations on that platform.

---

## Dependencies

| Package | Purpose |
| --- | --- |
| `requests` | HTTP client for Marketplace and CVE API calls |
| `rich` | Terminal colour output and table formatting |
| `click` | CLI argument and option parsing |
| `pyyaml` | Loading and parsing `config.yaml` |
| `packaging` | Version string comparison for currency checks |
