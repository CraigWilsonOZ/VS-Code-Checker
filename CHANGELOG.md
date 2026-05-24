# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-05-24

### Added

- Extension security audit with CVE lookups via OSV.dev and GitHub
  Advisory Database.
- Marketplace metadata checks: outdated versions, stale extensions,
  deprecated extensions, verified publisher status.
- AI extension and MCP server provider detection.
- High-risk `enabledApiProposals` flagging.
- Install source tracking (gallery vs. vsix vs. unknown).
- Settings security audit: secrets detection, AI configuration review,
  trusted URI inventory, remote SSH host flagging, HTTP MCP server
  detection.
- Full settings inventory at INFO severity.
- Four output formats: console (Rich), JSON, Markdown, HTML.
- Configurable severity threshold for console output.
- `config.yaml` auto-discovery with environment variable overrides.
- Linux platform support with auto-detection of VS Code and VS Code
  Insiders paths.
- Windows platform stub for future support.
- Extension export script (`scripts/export-extensions.sh` and `.ps1`)
  with platform-specific and universal vsix downloads.
- Marketplace reinstall script (`install-from-marketplace.sh` and `.ps1`)
  for resetting `install_source` to gallery.
- Extension update script (`scripts/update-extensions.sh` and `.ps1`).
- MITRE ATT&CK technique mapping in documentation.
- SBOM with dependency and licence inventory.
- Input validation on all CLI arguments (path existence, integer ranges,
  format names).
- Platform and extension ID validation in shell scripts.
- Atomic downloads with zip magic byte verification.
- Secrets redaction in all report output.
- Exit code 2 for CI integration when CRITICAL findings are present.
