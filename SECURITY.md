# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly. Do not open a public GitHub issue for security vulnerabilities.

**Email:** Send details to the project maintainers via the contact
information in their GitHub profiles.

**What to include:**

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue.
- The version of the tool and your operating system.
- Any relevant configuration or environment details.

**What to expect:**

- An acknowledgement within 30 days.
- An assessment of the vulnerability and a plan for remediation.
- Credit in the changelog and release notes unless you prefer to remain
  anonymous.

## Supported Versions

Only the latest release on `main` is actively maintained. If you are
running an older version, please update before reporting.

## Scope

This policy covers the VS Code Security Checker tool itself - the Python
source code, shell scripts, and PowerShell scripts in this repository.

It does not cover:

- The VS Code Marketplace, OSV.dev, or GitHub Advisory APIs that the
  tool queries. Report vulnerabilities in those services to their
  respective maintainers.
- VS Code extensions flagged by this tool. Report vulnerabilities in
  specific extensions to their publishers.
- Your local VS Code installation or settings. This tool reads but does
  not modify your VS Code environment.

## Security Practices in This Project

- All external API calls use HTTPS. No plaintext HTTP endpoints.
- Secrets detected in settings are redacted before being written to any
  report output.
- No user credentials or tokens are logged, stored, or transmitted by
  the tool except when explicitly provided for GitHub API authentication.
- CLI inputs are validated for type, range, and path existence.
- Shell scripts validate extension IDs and platform strings against
  known-good patterns before use.
- Downloads are written atomically (to a temporary file, then moved)
  and validated against zip magic bytes before being accepted.
