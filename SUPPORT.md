# Support

## How to Get Help

This project uses GitHub Issues for bug tracking and feature requests.

**Before opening an issue**, please:

1. Check the [README](README.md) for setup instructions and CLI reference.
2. Search [existing issues](../../issues) to see if your problem has
   already been reported.
3. Run the tool with `--no-cve --no-marketplace --no-github` to determine
   whether the issue is related to network calls or to local scanning.

## Opening an Issue

- **Bug reports:** Use the
  [bug report template](../../issues/new?template=bug_report.md).
  Include your OS, Python version, the command you ran, and the full
  error output.
- **Feature requests:** Use the
  [feature request template](../../issues/new?template=feature_request.md).
  Describe the problem you are trying to solve and the behaviour you
  would like to see.

## What This Project Does Not Cover

This tool audits your VS Code installation. It does not provide:

- General VS Code support. For VS Code issues, see
  [code.visualstudio.com](https://code.visualstudio.com/).
- Vulnerability remediation. The tool surfaces findings - acting on them
  is up to you.
- Extension development support. For extension authoring, see the
  [VS Code Extension API docs](https://code.visualstudio.com/api).
