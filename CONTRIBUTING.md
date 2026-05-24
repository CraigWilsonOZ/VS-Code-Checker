# Contributing to VS Code Security Checker

Thank you for your interest in contributing. This document explains how to
get involved and what to expect from the process.

## Getting Started

1. Fork the repository and clone your fork locally.
2. Run `bash setup.sh` to create the virtual environment.
3. Activate the environment with `source .venv/bin/activate`.
4. Run `python main.py --no-cve --no-marketplace --no-github` to confirm
   the tool works on your system.

## Reporting Bugs

Open a [GitHub Issue](../../issues/new?template=bug_report.md) with:

- The command you ran and the full error output.
- Your operating system and Python version (`python3 --version`).
- Whether you are using VS Code or VS Code Insiders.
- Any relevant settings from your `config.yaml` (redact tokens and paths).

## Suggesting Features

Open a [GitHub Issue](../../issues/new?template=feature_request.md) with a
clear description of the problem you are trying to solve and the behaviour
you would like to see. Include examples of the expected output if possible.

## Submitting Changes

1. Create a branch from `main` with a descriptive name
   (e.g. `fix/stale-check-threshold` or `feat/new-cve-source`).
2. Make your changes. Follow the existing code style - the project does not
   use a formatter or linter beyond what is already in place.
3. Test your changes by running the tool against a real VS Code installation.
   At minimum, run an offline scan and verify the output is correct.
4. Commit with a clear message describing what changed and why.
5. Open a pull request against `main`.

## What Makes a Good Pull Request

- **Small and focused.** One logical change per PR. A bug fix and a new
  feature should be separate PRs.
- **Tested.** Describe how you verified the change works in the PR
  description. Include sample output if relevant.
- **No unrelated changes.** Avoid reformatting code, renaming variables, or
  refactoring logic that is not related to the PR's purpose.

## Adding a New Check

The architecture is designed to make this straightforward. See the
"Adding a Check" section in `README.md` for the steps. The key points:

- Subclass `BaseCheck` in `src/audit/checks/`.
- Return `list[Finding]` from your `run()` method.
- Wire it into the appropriate auditor class.
- Do not add network calls to local checks. If your check needs network
  access, implement it as a `BaseVulnAPI` client instead.

## Adding a New Vulnerability API Source

See the "Adding a Vulnerability API Source" section in `README.md`. All
API clients must fail gracefully on network errors and respect the
configured timeout.

## Code Style

- No comments unless the "why" is non-obvious.
- No docstrings on internal methods.
- Use existing patterns as a guide - look at how similar code in the
  project handles the same problem before inventing a new approach.
- Australian English in documentation and user-facing strings.

## Licence

By contributing, you agree that your contributions will be licensed under
the same [MIT Licence](LICENSE) that covers the project.
