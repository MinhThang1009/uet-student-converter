# Contributing to UET Student Converter

Thank you for contributing. This document describes local setup, validation,
and student-data handling requirements.

## Workflow

The repository uses a private GitHub remote. Use GitHub Flow:

1. Create a branch from `main`, for example `feat/improve-pdf-parser`.
2. Keep each branch and pull request focused on one objective.
3. Use Conventional Commits, for example `fix(parser): handle continuation pages`.
4. Describe the change, verification, risks, and rollback in the pull request.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

## Required checks

```powershell
python -m pytest
python -m compileall src scripts tests
ruff check src scripts tests
ruff format --check src scripts tests
python -m pip check
```

## Change rules

- Read the relevant code and tests before editing.
- Add a regression test for bug fixes when practical.
- Do not weaken tests, lint, or validation gates to hide failures.
- Do not commit PDFs, Excel workbooks, reports, or student data from `data/`.
- Do not commit credentials, tokens, `.env` files, or personal information.
- Keep documentation and CLI behavior synchronized.

## Pull requests

Use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md). The CI
workflow must pass before a pull request is merged. Before broader
collaboration, the maintainer should configure `CODEOWNERS`, a private security
channel, a license, and branch protection.

## Reporting issues

For normal bugs, provide minimal reproduction steps, the Python version, the
operating system, and logs with sensitive data removed. For security issues,
see [SECURITY.md](SECURITY.md) and do not publish exploit details.
