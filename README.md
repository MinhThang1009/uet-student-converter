<div align="center">

# UET Student Converter

Convert K70 student lists from PDF to Excel using the UET template.

</div>

## Contents

- [1. Overview](#1-overview)
- [2. Requirements](#2-requirements)
- [3. Installation](#3-installation)
- [4. Directory layout](#4-directory-layout)
- [5. Usage](#5-usage)
  - [5.1 Default paths](#51-default-paths)
  - [5.2 Custom paths](#52-custom-paths)
- [6. Validation](#6-validation)
- [7. Data handling](#7-data-handling)
- [8. Community](#8-community)
- [9. License](#9-license)

## 1. Overview

This project reads a K70 student list from the University of Engineering and
Technology PDF and creates an Excel workbook from the supplied template. It
preserves PDF order, assigns a continuous `STT`, creates accounts in the
`MSSV@vnu.edu.vn` form, creates `DDMMYYYY` passwords, and sets the default
status to `Hoạt động`.

The Vietnamese headers and status values in the generated workbook are part of
the output contract. Student data stays local and is ignored by `.gitignore`.

## 2. Requirements

- Windows, macOS, or Linux
- Python 3.11 or newer
- Runtime dependencies: `PyMuPDF` and `openpyxl`

## 3. Installation

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

On macOS/Linux, activate the virtual environment with:

```bash
source .venv/bin/activate
```

## 4. Directory layout

```text
.
├── data/
│   ├── input/       Source PDF and Excel template
│   ├── output/      Generated Excel workbooks
│   └── reports/     Optional run reports
├── scripts/         Direct local entry points
├── src/             Python package source
├── tests/            Automated tests
├── .venv/           Local virtual environment, never commit
├── pyproject.toml   Package, test, and lint configuration
└── requirements*.txt Dependency lists
```

## 5. Usage

### 5.1 Default paths

```powershell
python scripts\convert_pdf_to_excel.py
```

Or, after installing the package:

```powershell
uet-convert
```

The default input files are:

- `data/input/Danh sách sinh viên K70.pdf`
- `data/input/Danh sách sinh viên UET.xlsx`

The default output file is:

- `data/output/Danh sách sinh viên UET - chuyển đổi K70.xlsx`

### 5.2 Custom paths

```powershell
python scripts\convert_pdf_to_excel.py `
  --pdf data\input\Danh sách sinh viên K70.pdf `
  --template data\input\Danh sách sinh viên UET.xlsx `
  --output data\output\Danh sách sinh viên UET - chuyển đổi K70.xlsx
```

## 6. Validation

```powershell
python -m pytest
python -m compileall src scripts tests
ruff check src scripts/convert_pdf_to_excel.py tests
ruff format --check src scripts/convert_pdf_to_excel.py tests
python -m pip check
```

## 7. Data handling

- Do not modify the source PDF or Excel template.
- Recreate output files from inputs instead of manually patching generated data.
- Passwords are stored as text so a leading `0` is preserved.
- Do not commit data from `data/input/`, `data/output/`, or `data/reports/`.
- Do not place real student data, credentials, or secrets in tests or logs.

## 8. Community

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Pull request template](.github/PULL_REQUEST_TEMPLATE.md)
- [Issue forms](.github/ISSUE_TEMPLATE/)

The project now has a private GitHub remote. CI and documentation workflows run
on code changes, while scheduled community-health and freshness checks monitor
repository maintenance. Maintainer ownership and issue forms are configured.
Branch protection and a private security contact still need to be configured
before broader collaboration.

## 9. License

No distribution license has been selected. Add a `LICENSE` file before sharing
the project publicly.
