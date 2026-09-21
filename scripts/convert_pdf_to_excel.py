"""Run the converter directly from a checkout without installing the package."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root / "src"))
    from uet_student_converter.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
