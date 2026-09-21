"""Command-line interface for UET Student Converter."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .converter import convert_pdf_to_excel


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    root = _project_root()
    parser = argparse.ArgumentParser(
        description="Convert UET student lists from PDF to Excel using the template."
    )
    parser.add_argument(
        "--pdf",
        type=Path,
        default=root / "data" / "input" / "Danh sách sinh viên K70.pdf",
        help="Source PDF path.",
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=root / "data" / "input" / "Danh sách sinh viên UET.xlsx",
        help="Excel template path.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data" / "output" / "Danh sách sinh viên UET - chuyển đổi K70.xlsx",
        help="Output Excel path.",
    )
    return parser


def _configure_utf8_output() -> None:
    """Prefer UTF-8 so help and Vietnamese data paths work on Windows."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (OSError, ValueError):
                pass


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface."""

    _configure_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        count = convert_pdf_to_excel(args.pdf, args.template, args.output)
    except (FileNotFoundError, ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"Converted {count} records to: {args.output}")
    return 0
