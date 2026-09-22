#!/usr/bin/env python3
"""Backward-compatible wrapper for the ZipSafe scanner."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import sys

try:
    from zipsafe.scanner import scan_archive
except ModuleNotFoundError:  # Keep the historical script runnable from a checkout.
    sys.path.insert(0, str(Path(__file__).with_name("src")))
    from zipsafe.scanner import scan_archive


def check_zip_safety(filepath: os.PathLike[str] | str) -> bool:
    """Print findings for *filepath* and return True only when no findings exist."""
    path = Path(filepath)
    result = scan_archive(filepath, antivirus="none")
    if not result.valid_zip:
        print(result.findings[0].message, file=sys.stderr)
        return False
    for finding in result.findings:
        label = "Zip Slip" if finding.code == "path_traversal" else (
            "WARNING: Potentially dangerous executable found"
            if finding.code == "executable" else finding.code
        )
        print(f"[!] {label}: {finding.entry or finding.message}")
    if result.safe:
        print(f"[+] {path} structurally safe. No findings detected.")
    return result.safe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check a ZIP archive for path traversal and executable members."
    )
    parser.add_argument("zip_file", type=Path, help="path to the ZIP archive")
    args = parser.parse_args(argv)
    return 0 if check_zip_safety(args.zip_file) else 1


if __name__ == "__main__":
    raise SystemExit(main())
