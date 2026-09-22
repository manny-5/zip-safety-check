#!/usr/bin/env python3
"""Inspect a ZIP archive for common extraction hazards."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import sys
import zipfile


DANGEROUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".dll",
    ".exe",
    ".jar",
    ".js",
    ".pif",
    ".scr",
    ".sh",
    ".vbs",
}


def _is_unsafe_member_name(name: str) -> bool:
    """Return whether a ZIP member can escape its extraction directory."""
    # ZIP member names use forward slashes, even on Windows.
    normalized_name = name.replace("\\", "/")
    path = PurePosixPath(normalized_name)
    return (
        path.is_absolute()
        or ".." in path.parts
        or (len(normalized_name) >= 2 and normalized_name[1] == ":")
    )


def check_zip_safety(filepath: os.PathLike[str] | str) -> bool:
    """Print findings for *filepath* and return True only when no findings exist."""
    path = Path(filepath)
    if not path.is_file():
        print(f"[-] File not found: {path}", file=sys.stderr)
        return False

    if not zipfile.is_zipfile(path):
        print(f"[-] {path} is not a valid ZIP file.", file=sys.stderr)
        return False

    is_safe = True
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if _is_unsafe_member_name(info.filename):
                    print(
                        f"[!] DANGER (Zip Slip): File attempts to extract outside "
                        f"directory -> {info.filename}"
                    )
                    is_safe = False

                if Path(info.filename).suffix.lower() in DANGEROUS_EXTENSIONS:
                    print(
                        f"[!] WARNING: Potentially dangerous executable found -> "
                        f"{info.filename}"
                    )
                    is_safe = False
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        print(f"[-] Error reading ZIP file: {error}", file=sys.stderr)
        return False

    if is_safe:
        print(f"[+] {path} structurally safe. No findings detected.")
    return is_safe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check a ZIP archive for path traversal and executable members."
    )
    parser.add_argument("zip_file", type=Path, help="path to the ZIP archive")
    args = parser.parse_args(argv)
    return 0 if check_zip_safety(args.zip_file) else 1


if __name__ == "__main__":
    raise SystemExit(main())
