"""Command-line interface for ZipSafe."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from pathlib import Path

from .scanner import scan_archive, result_json

EXIT_SAFE = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

EXPLANATIONS = {
    "path_traversal": "A member uses absolute paths, drive prefixes, or '..' components.",
    "executable": "Executable and active script extensions can run code when opened.",
    "script": "Script files can run code when opened or invoked.",
    "archive_bomb_size": "The declared uncompressed size is unusually large.",
    "archive_bomb_ratio": "A very high compression ratio can indicate a decompression bomb.",
    "too_many_entries": "A very high member count can exhaust filesystem resources.",
    "symlink": "Symlinks can redirect extraction outside the destination.",
    "encrypted": "Encrypted members cannot be inspected without their password.",
    "nested_archive_size": "Nested archives are bounded but may hide another payload.",
    "disguised_file": "Multiple extensions can hide an executable suffix.",
    "magic_mismatch": "The content header does not match the filename type.",
    "antivirus_unavailable": "ClamAV was explicitly requested but is unavailable.",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zipsafe", description="Inspect ZIP archives safely.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan an archive for safety findings")
    scan.add_argument("archive", type=Path)
    scan.add_argument("--json", action="store_true", help="emit stable JSON")
    scan.add_argument("--no-antivirus", action="store_true", help="skip ClamAV")
    scan.add_argument("--antivirus", action="store_true", help="require ClamAV if available")
    listing = sub.add_parser("list", help="list archive members")
    listing.add_argument("archive", type=Path)
    listing.add_argument("--json", action="store_true")
    explain = sub.add_parser("explain", help="explain finding codes")
    explain.add_argument("codes", nargs="*")
    extract = sub.add_parser("extract", help="extract only an archive with no findings")
    extract.add_argument("archive", type=Path)
    extract.add_argument("destination", type=Path)
    extract.add_argument("--no-antivirus", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "explain":
        codes = args.codes or sorted(EXPLANATIONS)
        unknown = [code for code in codes if code not in EXPLANATIONS]
        if unknown:
            print(json.dumps({"unknown": unknown}), file=sys.stderr)
            return EXIT_USAGE
        print(json.dumps({code: EXPLANATIONS[code] for code in codes}, indent=2, sort_keys=True))
        return EXIT_SAFE
    if args.command == "list":
        result = scan_archive(args.archive, antivirus="none")
        if not result.valid_zip:
            print(result_json(result) if args.json else result.findings[0].message, file=sys.stderr)
            return EXIT_ERROR
        output = result.entries
        print(json.dumps(output, indent=2) if args.json else
              "\n".join(str(item["name"]) for item in output))
        return EXIT_SAFE
    antivirus = "none" if getattr(args, "no_antivirus", False) else (
        "clamav" if getattr(args, "antivirus", False) else "auto")
    result = scan_archive(args.archive, antivirus=antivirus)
    if args.command == "extract":
        if not result.safe:
            print(result_json(result), file=sys.stderr)
            return EXIT_FINDINGS
        try:
            with zipfile.ZipFile(args.archive) as archive:
                archive.extractall(args.destination)
        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
            print(f"Extraction failed: {error}", file=sys.stderr)
            return EXIT_ERROR
        return EXIT_SAFE
    print(result_json(result) if args.json else
          (f"SAFE: {args.archive}" if result.safe else
           "\n".join(f"{item.code}: {item.message}" for item in result.findings)))
    return EXIT_SAFE if result.safe else (
        EXIT_ERROR if any(item.severity == "error" for item in result.findings) else EXIT_FINDINGS
    )
