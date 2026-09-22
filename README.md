# ZipSafe

ZipSafe is a Python CLI for reviewing ZIP archives
before extraction. It detects path traversal,
symlinks, encrypted entries, executable and script members, disguised names,
magic-byte mismatches, nested archives, and conservative archive-bomb signals.
It never extracts during a scan.

## Install and use

Requires Python 3.10+:

```sh
python -m venv .venv
. .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install .
zipsafe scan --no-antivirus archive.zip
zipsafe scan --json --no-antivirus archive.zip
zipsafe list archive.zip
zipsafe explain path_traversal encrypted
zipsafe extract --no-antivirus archive.zip destination
```

Exit codes: `0` means no findings, `1` means safety findings,
`2` means invalid command or finding code, and `3` means an invalid archive or
operational error. `extract` refuses every archive with a finding and is
intended only for archives that have been reviewed.

ClamAV is used automatically when `clamscan` is on `PATH`; use
`--no-antivirus` for deterministic offline operation or `--antivirus` to make
missing ClamAV an error. ZipSafe does not download virus definitions.

The checks are heuristics, not a proof of safety. ZIP metadata can be
malformed, new file formats can be disguised, and antivirus coverage depends
on the installed ClamAV database. The nested scan is bounded to two levels and
16 MiB per nested archive. Do not open untrusted files solely because ZipSafe
reports no findings.

The original `check_zip.py` and `scan_zip.sh` remain for compatibility.
