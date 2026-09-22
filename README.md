# ZIP File Safety Check

Two small command-line checks for ZIP archives:

- `check_zip.py` performs a structural inspection for path traversal (Zip Slip)
  and commonly executable/script file extensions.
- `scan_zip.sh` runs ClamAV against the archive contents for malware signatures.

These checks reduce common risks but do not prove that an archive is safe. Do
not extract an untrusted archive until you have reviewed the findings and
trust its source.

## Requirements

- Python 3.10 or newer for `check_zip.py`
- ClamAV (`clamscan` and `freshclam`) for `scan_zip.sh`

On macOS with Homebrew:

```sh
brew install clamav
```

## Usage

```sh
python3 check_zip.py path/to/archive.zip
./scan_zip.sh path/to/archive.zip
```

Both commands return exit status `0` when their check succeeds and a non-zero
status when the input is invalid or a finding/error is reported. `scan_zip.sh`
continues with the existing ClamAV database if `freshclam` cannot update it;
the scan's own status is still returned.

The structural checker is intentionally a heuristic. It does not replace
antivirus scanning, sandboxing, or careful review of archive contents.
