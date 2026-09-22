#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <path_to_zip>" >&2
    exit 2
fi

zip_file=$1
if [[ ! -f "$zip_file" ]]; then
    echo "[-] File not found: $zip_file" >&2
    exit 1
fi

if ! command -v clamscan >/dev/null 2>&1; then
    echo "[-] ClamAV is not installed. Install it with 'brew install clamav'." >&2
    exit 1
fi

echo "Updating virus definitions..."
if ! freshclam --quiet; then
    echo "[!] Could not update virus definitions; scanning with the existing database." >&2
fi

echo "Scanning $zip_file for malware..."
# clamscan can inspect archive contents; -- prevents a filename beginning with '-'
# from being interpreted as an option.
clamscan --recursive --infected -- "$zip_file"
