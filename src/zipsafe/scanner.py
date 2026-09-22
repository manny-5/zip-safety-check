"""ZIP inspection with bounded, explainable safety heuristics."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

EXECUTABLE_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".dll", ".exe", ".jar", ".js", ".msi",
    ".pif", ".ps1", ".scr", ".sh", ".vbe", ".vbs", ".wsf",
}
SCRIPT_EXTENSIONS = {".php", ".py", ".rb", ".pl", ".lua"}
MAGIC = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".pdf": (b"%PDF-",),
    ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
}
MAX_NESTED_DEPTH = 2
MAX_NESTED_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_UNCOMPRESSED = 1_000_000_000
MAX_RATIO = 100


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    entry: str | None = None


@dataclass
class ScanResult:
    path: str
    valid_zip: bool = False
    safe: bool = False
    findings: list[Finding] = field(default_factory=list)
    entries: list[dict[str, object]] = field(default_factory=list)
    antivirus: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["findings"] = [asdict(item) for item in self.findings]
        return result


def _unsafe_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return path.is_absolute() or ".." in path.parts or (
        len(normalized) >= 2 and normalized[1] == ":"
    )


def _add(result: ScanResult, code: str, severity: str, message: str,
         entry: str | None = None) -> None:
    result.findings.append(Finding(code, severity, message, entry))


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000


def _inspect_entries(archive: zipfile.ZipFile, result: ScanResult,
                     nested_depth: int) -> None:
    infos = archive.infolist()
    if len(infos) > MAX_ENTRIES:
        _add(result, "too_many_entries", "high",
             f"Archive contains {len(infos)} entries (limit {MAX_ENTRIES}).")
    total_uncompressed = sum(max(0, info.file_size) for info in infos)
    if total_uncompressed > MAX_UNCOMPRESSED:
        _add(result, "archive_bomb_size", "high",
             f"Uncompressed size exceeds {MAX_UNCOMPRESSED} bytes.")

    for info in infos:
        name = info.filename
        result.entries.append({
            "name": name, "directory": info.is_dir(), "compressed_size": info.compress_size,
            "uncompressed_size": info.file_size, "encrypted": bool(info.flag_bits & 1),
        })
        if _unsafe_name(name):
            _add(result, "path_traversal", "critical",
                 "Entry can escape the extraction directory.", name)
        if _is_symlink(info):
            _add(result, "symlink", "high", "Symbolic links are not extracted safely.", name)
        if info.flag_bits & 1:
            _add(result, "encrypted", "medium",
                 "Encrypted entries cannot be inspected reliably.", name)
        if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            _add(result, "archive_bomb_ratio", "high",
                 f"Compression ratio exceeds {MAX_RATIO}:1.", name)
        suffix = Path(name).suffix.lower()
        lower_name = name.lower()
        if suffix in EXECUTABLE_EXTENSIONS:
            _add(result, "executable", "high", "Executable or active script member.", name)
        elif suffix in SCRIPT_EXTENSIONS:
            _add(result, "script", "medium", "Script member may execute when opened.", name)
        if any(lower_name.endswith(ext + ".exe") or lower_name.endswith(ext + ".js")
               for ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png")):
            _add(result, "disguised_file", "high",
                 "Multiple extensions disguise an executable member.", name)
        if suffix in MAGIC and not info.is_dir() and info.file_size <= MAX_NESTED_BYTES:
            try:
                prefix = archive.read(info)[:16]
            except (OSError, RuntimeError, zipfile.BadZipFile):
                prefix = b""
            if prefix and not any(prefix.startswith(magic) for magic in MAGIC[suffix]):
                _add(result, "magic_mismatch", "medium",
                     f"Content does not match the expected {suffix} signature.", name)
        if suffix == ".zip" and nested_depth < MAX_NESTED_DEPTH and info.file_size <= MAX_NESTED_BYTES:
            try:
                nested = zipfile.ZipFile(io.BytesIO(archive.read(info)))
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            nested_result = ScanResult(result.path, valid_zip=True)
            _inspect_entries(nested, nested_result, nested_depth + 1)
            for finding in nested_result.findings:
                _add(result, "nested_" + finding.code, finding.severity,
                     "Nested archive: " + finding.message, f"{name}/{finding.entry or ''}".rstrip("/"))


def scan_archive(path: os.PathLike[str] | str, *, antivirus: str = "auto") -> ScanResult:
    """Scan *path* without extracting it. ``antivirus`` is auto, clamav, or none."""
    target = Path(path)
    result = ScanResult(str(target))
    if not target.is_file():
        _add(result, "file_not_found", "error", f"File not found: {target}")
        return result
    if not zipfile.is_zipfile(target):
        _add(result, "invalid_zip", "error", "Input is not a valid ZIP file.")
        return result
    try:
        with zipfile.ZipFile(target) as archive:
            result.valid_zip = True
            _inspect_entries(archive, result, 0)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        _add(result, "read_error", "error", f"Error reading ZIP: {error}")
        return result

    if antivirus != "none":
        clamscan = shutil.which("clamscan")
        if clamscan is None:
            result.antivirus = {"requested": antivirus, "available": False,
                                "status": "unavailable"}
            if antivirus == "clamav":
                _add(result, "antivirus_unavailable", "error",
                     "ClamAV requested but clamscan is not installed.")
        else:
            completed = subprocess.run(
                [clamscan, "--no-summary", "--infected", "--", str(target)],
                capture_output=True, text=True, check=False,
            )
            result.antivirus = {"requested": antivirus, "available": True,
                                "status": "clean" if completed.returncode == 0 else "detected",
                                "returncode": completed.returncode}
            if completed.returncode == 1:
                _add(result, "malware_detected", "critical", "ClamAV detected malware.")
            elif completed.returncode > 1:
                _add(result, "antivirus_error", "error", completed.stderr.strip() or
                     "ClamAV could not scan the archive.")
    result.safe = result.valid_zip and not result.findings
    return result


def result_json(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2, sort_keys=True)
