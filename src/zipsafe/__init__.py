"""ZipSafe public Python API."""

from .scanner import Finding, ScanResult, scan_archive

__all__ = ["Finding", "ScanResult", "scan_archive"]
