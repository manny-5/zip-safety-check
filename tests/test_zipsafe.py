import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from zipsafe.scanner import scan_archive


def make_zip(path: Path, entries: dict[str, bytes], *, encrypted: str | None = None) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            info = zipfile.ZipInfo(name)
            if name == encrypted:
                info.flag_bits |= 1
            archive.writestr(info, content)


class ScannerTests(unittest.TestCase):
    def test_safe_and_json_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.zip"
            make_zip(path, {"readme.txt": b"hello"})
            result = scan_archive(path, antivirus="none")
            self.assertTrue(result.safe)
            self.assertEqual(result.findings, [])
            self.assertIn('"safe": true', json.dumps(result.as_dict()))

    def test_windows_absolute_and_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.zip"
            make_zip(path, {r"C:\temp\file.txt": b"x", "../../outside": b"x"})
            codes = {f.code for f in scan_archive(path, antivirus="none").findings}
            self.assertIn("path_traversal", codes)

    def test_entry_heuristics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.zip"
            make_zip(path, {"invoice.pdf.exe": b"MZ", "run.py": b"print(1)", "pic.png": b"not png"})
            codes = {f.code for f in scan_archive(path, antivirus="none").findings}
            self.assertTrue({"executable", "script", "disguised_file", "magic_mismatch"} <= codes)

    def test_encrypted_and_nested(self):
        nested_bytes = io.BytesIO()
        with zipfile.ZipFile(nested_bytes, "w") as nested:
            nested.writestr("../../nested-out", b"x")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested.zip"
            make_zip(path, {"inner.zip": nested_bytes.getvalue(), "secret.txt": b"x"},
                     encrypted="secret.txt")
            codes = {f.code for f in scan_archive(path, antivirus="none").findings}
            self.assertIn("nested_path_traversal", codes)

    def test_symlink_and_bomb_ratio(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.zip"
            info = zipfile.ZipInfo("link")
            info.external_attr = (0o120777 << 16) | 0xA000
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(info, b"target")
                archive.writestr("repeat.txt", b"x" * 100000)
            codes = {f.code for f in scan_archive(path, antivirus="none").findings}
            self.assertIn("symlink", codes)
            self.assertIn("archive_bomb_ratio", codes)

    def test_invalid_and_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIn("file_not_found", {f.code for f in scan_archive(root / "x.zip", antivirus="none").findings})
            bad = root / "bad.zip"
            bad.write_bytes(b"not zip")
            self.assertIn("invalid_zip", {f.code for f in scan_archive(bad, antivirus="none").findings})


if __name__ == "__main__":
    unittest.main()
