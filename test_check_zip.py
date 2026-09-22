import contextlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from check_zip import check_zip_safety


def write_zip(path: Path, member_name: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member_name, "content")


class CheckZipSafetyTests(unittest.TestCase):
    def run_check(self, archive: Path) -> tuple[bool, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = check_zip_safety(archive)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_safe_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "safe.zip"
            write_zip(archive, "documents/readme.txt")

            result, output, _ = self.run_check(archive)

        self.assertTrue(result)
        self.assertIn("structurally safe", output)

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.zip"
            write_zip(archive, r"nested\..\..\outside.txt")

            result, output, _ = self.run_check(archive)

        self.assertFalse(result)
        self.assertIn("Zip Slip", output)

    def test_rejects_executable_member(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.zip"
            write_zip(archive, "installer.EXE")

            result, output, _ = self.run_check(archive)

        self.assertFalse(result)
        self.assertIn("dangerous executable", output)

    def test_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _, error = self.run_check(Path(directory) / "missing.zip")

        self.assertFalse(result)
        self.assertIn("File not found", error)


if __name__ == "__main__":
    unittest.main()
