"""Deterministic tests of automatic path reading without Modal credentials."""
import unittest
from unittest.mock import Mock

from path_reader import INLINE_TEXT_LIMIT, inspect_path


class PathReaderTests(unittest.TestCase):
    def file(self, size, payload=None, kind="FileType.FILE"):
        fs = Mock()
        fs.stat.return_value = Mock(type=kind, size=size)
        if payload is not None:
            fs.read_bytes.return_value = payload
        return fs

    def test_short_utf8_inlined(self):
        data = "繁體中文🌈".encode("utf-8")
        fs = self.file(len(data), data)
        result = inspect_path(fs, "/tmp/test.txt")
        self.assertEqual(result["delivery"], "inline")
        self.assertEqual(result["content"], "繁體中文🌈")
        self.assertEqual(result["size_bytes"], len(data))

    def test_empty_file_inlined(self):
        fs = self.file(0, b"")
        result = inspect_path(fs, "/tmp/empty")
        self.assertEqual(result["content"], "")
        self.assertEqual(result["delivery"], "inline")

    def test_boundary_inlined(self):
        fs = self.file(INLINE_TEXT_LIMIT, b"x" * INLINE_TEXT_LIMIT)
        self.assertEqual(inspect_path(fs, "/tmp/test")["delivery"], "inline")

    def test_large_file_stays_out_of_mcp(self):
        fs = self.file(INLINE_TEXT_LIMIT + 1)
        result = inspect_path(fs, "/tmp/test")
        self.assertEqual(result["delivery"], "download")
        self.assertEqual(result["kind"], "file")
        fs.read_bytes.assert_not_called()

    def test_invalid_utf8_returns_download(self):
        fs = self.file(3, b"\xff\x00\xfe")
        self.assertEqual(inspect_path(fs, "/tmp/binary")["delivery"], "download")

    def test_control_data_returns_download(self):
        fs = self.file(4, b"a\x00b\x01")
        self.assertEqual(inspect_path(fs, "/tmp/binary")["delivery"], "download")

    def test_newline_tab_valid_text(self):
        fs = self.file(5, b"a\nb\tc")
        self.assertEqual(inspect_path(fs, "/tmp/code")["delivery"], "inline")

    def test_growing_file_returns_download(self):
        fs = self.file(4, b"a" * (INLINE_TEXT_LIMIT + 10))
        result = inspect_path(fs, "/tmp/growing")
        self.assertEqual(result["delivery"], "download")
        self.assertGreater(result["size_bytes"], INLINE_TEXT_LIMIT)

    def test_directory_always_zip(self):
        fs = self.file(0, kind="FileType.DIRECTORY")
        result = inspect_path(fs, "/tmp/folder")
        self.assertEqual(result["delivery"], "download")
        self.assertEqual(result["format"], "zip")
        fs.read_bytes.assert_not_called()

    def test_symlinks_not_read(self):
        fs = self.file(9, kind="FileType.SYMLINK")
        with self.assertRaises(ValueError):
            inspect_path(fs, "/tmp/link")

    def test_no_offset_api(self):
        with self.assertRaises(TypeError):
            inspect_path(self.file(0, b""), "/tmp/test", offset=12)


if __name__ == "__main__":
    unittest.main()
