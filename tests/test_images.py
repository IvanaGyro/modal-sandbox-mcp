"""Pure unit tests for Sandbox Image selection (no Modal credentials needed)."""
import unittest
from unittest.mock import MagicMock

from sandbox_images import resolve_sandbox_image


class SandboxImageTests(unittest.TestCase):
    def setUp(self):
        self.modal = MagicMock()
        self.default = object()

    def select(self, ref=None, source="registry", add_python=None):
        return resolve_sandbox_image(self.modal, self.default, ref, source, add_python)

    def test_default_image_remains_unchanged(self):
        image, meta = self.select()
        self.assertIs(image, self.default)
        self.assertEqual(meta["image_source"], "default")
        self.modal.Image.from_registry.assert_not_called()

    def test_public_registry_image(self):
        image, meta = self.select("python:3.12-slim-bookworm")
        self.modal.Image.from_registry.assert_called_once_with(
            "python:3.12-slim-bookworm"
        )
        self.assertEqual(meta["image_ref"], "python:3.12-slim-bookworm")

    def test_registry_digest_and_python_bootstrap(self):
        self.select("ubuntu:22.04", add_python="3.12")
        self.modal.Image.from_registry.assert_called_once_with(
            "ubuntu:22.04", add_python="3.12"
        )
        self.modal.reset_mock()
        self.select("docker.io/library/python@sha256:" + "a" * 64)
        self.modal.Image.from_registry.assert_called_once()

    def test_published_modal_image(self):
        _, meta = self.select("cytnx-build:v1", source="modal_name")
        self.modal.Image.from_name.assert_called_once_with("cytnx-build:v1")
        self.assertEqual(meta["image_source"], "modal_name")

    def test_modal_image_id(self):
        _, meta = self.select("im-ABC123", source="modal_id")
        self.modal.Image.from_id.assert_called_once_with("im-ABC123")
        self.assertEqual(meta["image_source"], "modal_id")

    def test_reject_shell_injection_and_credentials(self):
        for ref in [
            "", "python:latest;rm -rf /", "https://registry.example/image:tag",
            "python:latest\nname", "user:secret@host/image", "x" * 256,
            "image:latest?token=secret", "python:latest $(id)",
        ]:
            with self.subTest(ref=repr(ref)), self.assertRaises(ValueError):
                self.select(ref)

    def test_reject_invalid_source_and_combinations(self):
        with self.assertRaises(ValueError):
            self.select("ubuntu:22.04", source="local-dockerfile")
        with self.assertRaises(ValueError):
            self.select(source="modal_name")
        with self.assertRaises(ValueError):
            self.select(add_python="3.12")
        with self.assertRaises(ValueError):
            self.select("example:v1", source="modal_name", add_python="3.12")
        with self.assertRaises(ValueError):
            self.select("ubuntu:22.04", add_python="3.12;echo X")
        with self.assertRaises(ValueError):
            self.select("im-/", source="modal_id")


if __name__ == "__main__":
    unittest.main()
