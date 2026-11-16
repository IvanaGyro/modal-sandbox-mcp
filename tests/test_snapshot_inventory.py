"""Credential-free tests for persistent Exit Snapshot inventory."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock

from snapshot_inventory import read_record, write_record, list_records, inspect_exit_snapshot


class InventoryTests(unittest.TestCase):
    def test_create_update_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_record("sb-ABC123", directory=directory, status="running")
            write_record("sb-ABC123", directory=directory, status="ready", image_id="im-snap")
            record = read_record("sb-ABC123", directory=directory)
            self.assertEqual(record["status"], "ready")
            self.assertEqual(record["image_id"], "im-snap")
            self.assertEqual(len(list_records(directory=directory)), 1)

    def test_reject_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad_id in ("../hack", "sb-../../hack", "im-snapshot", "sb-??"):
                with self.subTest(bad_id=bad_id):
                    with self.assertRaises(ValueError):
                        write_record(bad_id, directory=Path(tmp), status="running")

    def test_running_does_not_fetch_snapshot(self):
        sandbox = Mock()
        sandbox.poll.return_value = None
        self.assertEqual(inspect_exit_snapshot(sandbox)["status"], "running")
        sandbox._experimental_get_exit_snapshot.assert_not_called()

    def test_ready_and_pending(self):
        sandbox = Mock()
        sandbox.poll.return_value = 0
        sandbox._experimental_get_exit_snapshot.return_value = Mock(object_id="im-good")
        self.assertEqual(inspect_exit_snapshot(sandbox), {"status": "ready", "image_id": "im-good"})
        sandbox._experimental_get_exit_snapshot.assert_called_with(timeout=0)

        # Mirror the Modal exception's class name, not Python's builtin TimeoutError.
        ModalTimeout = type("TimeoutError", (Exception,), {})
        sandbox._experimental_get_exit_snapshot.side_effect = ModalTimeout("not ready")
        self.assertEqual(inspect_exit_snapshot(sandbox)["status"], "pending")

    def test_error_is_not_reported_as_ready(self):
        sandbox = Mock()
        sandbox.poll.return_value = 1
        sandbox._experimental_get_exit_snapshot.side_effect = RuntimeError("snapshot failed")
        self.assertEqual(inspect_exit_snapshot(sandbox)["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
