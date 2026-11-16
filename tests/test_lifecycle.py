"""Zero-credential tests for cost-based idle TTL and Exit Snapshot cleanup."""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from sandbox_lifecycle import (
    CPU_CORE_USD_PER_SECOND, IDLE_BUDGET_USD, DEFAULT_LIFETIME_SECONDS,
    delete_exit_snapshot_of, idle_budget_for, managed_tags, restored_settings,
)


class IdlePricingTests(unittest.TestCase):
    def test_two_core_hours_budget(self):
        self.assertEqual(str(IDLE_BUDGET_USD), "0.283824")
        self.assertEqual(CPU_CORE_USD_PER_SECOND * 7200, IDLE_BUDGET_USD)

    def test_default_1core_1gib(self):
        policy = idle_budget_for(1.0, 1024, DEFAULT_LIFETIME_SECONDS)
        self.assertEqual(policy["idle_seconds"], 6158)
        self.assertFalse(policy["idle_capped_by_lifetime"])
        self.assertLessEqual(policy["estimated_idle_cost_usd"], policy["idle_budget_usd"])
        self.assertTrue(policy["estimate_only"])

    def test_cpu_and_ram_scale_idle_budget(self):
        low = idle_budget_for(0.125, 128, 86400)
        standard = idle_budget_for(1, 1024, 86400)
        high = idle_budget_for(2, 4096, 86400)
        self.assertGreater(low["idle_seconds"], standard["idle_seconds"])
        self.assertGreater(standard["idle_seconds"], high["idle_seconds"])
        for policy in (low, standard, high):
            self.assertLessEqual(policy["estimated_idle_cost_usd"], 0.283824 + 0.000001)

    def test_lifetime_cap_is_reported(self):
        policy = idle_budget_for(1, 1024, 90)
        self.assertEqual(policy["calculated_idle_seconds"], 6158)
        self.assertEqual(policy["idle_seconds"], 90)
        self.assertTrue(policy["idle_capped_by_lifetime"])

    def test_invalid_resource_limits_rejected(self):
        for cpu, memory, seconds in (
            (0, 1024, 300), (3, 1024, 300),
            (1, 127, 300), (1, 8192, 300),
            (1, 1024, 59), (1, 1024, 86401),
        ):
            with self.subTest(cpu=cpu, memory=memory, seconds=seconds):
                with self.assertRaises(ValueError):
                    idle_budget_for(cpu, memory, seconds)


class ExitSnapshotTests(unittest.TestCase):
    def test_managed_tags_round_trip(self):
        tags = managed_tags(0.5, 512, 14400, True)
        self.assertEqual(tags["mcp_exit_snapshot"], "1")
        self.assertEqual(restored_settings(tags), (0.5, 512, 14400, True))

    def test_foreign_sandbox_cannot_resume(self):
        with self.assertRaises(ValueError):
            restored_settings({"mcp_exit_snapshot": "1"})

    def test_successfully_deleted_reports_success(self):
        sb = Mock()
        sb.get_tags.return_value = {"mcp_exit_snapshot": "1"}
        sb._experimental_get_exit_snapshot.return_value = Mock(object_id="im-example123")
        api = Mock()
        result = delete_exit_snapshot_of(sb, api)
        api.experimental.image_delete.assert_called_once_with("im-example123")
        self.assertEqual(result["status"], "deleted")
        self.assertTrue(result["deleted"])

    def test_failed_snapshot_is_not_claimed_deleted(self):
        sb = Mock()
        sb.get_tags.return_value = {"mcp_exit_snapshot": "1"}
        sb._experimental_get_exit_snapshot.side_effect = RuntimeError("pending")
        api = Mock()
        result = delete_exit_snapshot_of(sb, api)
        self.assertFalse(result["deleted"])
        self.assertEqual(result["status"], "not_deleted")
        api.experimental.image_delete.assert_not_called()

    def test_failed_delete_is_not_claimed_deleted(self):
        sb = Mock()
        sb.get_tags.return_value = {"mcp_exit_snapshot": "1"}
        sb._experimental_get_exit_snapshot.return_value = Mock(object_id="im-example123")
        api = Mock()
        api.experimental.image_delete.side_effect = PermissionError("no permission")
        result = delete_exit_snapshot_of(sb, api)
        self.assertFalse(result["deleted"])
        self.assertEqual(result["status"], "not_deleted")

    def test_no_snapshot_on_legacy_sandbox(self):
        sb = Mock()
        sb.get_tags.return_value = {}
        api = Mock()
        result = delete_exit_snapshot_of(sb, api)
        self.assertEqual(result["status"], "not_enabled")
        sb._experimental_get_exit_snapshot.assert_not_called()
        api.experimental.image_delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
