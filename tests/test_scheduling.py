import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from appsec_scan_router.scheduling import ScanScheduler


class FakeScanManager:
    def __init__(self):
        self.started: list[dict] = []

    def normalize_config(self, config):
        return dict(config)

    def start_scan(self, config):
        self.started.append(dict(config))
        return SimpleNamespace(id=f"scan-{len(self.started)}")


class SchedulingTests(unittest.TestCase):
    def test_schedule_storage_is_encrypted_and_owner_scoped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = FakeScanManager()
            scheduler = ScanScheduler(manager, Path(tmpdir))
            run_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            schedule = scheduler.create_schedule(
                "Daily inventory",
                "daily",
                run_at,
                {"provider": "azure-devops", "adoOrgPats": [{"org": "Fabrikam", "pat": "secret-pat"}]},
                "user-1",
                "user@example.com",
            )

            encrypted = (Path(tmpdir) / "schedules.json.enc").read_bytes()
            own = scheduler.list_schedules("user-1")
            other = scheduler.list_schedules("user-2")

        self.assertNotIn(b"secret-pat", encrypted)
        self.assertEqual([item["id"] for item in own], [schedule.id])
        self.assertEqual(other, [])
        self.assertNotIn("config", own[0])

    def test_due_once_schedule_runs_and_disables_itself(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = FakeScanManager()
            scheduler = ScanScheduler(manager, Path(tmpdir))
            schedule = scheduler.create_schedule(
                "Immediate inventory",
                "once",
                datetime.now(timezone.utc).isoformat(),
                {"provider": "github-enterprise", "githubUrls": ["example"]},
                "user-1",
                "user@example.com",
            )
            scheduler.start()
            deadline = time.monotonic() + 2
            while not manager.started and time.monotonic() < deadline:
                time.sleep(0.01)
            scheduler.close()

            summary = scheduler.list_schedules("user-1")[0]

        self.assertEqual(len(manager.started), 1)
        self.assertFalse(summary["enabled"])
        self.assertEqual(summary["lastScanId"], "scan-1")
        self.assertEqual(summary["id"], schedule.id)

    def test_schedule_actions_enforce_owner_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = FakeScanManager()
            scheduler = ScanScheduler(manager, Path(tmpdir))
            schedule = scheduler.create_schedule(
                "Weekly inventory",
                "weekly",
                (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                {"provider": "azure-devops"},
                "user-1",
                "user@example.com",
            )

            self.assertIsNone(scheduler.set_enabled(schedule.id, "user-2", False))
            self.assertFalse(scheduler.delete_schedule(schedule.id, "user-2"))
            self.assertIsNotNone(scheduler.set_enabled(schedule.id, "user-1", False))
            self.assertTrue(scheduler.delete_schedule(schedule.id, "user-1"))


if __name__ == "__main__":
    unittest.main()
