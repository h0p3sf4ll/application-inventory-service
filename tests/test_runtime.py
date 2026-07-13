import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from appsec_scan_router.constants import (
    APPLICATION_CLASSIFICATION_FIELDNAMES,
    INVENTORY_FIELDNAMES,
    MOBILE_FIELDNAMES,
)
from appsec_scan_router.postgres import EXPORT_COLUMNS
from appsec_scan_router.runtime import ScanManager, ScanRun
from appsec_scan_router.scanner import collect_targets


class RuntimeTests(unittest.TestCase):
    def test_scan_run_tracks_metrics_without_rescanning_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run = ScanRun("scan-1", {}, (), (), Path(tmpdir))
            for index in range(5100):
                run.append_log(f"line {index}")
            run.append_log('SCAN_PROGRESS {"repositoriesPrepared":10,"repositoriesTotal":20,"branchesScanned":7,"branchesTotal":12}')
            run.append_log("DETECTED asset=Payments branch=main")

            summary = run.summary()

        self.assertEqual(len(run.logs), 5000)
        self.assertEqual(len(summary["logsTail"]), 300)
        self.assertEqual(summary["detectedCount"], 1)
        self.assertEqual(summary["progress"]["repositoriesPrepared"], 10)
        self.assertEqual(summary["progress"]["branchesScanned"], 7)

    def test_scan_manager_pauses_and_resumes_running_process(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScanManager(Path(tmpdir), dict, lambda config, path: [], lambda config: {}, list)
            process = Mock()
            process.poll.return_value = None
            run = ScanRun("scan-1", {"ownerUserId": "user-1"}, (), (), Path(tmpdir), status="running", process=process)
            manager.scans[run.id] = run

            with patch("appsec_scan_router.runtime.pause_process") as pause, patch("appsec_scan_router.runtime.resume_process") as resume:
                manager.pause_scan(run.id)
                self.assertEqual(run.status, "paused")
                pause.assert_called_once_with(process)
                manager.resume_scan(run.id)
                self.assertEqual(run.status, "running")
                resume.assert_called_once_with(process)

    @unittest.skipUnless(os.name == "posix", "Process pause and resume require POSIX signals.")
    def test_scan_manager_controls_a_real_process_group(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScanManager(
                Path(tmpdir),
                dict,
                lambda config, path: [
                    sys.executable,
                    "-c",
                    "import time; print('ready', flush=True); time.sleep(30)",
                ],
                lambda config: dict(os.environ),
                list,
            )
            run = manager.start_scan({"ownerUserId": "user-1"})
            deadline = time.monotonic() + 3
            while (run.process is None or not run.logs) and time.monotonic() < deadline:
                time.sleep(0.01)

            manager.pause_scan(run.id)
            self.assertEqual(run.status, "paused")
            manager.resume_scan(run.id)
            self.assertEqual(run.status, "running")
            manager.stop_scan(run.id)
            while run.status not in {"stopped", "failed"} and time.monotonic() < deadline:
                time.sleep(0.01)
            manager.close()

        self.assertEqual(run.status, "stopped")

    def test_application_and_mobile_fields_are_at_the_end(self):
        classification_start = INVENTORY_FIELDNAMES.index(APPLICATION_CLASSIFICATION_FIELDNAMES[0])
        mobile_start = INVENTORY_FIELDNAMES.index(MOBILE_FIELDNAMES[0])
        self.assertEqual(INVENTORY_FIELDNAMES[classification_start:mobile_start], APPLICATION_CLASSIFICATION_FIELDNAMES)
        self.assertEqual(INVENTORY_FIELDNAMES[mobile_start:], MOBILE_FIELDNAMES)
        self.assertEqual(EXPORT_COLUMNS[-1], "google_play_lookup_status")
        self.assertGreater(EXPORT_COLUMNS.index("mobile_name"), EXPORT_COLUMNS.index("inventory_types"))

    def test_repository_discovery_uses_multiple_workers(self):
        lock = threading.Lock()
        thread_ids: set[int] = set()

        class Client:
            org = "Fabrikam"

            def list_projects(self):
                return [{"name": f"Project-{index}"} for index in range(6)]

            def list_repos(self, project):
                with lock:
                    thread_ids.add(threading.get_ident())
                time.sleep(0.01)
                return [{"id": project, "name": "repo"}]

        targets = collect_targets(Client(), None, max_workers=4)

        self.assertEqual(len(targets), 6)
        self.assertGreater(len(thread_ids), 1)


if __name__ == "__main__":
    unittest.main()
