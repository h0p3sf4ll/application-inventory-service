import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import Mock, patch

from appsec_scan_router.constants import (
    APPLICATION_CLASSIFICATION_FIELDNAMES,
    INVENTORY_FIELDNAMES,
    MOBILE_FIELDNAMES,
)
from appsec_scan_router.auth import AuthenticatedUser, SessionRecord
from appsec_scan_router.postgres import EXPORT_COLUMNS
from appsec_scan_router.runtime import (
    ScanManager,
    ScanRun,
    is_failure_log_line,
    rebuild_failure_log,
)
from appsec_scan_router.scanner import collect_targets
from appsec_scan_router.ui import ApplicationInventoryServiceHandler


class RuntimeTests(unittest.TestCase):
    def test_scan_failures_are_isolated_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reports_dir = Path(tmpdir)
            failure_path = reports_dir / "failures.log"
            run = ScanRun(
                "scan-1",
                {},
                (),
                (),
                reports_dir,
                failure_log_path=failure_path,
            )
            listener = run.add_listener()

            run.append_log("Completed with 0 errors")
            run.append_log("ERROR GitHub request could not be completed")
            event = listener.get_nowait()
            event = listener.get_nowait()
            run.append_log("HTTP 404 from repository endpoint")
            (reports_dir / ".scan.log").write_text("internal", encoding="utf-8")
            summary = run.summary()

            self.assertFalse(is_failure_log_line("Completed with no failures"))
            self.assertFalse(is_failure_log_line("Errors: 0"))
            self.assertFalse(
                is_failure_log_line("DETECTED asset=errors-dashboard confidence=high")
            )
            self.assertTrue(is_failure_log_line("Status: 503"))
            self.assertTrue(event["data"]["failure"])
            self.assertEqual(event["data"]["sequence"], 2)
            self.assertEqual(summary["failureCount"], 2)
            self.assertEqual(summary["logSequence"], 3)
            self.assertEqual(
                summary["failuresTail"],
                [
                    "ERROR GitHub request could not be completed",
                    "HTTP 404 from repository endpoint",
                ],
            )
            self.assertEqual(
                failure_path.read_text(encoding="utf-8").splitlines(),
                summary["failuresTail"],
            )
            self.assertEqual(stat.S_IMODE(failure_path.stat().st_mode), 0o600)
            self.assertEqual(
                [report["name"] for report in run.report_files()],
                ["failures.log"],
            )

    def test_failure_log_rebuild_replaces_stale_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = root / ".scan.log"
            failures = root / "failures.log"
            source.write_text(
                "ready\nFailed repo A\nCompleted with no errors\nFatal: repo B\n",
                encoding="utf-8",
            )
            failures.write_text("stale\n", encoding="utf-8")

            count = rebuild_failure_log(source, failures)

            self.assertEqual(count, 2)
            self.assertEqual(
                failures.read_text(encoding="utf-8").splitlines(),
                ["Failed repo A", "Fatal: repo B"],
            )
            self.assertEqual(stat.S_IMODE(failures.stat().st_mode), 0o600)

    def test_scan_run_tracks_metrics_without_rescanning_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run = ScanRun("scan-1", {}, (), (), Path(tmpdir))
            for index in range(5100):
                run.append_log(f"line {index}")
            run.append_log(
                'SCAN_PROGRESS {"repositoriesPrepared":10,"repositoriesTotal":20,"branchesScanned":7,"branchesTotal":12}'
            )
            run.append_log("DETECTED asset=Payments branch=main")

            summary = run.summary()

        self.assertEqual(len(run.logs), 5000)
        self.assertEqual(len(summary["logsTail"]), 300)
        self.assertEqual(summary["logSequence"], 5102)
        self.assertEqual(summary["detectedCount"], 1)
        self.assertEqual(summary["progress"]["repositoriesPrepared"], 10)
        self.assertEqual(summary["progress"]["branchesScanned"], 7)

    def test_event_stream_replays_log_tail_with_sequence_numbers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run = ScanRun(
                "scan-1",
                {},
                (),
                (),
                Path(tmpdir),
                status="succeeded",
            )
            run.append_log("ready")
            run.append_log("ERROR provider unavailable")
            handler = object.__new__(ApplicationInventoryServiceHandler)
            handler.send_response = Mock()
            handler.send_header = Mock()
            handler.end_headers = Mock()
            handler.write_event = Mock()

            handler.stream_scan_events(run)

        events = [call.args for call in handler.write_event.call_args_list]
        log_events = [data for event, data in events if event == "log"]
        self.assertEqual([event["sequence"] for event in log_events], [1, 2])
        self.assertFalse(log_events[0]["failure"])
        self.assertTrue(log_events[1]["failure"])
        self.assertEqual(events[0][0], "status")
        self.assertEqual(events[-1][0], "done")

    def test_scan_manager_pauses_and_resumes_running_process(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScanManager(
                Path(tmpdir), dict, lambda config, path: [], lambda config: {}, list
            )
            process = Mock()
            process.poll.return_value = None
            run = ScanRun(
                "scan-1",
                {"ownerUserId": "user-1"},
                (),
                (),
                Path(tmpdir),
                status="running",
                process=process,
            )
            manager.scans[run.id] = run

            with (
                patch("appsec_scan_router.runtime.pause_process") as pause,
                patch("appsec_scan_router.runtime.resume_process") as resume,
            ):
                manager.pause_scan(run.id)
                self.assertEqual(run.status, "paused")
                pause.assert_called_once_with(process, None)
                manager.resume_scan(run.id)
                self.assertEqual(run.status, "running")
                resume.assert_called_once_with(process, None)

    def test_failed_scan_retry_creates_a_new_persisted_attempt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manager = ScanManager(
                root,
                lambda config: dict(config),
                lambda config, path: ["scanner", "--out-dir", str(path)],
                lambda config: {},
                list,
            )
            source_config = {
                "ownerUserId": "user-1",
                "provider": "azure-devops",
                "adoOrgPats": [{"org": "Example", "pat": "encrypted-state"}],
            }
            source = ScanRun(
                "scan-1",
                source_config,
                (),
                (),
                root / "scan-1",
                root_scan_id="scan-1",
                status="failed",
                exit_code=1,
            )
            manager.scans[source.id] = source

            with patch.object(manager, "_start_thread") as start_thread:
                retry = manager.retry_scan(source.id)

            self.assertIsNotNone(retry)
            self.assertNotEqual(retry.id, source.id)
            self.assertEqual(retry.status, "queued")
            self.assertEqual(retry.retry_of, source.id)
            self.assertEqual(retry.root_scan_id, source.id)
            self.assertEqual(retry.attempt, 2)
            self.assertEqual(retry.config, source_config)
            self.assertIsNot(retry.config, source.config)
            self.assertIsNot(retry.config["adoOrgPats"], source.config["adoOrgPats"])
            self.assertNotEqual(retry.reports_dir, source.reports_dir)
            self.assertEqual(retry.summary()["retryOf"], source.id)
            self.assertFalse(retry.summary()["canRetry"])
            self.assertTrue(source.summary()["canRetry"])
            start_thread.assert_called_once_with(retry, manager._run_scan)

            record = next(
                item
                for item in manager.state_store.records()
                if item["id"] == retry.id
            )
            restored = manager._restore_run(record)
            self.assertEqual(restored.retry_of, source.id)
            self.assertEqual(restored.root_scan_id, source.id)
            self.assertEqual(restored.attempt, 2)
            manager.close()

    def test_scan_retry_rejects_nonfailed_and_duplicate_active_attempts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manager = ScanManager(
                root, dict, lambda config, path: [], lambda config: {}, list
            )
            succeeded = ScanRun(
                "scan-succeeded",
                {"ownerUserId": "user-1"},
                (),
                (),
                root / "scan-succeeded",
                status="succeeded",
            )
            failed = ScanRun(
                "scan-failed",
                {"ownerUserId": "user-1"},
                (),
                (),
                root / "scan-failed",
                root_scan_id="scan-failed",
                status="failed",
            )
            active_retry = ScanRun(
                "scan-retry",
                {"ownerUserId": "user-1"},
                (),
                (),
                root / "scan-retry",
                retry_of=failed.id,
                root_scan_id=failed.id,
                attempt=2,
                status="running",
            )
            manager.scans = {
                succeeded.id: succeeded,
                failed.id: failed,
                active_retry.id: active_retry,
            }

            with self.assertRaisesRegex(ValueError, "Only a failed run"):
                manager.retry_scan(succeeded.id)
            with self.assertRaisesRegex(ValueError, "already active"):
                manager.retry_scan(failed.id)
            manager.close()

    def test_retry_api_queues_new_attempt_for_the_run_owner(self):
        source = ScanRun(
            "scan-failed",
            {"ownerUserId": "user-1", "postgresEnabled": False},
            (),
            (),
            Path("reports/scan-failed"),
            status="failed",
        )
        retry = ScanRun(
            "scan-retry",
            {"ownerUserId": "user-1", "postgresEnabled": False},
            (),
            (),
            Path("reports/scan-retry"),
            retry_of=source.id,
            root_scan_id=source.id,
            attempt=2,
        )
        record = SessionRecord(
            "session-1",
            AuthenticatedUser("user-1", "user@example.test"),
            "csrf-token",
            time.time() + 60,
        )
        handler = object.__new__(ApplicationInventoryServiceHandler)
        handler.manager = Mock()
        handler.manager.get_scan.return_value = source
        handler.manager.retry_scan.return_value = retry
        handler.current_session = Mock(return_value=record)
        handler.valid_csrf = Mock(return_value=True)
        handler.send_json = Mock()
        handler.send_error = Mock()

        handler.handle_scan_action("/api/scans/scan-failed/retry")

        handler.manager.retry_scan.assert_called_once_with(source.id)
        handler.send_json.assert_called_once_with(
            {"scan": retry.summary()}, HTTPStatus.CREATED
        )
        handler.send_error.assert_not_called()

    def test_failed_subprocess_retry_completes_as_a_separate_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            marker = root / "attempted"

            def command(config, reports_dir):
                return [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; import sys; "
                        "marker = Path(sys.argv[1]); "
                        "already_attempted = marker.exists(); marker.touch(); "
                        "raise SystemExit(0 if already_attempted else 1)"
                    ),
                    str(marker),
                ]

            manager = ScanManager(
                root / "reports",
                dict,
                command,
                lambda config: dict(os.environ),
                list,
            )
            source = manager.start_scan({"ownerUserId": "user-1"})
            deadline = time.monotonic() + 5
            while source.status != "failed" and time.monotonic() < deadline:
                time.sleep(0.02)

            retry = manager.retry_scan(source.id)
            while retry.status != "succeeded" and time.monotonic() < deadline:
                time.sleep(0.02)
            manager.close()

        self.assertEqual(source.status, "failed")
        self.assertEqual(source.exit_code, 1)
        self.assertEqual(retry.status, "succeeded")
        self.assertEqual(retry.exit_code, 0)
        self.assertEqual(retry.retry_of, source.id)
        self.assertNotEqual(retry.reports_dir, source.reports_dir)

    @unittest.skipUnless(
        os.name == "posix", "Durable process recovery requires POSIX process groups."
    )
    def test_running_scan_survives_manager_restart(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_dir = root / "state"

            def command(config, path):
                return [
                    sys.executable,
                    "-c",
                    "import time; print('ready', flush=True); time.sleep(1.5); print('done', flush=True)",
                ]

            manager = ScanManager(
                root / "reports",
                dict,
                command,
                lambda config: dict(os.environ),
                list,
                state_dir=state_dir,
            )
            run = manager.start_scan(
                {"ownerUserId": "user-1", "token": "not-written-in-plaintext"}
            )
            deadline = time.monotonic() + 3
            while (
                run.process_pid is None or not any("ready" in line for line in run.logs)
            ) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIsNotNone(run.process_pid)
            process_pid = run.process_pid

            manager.close()
            os.kill(process_pid, 0)
            self.assertNotIn(
                b"not-written-in-plaintext",
                (state_dir / "scan-runs.json.enc").read_bytes(),
            )

            recovered_manager = ScanManager(
                root / "reports",
                dict,
                command,
                lambda config: dict(os.environ),
                list,
                state_dir=state_dir,
            )
            recovered = recovered_manager.get_scan(run.id)
            self.assertIsNotNone(recovered)
            self.assertTrue(recovered.recovered)
            self.assertIn(recovered.status, {"running", "succeeded"})
            deadline = time.monotonic() + 5
            while recovered.status != "succeeded" and time.monotonic() < deadline:
                time.sleep(0.03)
            recovered_manager.close()
            if run.process is not None:
                run.process.wait(timeout=2)

        self.assertEqual(recovered.status, "succeeded")
        self.assertTrue(any("done" in line for line in recovered.logs))

    def test_recovered_completion_does_not_wait_for_a_zombie_worker(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manager = ScanManager(
                root / "reports",
                dict,
                lambda config, path: [],
                lambda config: {},
                list,
                state_dir=root / "state",
            )
            run = ScanRun(
                "scan-1",
                {"ownerUserId": "user-1"},
                (),
                (),
                root / "reports" / "scan-1",
                status="running",
                process_pid=12345,
                process_group_id=12345,
            )
            manager.scans[run.id] = run

            with (
                patch.object(
                    manager.state_store,
                    "read_completion",
                    return_value={"exitCode": 0, "endedAt": "2026-07-31T00:00:00+00:00"},
                ),
                patch(
                    "appsec_scan_router.runtime.process_is_running",
                    return_value=True,
                ) as is_running,
            ):
                manager._monitor_scan(run, None, 0)
            manager.close()

        self.assertEqual(run.status, "succeeded")
        self.assertEqual(run.exit_code, 0)
        is_running.assert_not_called()

    @unittest.skipUnless(
        os.name == "posix", "Process pause and resume require POSIX signals."
    )
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
            while (
                run.status not in {"stopped", "failed"} and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            manager.close()

        self.assertEqual(run.status, "stopped")

    def test_application_and_mobile_fields_are_at_the_end(self):
        classification_start = INVENTORY_FIELDNAMES.index(
            APPLICATION_CLASSIFICATION_FIELDNAMES[0]
        )
        mobile_start = INVENTORY_FIELDNAMES.index(MOBILE_FIELDNAMES[0])
        self.assertEqual(
            INVENTORY_FIELDNAMES[classification_start:mobile_start],
            APPLICATION_CLASSIFICATION_FIELDNAMES,
        )
        self.assertEqual(INVENTORY_FIELDNAMES[mobile_start:], MOBILE_FIELDNAMES)
        self.assertEqual(EXPORT_COLUMNS[-1], "google_play_lookup_status")
        self.assertGreater(
            EXPORT_COLUMNS.index("mobile_name"), EXPORT_COLUMNS.index("inventory_types")
        )

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
