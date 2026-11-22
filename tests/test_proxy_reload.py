"""Offline tests for the manually triggered mitmdump-only reload contract."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from tah_control import services
from tah_control.cli import _report_reload_progress, reload_proxy_command
from tah_control.config import Settings, load_settings
from tah_control.proxy_activity import ProxyActivity
from tah_control.supervisor import Supervisor, atomic_json


class ProxyActivityTests(unittest.TestCase):
    def test_snapshot_tracks_http_and_noninspected_tunnel_without_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_settings = SimpleNamespace(runtime=Path(tmp))
            with patch("tah_control.proxy_activity.load_settings", return_value=fake_settings):
                activity = ProxyActivity()
            conn = SimpleNamespace(id="c1")
            flow = SimpleNamespace(
                id="flow1", client_conn=conn, request=SimpleNamespace(method="GET")
            )
            activity.requestheaders(flow)
            state = json.loads(activity.path.read_text())
            self.assertEqual(state["active_http_flows"], 1)
            self.assertEqual(state["process_pid"], os.getpid())
            self.assertNotIn("url", state)
            activity.response(flow)
            self.assertEqual(json.loads(activity.path.read_text())["active_http_flows"], 0)
            tunnel = SimpleNamespace(
                request=SimpleNamespace(host="outside.example"), client_conn=conn
            )
            activity.http_connect(tunnel)
            self.assertEqual(json.loads(activity.path.read_text())["active_tunnels"], 1)
            activity.client_disconnected(conn)
            self.assertEqual(json.loads(activity.path.read_text())["active_tunnels"], 0)

    def test_activity_snapshot_write_failure_never_breaks_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_settings = SimpleNamespace(runtime=Path(tmp))
            with patch("tah_control.proxy_activity.load_settings", return_value=fake_settings):
                activity = ProxyActivity()
            flow = SimpleNamespace(
                id="flow1", client_conn=SimpleNamespace(id="c1"),
                request=SimpleNamespace(method="GET"),
            )
            with patch("tah_control.proxy_activity.os.open", side_effect=OSError("no space")):
                activity.requestheaders(flow)
            self.assertIn("flow1", activity.http)
            self.assertFalse(activity.path.exists())

    def test_stable_loader_does_not_change_after_first_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = services._proxy_loader(Path(tmp), "r2_client.addon")
            initial = path.read_bytes()
            mtime = path.stat().st_mtime_ns
            self.assertIn(b"from r2_client.addon import addons\n", initial)
            self.assertEqual(services._proxy_loader(Path(tmp), "r2_client.addon"), path)
            self.assertEqual(path.stat().st_mtime_ns, mtime)
            path.write_text("malicious = True\n")
            with self.assertRaises(RuntimeError):
                services._proxy_loader(Path(tmp), "r2_client.addon")


class ReloadSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path_patch = patch.object(
            Settings, "runtime", new_callable=lambda: property(lambda _: self.root)
        )
        self.path_patch.start()
        self.settings = load_settings(self.root / "not-existing.toml")
        self.supervisor = Supervisor(self.settings)
        self.old_proc = Mock()
        self.old_proc.pid = 32101
        self.old_proc.poll.return_value = None
        self.supervisor.proxy = self.old_proc

    def tearDown(self):
        self.path_patch.stop()
        self.tmp.cleanup()

    def _activity(self, pid=32101, *, http=0, age=0, build="a" * 16):
        atomic_json(self.root / "proxy-activity.json", {
            "process_pid": pid, "timestamp": time.time() - age,
            "build_id": build,
            "active_http_flows": http, "active_tcp_flows": 0,
            "active_websockets": 0, "active_tunnels": 0,
        })

    def _request(self, *, wait=0, pid=32101):
        atomic_json(self.root / "reload-proxy-request.json", {
            "request_id": "a" * 32, "expected_proxy_pid": pid,
            "expected_supervisor_pid": os.getpid(),
            "wait_seconds": wait, "deadline": time.time() + wait,
        })

    def _result(self):
        return json.loads((self.root / "reload-proxy-result.json").read_text())

    def test_progress_scoped_to_request_and_records_only_safe_fields(self):
        request_id = "a" * 32
        self._activity(http=4)
        snapshot = self.supervisor._activity_snapshot(32101)
        self.supervisor._reload_progress(
            request_id, "WAITING_BUSY", old_pid=32101, snapshot=snapshot
        )
        self._activity(http=2)
        self.supervisor._reload_progress(
            request_id, "WAITING_BUSY", old_pid=32101,
            snapshot=self.supervisor._activity_snapshot(32101)
        )
        self.supervisor._reload_progress(request_id, "PREFLIGHT", old_pid=32101)
        progress_file = self.root / "reload-proxy-progress.json"
        progress = json.loads(progress_file.read_text())
        self.assertEqual(progress["request_id"], request_id)
        self.assertEqual(progress["last_seq"], 2)
        self.assertEqual(
            [event["stage"] for event in progress["events"]],
            ["WAITING_BUSY", "PREFLIGHT"],
        )
        self.assertEqual(progress["events"][0]["counts"]["active_http_flows"], 4)
        self.assertNotIn("Authorization", progress_file.read_text())
        self.assertNotIn("https://", progress_file.read_text())
        self.supervisor._reload_progress("b" * 32, "STOPPING", old_pid=32101)
        self.assertEqual(json.loads(progress_file.read_text())["last_seq"], 1)
        self.assertEqual(json.loads(progress_file.read_text())["request_id"], "b" * 32)

    def test_progress_write_failure_does_not_affect_reload(self):
        with patch("tah_control.supervisor.atomic_json", side_effect=OSError("read-only")):
            self.supervisor._reload_progress("a" * 32, "PREFLIGHT", old_pid=32101)

    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    def test_busy_proxy_is_not_stopped(self, stop):
        self._activity(http=1)
        self._request(wait=0)
        self.supervisor._reload_proxy_tick()
        self.assertEqual(self._result()["status"], "BUSY")
        progress = json.loads((self.root / "reload-proxy-progress.json").read_text())
        self.assertEqual(progress["stage"], "WAITING_BUSY")
        self.assertEqual(progress["counts"]["active_http_flows"], 1)
        self.assertIs(self.supervisor.proxy, self.old_proc)
        stop.assert_not_called()

    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    def test_stale_snapshot_fails_closed(self, stop):
        self._activity(age=30)
        self._request()
        self.supervisor._reload_proxy_tick()
        self.assertEqual(self._result()["status"], "PREFLIGHT_FAILED")
        self.assertEqual(self._result()["reason"], "ACTIVITY_UNAVAILABLE")
        stop.assert_not_called()

    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    @patch("tah_control.supervisor.services.proxy_preflight")
    def test_preflight_rechecks_new_traffic_before_stop(self, preflight, stop):
        self._activity()
        self._request(wait=0)
        preflight.side_effect = lambda settings: self._activity(http=1)
        self.supervisor._reload_proxy_tick()
        self.assertEqual(self._result()["status"], "BUSY")
        stop.assert_not_called()
        self.assertIs(self.supervisor.proxy, self.old_proc)

    @patch("tah_control.supervisor.services.wait_proxy")
    @patch("tah_control.supervisor.services.start_proxy")
    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    @patch("tah_control.supervisor.services.proxy_preflight")
    def test_only_mitmdump_changes_on_success(self, preflight, stop, start, wait):
        self._activity()
        self._request()
        new = Mock()
        new.pid = 32102
        new.poll.return_value = None

        def start_new(settings, *, reload_only):
            self.assertTrue(reload_only)
            self._activity(pid=32102, build="b" * 16)
            atomic_json(self.root / "r2-download-status.json", {
                "process_pid": 32102, "relay_ready": True
            })
            return new

        start.side_effect = start_new
        self.supervisor._reload_proxy_tick()
        result = self._result()
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["old_pid"], 32101)
        self.assertEqual(result["new_pid"], 32102)
        self.assertEqual(result["new_build_id"], "b" * 16)
        self.assertIs(self.supervisor.proxy, new)
        stop.assert_called_once_with(self.old_proc)
        preflight.assert_called_once()
        wait.assert_called_once()
        self.assertFalse((self.root / "reload-proxy-request.json").exists())
        progress = json.loads((self.root / "reload-proxy-progress.json").read_text())
        self.assertEqual(
            [event["stage"] for event in progress["events"]],
            ["IDLE_CONFIRMING", "PREFLIGHT", "STOPPING", "STARTING", "VERIFYING"],
        )
        self.assertEqual(progress["events"][-1]["new_pid"], 32102)
        # No IOTA or Speedtest control path is called by this operation.
        self.supervisor._reload_proxy_tick()
        stop.assert_called_once()

    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    @patch("tah_control.supervisor.services.proxy_preflight",
           side_effect=RuntimeError("invalid code"))
    def test_preflight_error_leaves_original_proxy_running(self, preflight, stop):
        self._activity()
        self._request()
        self.supervisor._reload_proxy_tick()
        self.assertEqual(self._result()["status"], "PREFLIGHT_FAILED")
        self.assertIs(self.supervisor.proxy, self.old_proc)
        stop.assert_not_called()

    @patch("tah_control.supervisor.services.wait_proxy")
    @patch("tah_control.supervisor.services.start_proxy")
    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    @patch("tah_control.supervisor.services.proxy_preflight")
    def test_unhealthy_new_proxy_fails_without_reporting_success(
        self, preflight, stop, start, wait
    ):
        self._activity()
        self._request()
        new = Mock()
        new.pid = 32102
        new.poll.return_value = 1  # New process exits before addon readiness.
        start.return_value = new
        self.supervisor._reload_proxy_tick()
        self.assertEqual(self._result()["status"], "FAILED")
        self.assertIsNone(self.supervisor.proxy)
        stop.assert_called_once_with(self.old_proc)

    @patch("tah_control.supervisor.services.start_proxy",
           side_effect=RuntimeError("start failure"))
    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    @patch("tah_control.supervisor.services.proxy_preflight")
    def test_start_failure_is_not_reported_as_success(self, preflight, stop, start):
        self._activity()
        self._request()
        self.supervisor._reload_proxy_tick()
        self.assertEqual(self._result()["status"], "FAILED")
        self.assertIsNone(self.supervisor.proxy)
        stop.assert_called_once()


class ReloadCliTests(unittest.TestCase):
    def test_progress_is_limited_to_transitions_and_ten_second_heartbeats(self):
        request_id = "c" * 32
        counts = {
            "active_http_flows": 4, "active_tcp_flows": 0,
            "active_websockets": 0, "active_tunnels": 0,
        }
        progress = {
            "request_id": request_id, "stage": "WAITING_BUSY",
            "counts": counts, "old_pid": 32101,
            "events": [{
                "seq": 1, "stage": "WAITING_BUSY",
                "counts": counts, "old_pid": 32101,
            }],
        }
        out = StringIO()
        with redirect_stderr(out):
            seq, last = _report_reload_progress(
                progress, request_id, 0, -1, 2, 118
            )
            seq, last = _report_reload_progress(
                progress, request_id, seq, last, 7, 113
            )
            progress["counts"] = {**counts, "active_http_flows": 2}
            seq, last = _report_reload_progress(
                progress, request_id, seq, last, 12, 108
            )
            seq, last = _report_reload_progress(
                progress, "different-request", seq, last, 25, 95
            )
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("[00:02] WAITING_BUSY HTTP=4", lines[0])
        self.assertIn("[00:12] WAITING_BUSY HTTP=2", lines[1])
        self.assertEqual(seq, 1)

    def test_short_lived_phases_are_printed_from_history(self):
        request_id = "c" * 32
        phases = ("IDLE_CONFIRMING", "PREFLIGHT", "STOPPING",
                  "STARTING", "VERIFYING")
        progress = {
            "request_id": request_id, "stage": "VERIFYING",
            "events": [
                {"seq": index, "stage": phase,
                 "old_pid": 32101, "new_pid": 32102}
                for index, phase in enumerate(phases, 1)
            ],
        }
        stderr = StringIO()
        with redirect_stderr(stderr):
            seq, _ = _report_reload_progress(progress, request_id, 0, -1, 5, 115)
        self.assertEqual(seq, 5)
        self.assertEqual(
            [phase for line in stderr.getvalue().splitlines()
             for phase in phases if phase in line], list(phases),
        )
        self.assertIn("mitmdump_pid=32102", stderr.getvalue())

    def test_invalid_or_unrelated_progress_cannot_print_private_values(self):
        private = "https://example.com/private?token=secret"
        progress = {
            "request_id": "c" * 32, "stage": ["invalid"],
            "url": private,
            "events": [
                {"seq": 1, "stage": "unknown", "url": private},
                {"seq": 2, "stage": ["invalid"], "url": private},
            ],
        }
        stderr = StringIO()
        with redirect_stderr(stderr):
            seq, _ = _report_reload_progress(
                progress, "c" * 32, 0, -1, 2, 118
            )
            _report_reload_progress(progress, "d" * 32, seq, -1, 15, 100)
        self.assertEqual(stderr.getvalue(), "")

    def test_command_preserves_one_json_line_on_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(Settings, "runtime", new_callable=lambda: property(lambda _: root)):
                settings = load_settings(root / "not-existing.toml")
                atomic_json(root / "status.json", {
                    "supervisor_pid": os.getpid(), "proxy_pid": os.getpid(),
                    "timestamp": time.time(), "desired": "run",
                })

                def respond(_):
                    request_id = json.loads(
                        (root / "reload-proxy-request.json").read_text()
                    )["request_id"]
                    atomic_json(root / "reload-proxy-progress.json", {
                        "request_id": request_id, "stage": "VERIFYING",
                        "events": [
                            {"seq": 1, "stage": "PREFLIGHT", "old_pid": os.getpid()},
                            {"seq": 2, "stage": "STOPPING", "old_pid": os.getpid()},
                            {"seq": 3, "stage": "STARTING", "old_pid": os.getpid()},
                            {"seq": 4, "stage": "VERIFYING", "new_pid": 98765},
                        ],
                    })
                    atomic_json(root / "reload-proxy-result.json", {
                        "request_id": request_id, "status": "APPLIED",
                        "old_pid": os.getpid(), "new_pid": 98765,
                    })

                stdout, stderr = StringIO(), StringIO()
                with patch("tah_control.cli.time.sleep", side_effect=respond):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        self.assertEqual(reload_proxy_command(settings, 0), 0)
                self.assertEqual(len(stdout.getvalue().splitlines()), 1)
                self.assertEqual(json.loads(stdout.getvalue())["status"], "APPLIED")
                for stage in ("REQUESTED", "PREFLIGHT", "STOPPING",
                              "STARTING", "VERIFYING"):
                    self.assertIn(stage, stderr.getvalue())
                self.assertNotIn("PREFLIGHT", stdout.getvalue())

    def test_command_reports_success_and_does_not_signal_other_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(Settings, "runtime", new_callable=lambda: property(lambda _: root)):
                settings = load_settings(root / "not-existing.toml")
                atomic_json(root / "status.json", {
                    "supervisor_pid": os.getpid(), "proxy_pid": os.getpid(),
                    "timestamp": time.time(), "desired": "run"
                })

                def respond(_):
                    request = json.loads((root / "reload-proxy-request.json").read_text())
                    atomic_json(root / "reload-proxy-result.json", {
                        "request_id": request["request_id"], "status": "APPLIED"
                    })

                with patch("tah_control.cli.time.sleep", side_effect=respond):
                    with patch("builtins.print") as output:
                        self.assertEqual(reload_proxy_command(settings, 0), 0)
                        self.assertIn("APPLIED", output.call_args.args[0])

    def test_invalid_wait_is_rejected(self):
        with self.assertRaises(ValueError):
            reload_proxy_command(None, -1)


class RealMitmdumpSmokeTests(unittest.TestCase):
    @unittest.skipUnless(services.shutil.which("mitmdump"), "mitmdump is not installed")
    def test_real_mitmdump_relaunch_loads_private_addons(self):
        """Launch an isolated loopback proxy, never a real R2 GET or an IOTA app."""
        import socket

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"HOME": tmp}):
                settings = load_settings(Path(tmp) / "missing.toml")
                settings.data["speedtest"]["enabled"] = False
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    settings.data["proxy"]["port"] = listener.getsockname()[1]
                proc = None
                try:
                    proc = services.start_proxy(settings)
                    services.wait_proxy(settings, proc, seconds=20)
                    deadline = time.monotonic() + 12
                    while True:
                        try:
                            activity = json.loads(
                                (settings.runtime / "proxy-activity.json").read_text()
                            )
                            download = json.loads(
                                (settings.runtime / "r2-download-status.json").read_text()
                            )
                            if (activity["process_pid"] == proc.pid
                                    and download["process_pid"] == proc.pid
                                    and download["relay_ready"]):
                                break
                        except (OSError, KeyError, ValueError):
                            pass
                        if proc.poll() is not None or time.monotonic() >= deadline:
                            self.fail("real mitmdump addons did not become ready")
                        time.sleep(0.2)
                    self.assertEqual(activity["active_http_flows"], 0)
                    ca = settings.runtime / "mitmproxy" / "mitmproxy-ca-cert.pem"
                    ca_original = ca.read_bytes()
                    old_pid = proc.pid
                    services.stop_proxy_for_reload(proc)
                    proc = services.start_proxy(settings, reload_only=True)
                    services.wait_proxy(settings, proc, seconds=20)
                    self.assertNotEqual(proc.pid, old_pid)
                    self.assertEqual(ca.read_bytes(), ca_original)
                finally:
                    if proc is not None:
                        services.stop_owned(proc)


if __name__ == "__main__":
    unittest.main()
