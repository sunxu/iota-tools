"""Offline tests for the manually triggered mitmdump-only reload contract."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from tah_control import services
from tah_control.cli import reload_proxy_command
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

    @patch("tah_control.supervisor.services.stop_proxy_for_reload")
    def test_busy_proxy_is_not_stopped(self, stop):
        self._activity(http=1)
        self._request(wait=0)
        self.supervisor._reload_proxy_tick()
        self.assertEqual(self._result()["status"], "BUSY")
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
