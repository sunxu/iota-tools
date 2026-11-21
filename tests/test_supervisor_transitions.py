"""Failure-mode checks for the macOS Supervisor state machine.

All OS operations are mocked; these are NOT substitutes for a real IOTA upgrade.
"""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch

from tah_control.supervisor import Supervisor, set_desired


class SupervisorTransitions(unittest.TestCase):
    def _settings(self, root):
        config = {
            "update_grace_seconds": 180,
            "restart_delay_seconds": 1,
            "max_restarts_per_hour": 3,
            "scan_seconds": 0.1,
        }
        return SimpleNamespace(
            runtime=Path(root),
            section=lambda *keys: config if keys == ("supervisor",) else {},
        )

    def test_update_replacement_is_not_implicitly_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            supervisor = Supervisor(self._settings(tmp))
            supervisor.owned_pids = {123}
            supervisor.started_app = True
            supervisor.update_started = time.monotonic() - 181
            with patch("tah_control.supervisor.app_pids", return_value={456}), \
                 patch("tah_control.supervisor._graceful_app_stop") as stop, \
                 patch.object(supervisor, "_launch_app") as launch:
                supervisor._app_tick()
                stop.assert_called_once()
                self.assertEqual(stop.call_args.args[1], {456})
                launch.assert_called_once()

    def test_grace_does_not_force_an_immediate_kill(self):
        with tempfile.TemporaryDirectory() as tmp:
            supervisor = Supervisor(self._settings(tmp))
            supervisor.owned_pids = {123}
            supervisor.started_app = True
            with patch("tah_control.supervisor.app_pids", return_value={456}), \
                 patch("tah_control.supervisor._graceful_app_stop") as stop, \
                 patch.object(supervisor, "_launch_app") as launch:
                supervisor._app_tick()
                self.assertEqual(supervisor.state, "update_grace")
                stop.assert_not_called()
                launch.assert_not_called()

    def test_unknown_initial_app_is_never_taken_over(self):
        with tempfile.TemporaryDirectory() as tmp:
            supervisor = Supervisor(self._settings(tmp))
            with patch("tah_control.supervisor.app_pids", return_value={123}), \
                 patch.object(supervisor, "_launch_app") as launch:
                supervisor._app_tick()
                self.assertEqual(supervisor.state, "unmanaged_app")
                launch.assert_not_called()

    def test_failed_stop_keeps_helpers_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(tmp)
            set_desired(settings, "stop")
            supervisor = Supervisor(settings)
            supervisor.started_app = True
            supervisor.owned_pids = {123}
            proxy = object()
            supervisor.proxy = proxy
            with patch("tah_control.supervisor.app_pids", return_value={123}), \
                 patch("tah_control.supervisor._graceful_app_stop", side_effect=RuntimeError("refused")), \
                 patch("tah_control.supervisor.services.stop_owned") as stop_helper:
                supervisor.tick()
                self.assertEqual(supervisor.state, "stop_failed")
                self.assertIs(supervisor.proxy, proxy)
                stop_helper.assert_not_called()

    def test_restart_counter_persists_between_supervisors(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(tmp)
            supervisor = Supervisor(settings)
            self.assertTrue(supervisor._restarts_available())
            self.assertTrue(supervisor._restarts_available())
            self.assertTrue(supervisor._restarts_available())
            self.assertFalse(Supervisor(settings)._restarts_available())


if __name__ == "__main__":
    unittest.main()
