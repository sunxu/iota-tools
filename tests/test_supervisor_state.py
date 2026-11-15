import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tah_control.supervisor import atomic_json, desired, set_desired
from tah_control import services


class StateTests(unittest.TestCase):
    def test_stop_persists_and_corrupt_fails_stopped(self):
        with tempfile.TemporaryDirectory() as temp:
            s = SimpleNamespace(runtime=Path(temp))
            self.assertEqual(desired(s), "run")
            set_desired(s, "stop")
            self.assertEqual(desired(s), "stop")
            (Path(temp) / "desired.json").write_text("{invalid")
            self.assertEqual(desired(s), "stop")

    def test_atomic_private_state(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "state.json"
            atomic_json(p, {"n": 1})
            self.assertEqual(json.loads(p.read_text())["n"], 1)
            self.assertEqual(p.stat().st_mode & 0o077, 0)

    def test_app_environment_contains_ca_overrides(self):
        with tempfile.TemporaryDirectory() as temp:
            s = SimpleNamespace(runtime=Path(temp), section=lambda *keys:
                                {"port": 8899} if keys == ("proxy",)
                                else {"host": "speedtest.jsqiuying.com"})
            env = services.app_environment(s)
            self.assertIn("REQUESTS_CA_BUNDLE", env)
            self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:8899")
            self.assertIn("speedtest.jsqiuying.com", env["NO_PROXY"])


if __name__ == "__main__":
    unittest.main()
