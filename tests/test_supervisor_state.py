import json
import os
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


    def test_proxy_passes_upstream_ca_to_download_only_when_ready(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp)
            settings_by_section = {
                ("proxy",): {"port": 8899},
                ("speedtest",): {"enabled": False},
                ("r2",): {"enabled": True},
            }
            settings = SimpleNamespace(
                runtime=runtime,
                section=lambda *keys: settings_by_section[keys],
            )
            trust_path = runtime / "relay-upstream-ca.pem"
            trust_path.write_text("test CA placeholder")
            with patch("tah_control.services.require_free_port"), \
                 patch("tah_control.services.mitmdump_path", return_value=Path("/fake/mitmdump")), \
                 patch("tah_control.services.relay_ca_available", return_value=True), \
                 patch("tah_control.services.subprocess.Popen") as popen, \
                 patch.dict(os.environ, {"IOTA_R2_UPSTREAM_CA": "/stale/ca.pem"}):
                services.start_proxy(settings)
                ready_env = popen.call_args.kwargs["env"]
                self.assertEqual(ready_env["IOTA_RELAY_CA_READY"], "1")
                self.assertEqual(ready_env["IOTA_R2_UPSTREAM_CA"], str(trust_path))
                self.assertIn(
                    f"ssl_verify_upstream_trusted_ca={trust_path}",
                    popen.call_args.args[0],
                )

                trust_path.unlink()
                services.start_proxy(settings)
                unready_env = popen.call_args.kwargs["env"]
                self.assertEqual(unready_env["IOTA_RELAY_CA_READY"], "0")
                self.assertNotIn("IOTA_R2_UPSTREAM_CA", unready_env)


if __name__ == "__main__":
    unittest.main()
