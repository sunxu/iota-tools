import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest


class MitmproxyAddonLifecycleTests(unittest.TestCase):
    def test_real_mitmdump_loads_addons_and_starts_loopback_relay(self):
        root = Path(__file__).resolve().parents[1]
        binary = Path(sys.executable).with_name("mitmdump")
        if not binary.is_file():
            located = shutil.which("mitmdump")
            if not located:
                self.skipTest("mitmdump executable unavailable")
            binary = Path(located)

        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            home = temp / "home"
            home.mkdir()
            config = temp / "config.toml"
            config.write_text("[r2.download]\nenabled = true\n", encoding="utf-8")
            confdir = temp / "mitmproxy"
            stderr_path = temp / "mitmdump.stderr.log"
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                listen_port = sock.getsockname()[1]

            env = dict(os.environ)
            env.update({
                "HOME": str(home),
                "IOTA_TOOLS_CONFIG": str(config),
                "IOTA_RELAY_CA_READY": "0",
                "PYTHONPATH": str(root) + os.pathsep + env.get("PYTHONPATH", ""),
            })
            with stderr_path.open("w", encoding="utf-8") as stderr:
                process = subprocess.Popen(
                    [
                        str(binary), "--listen-host", "127.0.0.1",
                        "--listen-port", str(listen_port),
                        "--set", f"confdir={confdir}",
                        "--set", "termlog_verbosity=error",
                        "-s", "r2_client/addon.py",
                    ],
                    cwd=root,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr,
                )
                status_path = home / "Library" / "Application Support" / "iota-tools" / "r2-download-status.json"
                started = False
                try:
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            break
                        if status_path.is_file():
                            try:
                                status = json.loads(status_path.read_text(encoding="utf-8"))
                            except (OSError, ValueError):
                                status = {}
                            if status.get("process_pid") == process.pid and status.get("relay_ready"):
                                started = True
                                break
                        time.sleep(0.1)
                    if not started:
                        stderr.flush()
                        detail = stderr_path.read_text(encoding="utf-8")[-4000:]
                        self.fail(f"mitmdump did not start the async R2 relay:\n{detail}")
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGINT)
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            process.wait(timeout=5)

                self.assertIsNotNone(process.returncode)
                self.assertTrue(status_path.is_file())
                final_status = json.loads(status_path.read_text(encoding="utf-8"))
                self.assertFalse(final_status["relay_ready"])


if __name__ == "__main__":
    unittest.main()
