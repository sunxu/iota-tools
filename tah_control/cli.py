"""Command line entrypoint for the single-machine IOTA service."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

from tah_control import macos, services
from tah_control.config import load_settings, ensure_runtime
from tah_control.supervisor import Supervisor, atomic_json, desired, set_desired


def preflight(s) -> dict:
    checks = {
        "app_installed": s.app.is_dir(),
        "mitmdump_installed": True,
        "speedtest_hosts": True,
        "relay_ca_configured": services.relay_ca_available(s),
    }
    try:
        services.mitmdump_path()
    except RuntimeError:
        checks["mitmdump_installed"] = False
    if s.section("speedtest")["enabled"]:
        try:
            services.verify_hosts(s.section("speedtest")["host"], s.section("speedtest")["port"])
        except (OSError, RuntimeError):
            checks["speedtest_hosts"] = False
    return checks


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tah-control")
    p.add_argument("--config", type=Path, help="machine-local TOML override")
    sub = p.add_subparsers(dest="action", required=True)
    for action in ("install", "uninstall", "start", "stop", "restart", "reload", "run",
                   "status", "check", "logs", "finder"):
        sub.add_parser(action)
    args = p.parse_args(argv)
    try:
        settings = load_settings(args.config)
        ensure_runtime(settings)
        action = args.action
        if action == "check":
            checks = preflight(settings)
            print(json.dumps(checks, ensure_ascii=False, indent=2))
            return 0 if all(v for k, v in checks.items() if k != "relay_ca_configured") else 1
        if action == "install":
            checks = preflight(settings)
            if not all(v for k, v in checks.items() if k != "relay_ca_configured"):
                raise RuntimeError("preflight failed; run 'check' and repair before installation")
            agent = macos.install(settings)
            print(f"installed user LaunchAgent: {agent}")
            return 0
        if action == "uninstall":
            set_desired(settings, "stop")
            macos.uninstall()
            print("LaunchAgent removed; user config and local CA state preserved")
            return 0
        if action in ("start", "restart"):
            if action == "restart":
                atomic_json(settings.runtime / "restart-request.json", {"requested_at": time.time()})
            set_desired(settings, "run")
            state_file = settings.runtime / "status.json"
            try:
                state = json.loads(state_file.read_text())
                os.kill(state["supervisor_pid"], 0)
                active = True
            except (FileNotFoundError, ValueError, KeyError, OSError, TypeError):
                active = False
            if not active:
                macos.kickstart()
            print("Supervisor requested to " + ("restart IOTA" if action == "restart" else "run"))
            return 0
        if action == "reload":
            macos.kickstart(restart=True)
            print("Supervisor reload requested; managed app and proxy will restart")
            return 0
        if action == "stop":
            set_desired(settings, "stop")
            print("Supervisor requested to stop managed app and helpers")
            return 0
        if action == "run":
            if sys.platform != "darwin":
                raise RuntimeError("IOTA GUI Supervisor requires macOS")
            Supervisor(settings).run()
            return 0
        if action == "status":
            path = settings.runtime / "status.json"
            record = json.loads(path.read_text()) if path.is_file() else {}
            record["configured_desired"] = desired(settings)
            download_path = settings.runtime / "r2-download-status.json"
            if download_path.is_file():
                try:
                    record["r2_download"] = json.loads(download_path.read_text())
                except (OSError, ValueError):
                    record["r2_download"] = {"status": "unavailable"}
            pid = record.get("supervisor_pid")
            if isinstance(pid, int):
                try:
                    os.kill(pid, 0)
                    record["supervisor_alive"] = True
                except OSError:
                    record["supervisor_alive"] = False
            print(json.dumps(record, ensure_ascii=False, indent=2))
            return 0
        if action == "logs":
            print(settings.runtime / "supervisor.stderr.log")
            print(settings.runtime / "supervisor.stdout.log")
            return 0
        if action == "finder":
            print(macos.install_finder_app())
            return 0
        raise RuntimeError(f"unknown action: {action}")
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"tah-control: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
