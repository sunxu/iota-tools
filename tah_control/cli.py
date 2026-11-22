"""Command line entrypoint for the single-machine IOTA service."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import sys
import time
import uuid

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



_RELOAD_PROGRESS_STAGES = {
    "WAITING_BUSY", "IDLE_CONFIRMING", "PREFLIGHT",
    "STOPPING", "STARTING", "VERIFYING",
}
_RELOAD_WAIT_STAGES = {"WAITING_BUSY", "IDLE_CONFIRMING"}


def _reload_progress_line(stage: str, counts: object, old_pid: object,
                          new_pid: object, elapsed: int, remaining: int) -> str:
    """Format only trusted phase names and numeric diagnostics, never raw fields."""
    def number(value: object) -> str:
        return str(value) if type(value) is int and value >= 0 else "?"

    if not isinstance(counts, dict):
        counts = {}
    if stage == "WAITING_BUSY":
        details = " ".join(
            f"{label}={number(counts.get(key))}"
            for label, key in (
                ("HTTP", "active_http_flows"), ("TCP", "active_tcp_flows"),
                ("WebSocket", "active_websockets"), ("Tunnel", "active_tunnels"),
            )
        )
        return f"{stage} {details} elapsed={elapsed}s remaining={remaining}s"
    if stage == "IDLE_CONFIRMING":
        return f"{stage} elapsed={elapsed}s remaining={remaining}s"
    if stage == "PREFLIGHT":
        return "PREFLIGHT checking configuration, addons and CA"
    if stage == "STOPPING":
        return f"STOPPING mitmdump_pid={number(old_pid)}"
    if stage == "STARTING":
        return "STARTING new mitmdump"
    if stage == "VERIFYING":
        return f"VERIFYING mitmdump_pid={number(new_pid)}"
    return ""


def _report_reload_progress(
    progress: object, request_id: str, seen_seq: int,
    last_output_at: float, elapsed: float, remaining: int,
) -> tuple[int, float]:
    """Print each phase transition once, plus waiting heartbeat every 10 s."""
    if not isinstance(progress, dict) or progress.get("request_id") != request_id:
        return seen_seq, last_output_at
    events = progress.get("events")
    if not isinstance(events, list):
        return seen_seq, last_output_at
    minute, second = divmod(int(max(0, elapsed)), 60)
    for event in events:
        if not isinstance(event, dict):
            continue
        seq, stage = event.get("seq"), event.get("stage")
        if (type(seq) is not int or seq <= seen_seq
                or type(stage) is not str or stage not in _RELOAD_PROGRESS_STAGES):
            continue
        message = _reload_progress_line(
            stage, event.get("counts"), event.get("old_pid"),
            event.get("new_pid"), int(elapsed), remaining,
        )
        print(f"[{minute:02}:{second:02}] {message}", file=sys.stderr, flush=True)
        seen_seq = seq
        last_output_at = elapsed
    if (type(progress.get("stage")) is str
            and progress["stage"] in _RELOAD_WAIT_STAGES
            and last_output_at >= 0 and elapsed - last_output_at >= 10):
        stage = progress["stage"]
        message = _reload_progress_line(
            stage, progress.get("counts"), progress.get("old_pid"),
            progress.get("new_pid"), int(elapsed), remaining,
        )
        print(f"[{minute:02}:{second:02}] {message}", file=sys.stderr, flush=True)
        last_output_at = elapsed
    return seen_seq, last_output_at


def reload_proxy_command(settings, wait_seconds: int) -> int:
    """Submit one manual command; only the existing Supervisor owns mitmdump."""
    if not 0 <= wait_seconds <= 3600:
        raise ValueError("--wait must be between 0 and 3600 seconds")
    runtime = settings.runtime
    lock_path = runtime / "reload-proxy-cli.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"status": "BUSY", "reason": "ANOTHER_RELOAD_RUNNING"}))
            return 1
        status_file = runtime / "status.json"
        try:
            state = json.loads(status_file.read_text())
            supervisor_pid = state["supervisor_pid"]
            proxy_pid = state["proxy_pid"]
            if (type(supervisor_pid) is not int or type(proxy_pid) is not int
                    or time.time() - state["timestamp"] > 10
                    or state["desired"] != "run"):
                raise ValueError("stale Supervisor status")
            os.kill(supervisor_pid, 0)
            os.kill(proxy_pid, 0)
        except (OSError, KeyError, TypeError, ValueError):
            print(json.dumps({"status": "PREFLIGHT_FAILED",
                              "reason": "SUPERVISOR_OR_PROXY_NOT_RUNNING"}))
            return 1

        request_id = uuid.uuid4().hex
        request = {
            "request_id": request_id,
            "expected_supervisor_pid": supervisor_pid,
            "expected_proxy_pid": proxy_pid,
            "wait_seconds": wait_seconds,
            "deadline": time.time() + wait_seconds,
        }
        atomic_json(runtime / "reload-proxy-request.json", request)
        print(f"[00:00] REQUESTED mitmdump_pid={proxy_pid} wait={wait_seconds}s",
              file=sys.stderr, flush=True)
        # The Supervisor needs time for its scan loop, preflight and startup
        # after the last admissible idle snapshot.
        started = time.monotonic()
        until = started + wait_seconds + 45
        seen_seq = 0
        last_output_at = -1.0
        while time.monotonic() < until:
            try:
                progress = json.loads((runtime / "reload-proxy-progress.json").read_text())
                seen_seq, last_output_at = _report_reload_progress(
                    progress, request_id, seen_seq, last_output_at,
                    time.monotonic() - started,
                    max(0, int(request["deadline"] - time.time())),
                )
            except (OSError, ValueError):
                pass
            try:
                result = json.loads((runtime / "reload-proxy-result.json").read_text())
                if result.get("request_id") == request_id:
                    print(json.dumps(result, ensure_ascii=False))
                    return 0 if result.get("status") == "APPLIED" else 1
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        print(json.dumps({"status": "FAILED", "reason": "SUPERVISOR_RESULT_TIMEOUT",
                          "request_id": request_id}))
        return 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tah-control")
    p.add_argument("--config", type=Path, help="machine-local TOML override")
    sub = p.add_subparsers(dest="action", required=True)
    for action in ("install", "uninstall", "start", "stop", "restart", "reload", "run",
                   "status", "check", "logs", "finder"):
        sub.add_parser(action)
    proxy_reload = sub.add_parser("reload-proxy")
    proxy_reload.add_argument("--wait", type=int, default=120, metavar="SECONDS")
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
        if action == "reload-proxy":
            return reload_proxy_command(settings, args.wait)
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
                    download_status = json.loads(download_path.read_text())
                    if download_status.get("process_pid") != record.get("proxy_pid"):
                        download_status["relay_ready"] = False
                        download_status["status"] = "stale"
                    record["r2_download"] = download_status
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
