"""Single-user, single-machine IOTA Supervisor.

launchd keeps this process alive; this process owns the proxy and speedtest
children. The original .app is never modified. Update-relaunched processes are
NOT assumed to retain the environment: they are gracefully relaunched under
our environment after an update grace period.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from tah_control.config import Settings, ensure_runtime
from tah_control import services


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def desired_path(settings: Settings) -> Path:
    return settings.runtime / "desired.json"


def desired(settings: Settings) -> str:
    try:
        data = json.loads(desired_path(settings).read_text())
        return data["state"] if data["state"] in {"run", "stop"} else "stop"
    except FileNotFoundError:
        return "run"  # RunAtLoad starts after login on a freshly installed node.
    except (ValueError, KeyError, TypeError):
        return "stop"  # A corrupt stop flag must never start an unwanted app.


def set_desired(settings: Settings, state: str) -> None:
    if state not in {"run", "stop"}:
        raise ValueError("invalid desired state")
    ensure_runtime(settings)
    atomic_json(desired_path(settings), {"state": state})


def app_pids(settings: Settings) -> set[int]:
    binary = settings.app / "Contents" / "MacOS" / "IOTA Train at Home"
    pattern = "^" + re.escape(str(binary)) + "$"
    result = subprocess.run(["/usr/bin/pgrep", "-f", pattern], capture_output=True, text=True)
    if result.returncode == 1:
        return set()
    if result.returncode != 0:
        raise RuntimeError("cannot query IOTA processes")
    return {int(piece) for piece in result.stdout.split() if piece.isdecimal()}


def _wait_for_app(settings: Settings, seconds: float = 20) -> set[int]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pids = app_pids(settings)
        if pids:
            return pids
        time.sleep(0.5)
    raise RuntimeError("IOTA did not appear after macOS open")


def _graceful_app_stop(settings: Settings, allowed: set[int]) -> None:
    # Kill only exact executable-path matches we have already attributed to IOTA.
    for pid in app_pids(settings) & allowed:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and (app_pids(settings) & allowed):
        time.sleep(0.25)
    if app_pids(settings) & allowed:
        raise RuntimeError("IOTA refused graceful termination; no SIGKILL issued")


class Supervisor:
    def __init__(self, settings: Settings):
        self.s = settings
        self.speedtest: subprocess.Popen | None = None
        self.proxy: subprocess.Popen | None = None
        self.owned_pids: set[int] = set()
        self.started_app = False
        self.last_alive: float | None = None
        self.update_started: float | None = None
        self.last_service_retry = 0.0
        self.running = True
        self.state = "starting"
        self.error = ""

    def status(self) -> None:
        atomic_json(self.s.runtime / "status.json", {
            "supervisor_pid": os.getpid(), "timestamp": time.time(),
            "desired": desired(self.s), "state": self.state,
            "managed_app_pids": sorted(self.owned_pids), "error": self.error,
            "proxy_pid": self.proxy.pid if self.proxy and self.proxy.poll() is None else None,
            "speedtest_pid": self.speedtest.pid if self.speedtest and self.speedtest.poll() is None else None,
        })

    def _start_children(self) -> None:
        if self.speedtest is None or self.speedtest.poll() is not None:
            services.stop_owned(self.speedtest)
            self.speedtest = services.start_speedtest(self.s)
        if self.proxy is None or self.proxy.poll() is not None:
            services.stop_owned(self.proxy)
            self.proxy = services.start_proxy(self.s)
            services.wait_proxy(self.s, self.proxy)
            was_bootstrap = not (self.s.runtime / "combined-ca.pem").exists()
            services.generate_cas(self.s)
            if was_bootstrap and services.relay_ca_available(self.s):
                # First run: regenerate with upstream trust bundle before any IOTA traffic.
                services.stop_owned(self.proxy)
                self.proxy = services.start_proxy(self.s)
                services.wait_proxy(self.s, self.proxy)

    def _restarts_available(self) -> bool:
        path = self.s.runtime / "app-restarts.json"
        try:
            values = json.loads(path.read_text())
            if not isinstance(values, list):
                values = []
        except (FileNotFoundError, ValueError):
            values = []
        now = time.time()
        values = [float(t) for t in values if isinstance(t, (int, float)) and now - 3600 < t <= now]
        limit = self.s.section("supervisor")["max_restarts_per_hour"]
        if len(values) >= limit:
            return False
        values.append(now)
        atomic_json(path, values)
        return True

    def _launch_app(self) -> None:
        if app_pids(self.s):
            raise RuntimeError("unmanaged IOTA is running; do not attach without environment verification")
        if not self._restarts_available():
            self.state = "restart_limit"
            return
        environment = services.app_environment(self.s)
        cmd = ["/usr/bin/open", "-a", str(self.s.app)]
        for key, value in environment.items():
            cmd += ["--env", f"{key}={value}"]
        # The proxy remains alive independently of the 'open' command.
        subprocess.run(cmd, env=services.clean_env(), check=True, timeout=30)
        self.owned_pids = _wait_for_app(self.s)
        self.last_alive = time.monotonic()
        self.update_started = None
        self.started_app = True
        self.state = "running"

    def _app_tick(self) -> None:
        pids = app_pids(self.s)
        now = time.monotonic()
        if pids and self.owned_pids and pids.issubset(self.owned_pids):
            self.last_alive = now
            self.update_started = None
            self.state = "running"
            return
        if not self.started_app:
            if pids:
                self.state = "unmanaged_app"
                self.error = "IOTA already running; close it to enable managed startup"
                return
            self._launch_app()
            return
        if self.update_started is None:
            self.update_started = now
        grace = self.s.section("supervisor")["update_grace_seconds"]
        if now - self.update_started < grace:
            self.state = "update_grace"
            return
        if pids:
            # The updater may have spawned a process without our scoped CA/proxy
            # environment. Gracefully stop only the exact known app executable.
            _graceful_app_stop(self.s, pids)
        self.owned_pids.clear()
        self.started_app = False
        self.update_started = None
        self._launch_app()

    def _stop_everything(self) -> None:
        if self.started_app:
            # Update-launched replacement processes may not be in owned_pids.
            _graceful_app_stop(self.s, app_pids(self.s))
        self.owned_pids.clear()
        self.started_app = False
        services.stop_owned(self.proxy)
        services.stop_owned(self.speedtest)
        self.proxy = self.speedtest = None

    def tick(self) -> None:
        if desired(self.s) == "stop":
            self._stop_everything()
            self.state = "stopped"
            self.error = ""
            return
        delay = self.s.section("supervisor")["restart_delay_seconds"]
        if time.monotonic() - self.last_service_retry < delay:
            return
        try:
            self._start_children()
            restart = self.s.runtime / "restart-request.json"
            if restart.is_file():
                restart.unlink()
                if self.started_app:
                    _graceful_app_stop(self.s, app_pids(self.s))
                    self.owned_pids.clear()
                    self.started_app = False
                self._launch_app()
            else:
                self._app_tick()
            if self.state != "unmanaged_app":
                self.error = ""
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
            self.error = str(exc)
            self.state = "error"
            self.last_service_retry = time.monotonic()
            # If a child failed during startup, never retain a partial proxy.
            if self.proxy and self.proxy.poll() is not None:
                self.proxy = None

    def run(self) -> None:
        ensure_runtime(self.s)
        lock = (self.s.runtime / "supervisor.lock").open("a+")
        try:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("another iota-tools Supervisor is active") from exc

            def shutdown(_sig, _frame):
                self.running = False

            signal.signal(signal.SIGINT, shutdown)
            signal.signal(signal.SIGTERM, shutdown)
            while self.running:
                self.tick()
                self.status()
                time.sleep(self.s.section("supervisor")["scan_seconds"])
        finally:
            try:
                self._stop_everything()
            finally:
                lock.close()
