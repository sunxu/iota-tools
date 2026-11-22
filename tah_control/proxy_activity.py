"""Private, read-only activity snapshot for manual mitmdump replacement.

The snapshot never contains URLs, HTTP headers, request bodies or client addresses.
It is advisory: a new request can arrive between the idle check and shutdown.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import time

from tah_control.config import ROOT, load_settings


_SOURCE_FILES = (
    "tah_control/proxy_activity.py",
    "r2_client/addon.py",
    "r2_client/download.py",
    "r2_client/upload.py",
    "speedtest/addon.py",
)


def proxy_build_id() -> str:
    digest = hashlib.sha256()
    for name in _SOURCE_FILES:
        digest.update(name.encode("utf-8") + b"\0")
        digest.update((ROOT / name).read_bytes())
    return digest.hexdigest()[:16]


class ProxyActivity:
    def __init__(self) -> None:
        self.path = load_settings().runtime / "proxy-activity.json"
        self.pid = os.getpid()
        self.build_id = proxy_build_id()
        self.http: dict[str, str] = {}
        self.tcp: set[str] = set()
        self.websockets: set[str] = set()
        self.tunnels: set[str] = set()
        self._heartbeat_task: asyncio.Task | None = None

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        value = {
            "process_pid": self.pid,
            "timestamp": time.time(),
            "build_id": self.build_id,
            "active_http_flows": len(self.http),
            "active_tcp_flows": len(self.tcp),
            "active_websockets": len(self.websockets),
            "active_tunnels": len(self.tunnels),
        }
        temporary = self.path.with_name(self.path.name + f".{self.pid}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(value, stream, separators=(",", ":"))
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(2)
            self._write()

    def running(self) -> None:
        self._write()
        self._heartbeat_task = asyncio.create_task(self._heartbeat())

    def _client_id(self, flow) -> str:
        return str(getattr(flow.client_conn, "id", ""))

    def requestheaders(self, flow) -> None:
        if flow.request.method.upper() != "CONNECT":
            self.http[str(flow.id)] = self._client_id(flow)
            self._write()

    def response(self, flow) -> None:
        self.http.pop(str(flow.id), None)
        self._write()

    def error(self, flow) -> None:
        self.http.pop(str(flow.id), None)
        self._write()

    def http_connect(self, flow) -> None:
        # Uninspected CONNECT tunnels have no HTTP response hooks after setup.
        # Treat them as in-flight until their client transport disconnects.
        host = (flow.request.host or "").lower()
        inspected = (
            host in {"www.speedtest.net", "c.speedtest.net"}
            or host == "cloudflarestorage.com"
            or host.endswith(".cloudflarestorage.com")
        )
        if not inspected:
            self.tunnels.add(self._client_id(flow))
            self._write()

    def client_disconnected(self, client) -> None:
        ident = str(getattr(client, "id", ""))
        self.tunnels.discard(ident)
        self.http = {key: value for key, value in self.http.items() if value != ident}
        self._write()

    def tcp_start(self, flow) -> None:
        self.tcp.add(str(flow.id))
        self._write()

    def tcp_end(self, flow) -> None:
        self.tcp.discard(str(flow.id))
        self._write()

    def tcp_error(self, flow) -> None:
        self.tcp.discard(str(flow.id))
        self._write()

    def websocket_start(self, flow) -> None:
        self.websockets.add(str(flow.id))
        self._write()

    def websocket_end(self, flow) -> None:
        self.websockets.discard(str(flow.id))
        self._write()

    async def done(self) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            await asyncio.gather(self._heartbeat_task, return_exceptions=True)
        # Never remove a newer mitmdump process's status file.
        try:
            if json.loads(self.path.read_text()).get("process_pid") == self.pid:
                self.path.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass


addons = [ProxyActivity()]
