"""Minimal mitmproxy R2 UploadPart router.

Routes only new valid multipart PUTs, never GET or completion calls.
Busy primary waits; an actual proxy/CONNECT failure enables backup for NEW flows.
The addon never reads, buffers, rewrites or retries request bodies.
"""
from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import urlsplit

from mitmproxy import http
from mitmproxy.connection import ConnectionState, Server
from mitmproxy.net.server_spec import ServerSpec

from r2_client.eligibility import is_upload_part
from tah_control.config import load_settings

LOG = logging.getLogger("iota.r2")


def _spec(url: str) -> ServerSpec:
    u = urlsplit(url)
    return ServerSpec(("http", (u.hostname, u.port)))


class R2UploadRouter:
    def __init__(self, settings=None) -> None:
        s = settings or load_settings()
        up = s.section("r2", "upload")
        self.enabled = s.section("r2")["enabled"]
        self.primary = _spec(up["primary_proxy"])
        self.backup = _spec(up["fallback_proxy"])
        self.limit_primary = up["max_concurrency"]
        self.limit_backup = up["fallback_max_concurrency"]
        self.fallback_direct = up["fallback_direct"]
        self.probe_interval = up["probe_interval_seconds"]
        self.probe_timeout = up["probe_timeout_seconds"]
        self.relay_ca_ready = os.environ.get("IOTA_RELAY_CA_READY") == "1"
        self.failed: set[ServerSpec] = set()
        if not self.relay_ca_ready:
            self.failed.add(self.primary)
        self.assignments: dict[int, ServerSpec | str] = {}
        self.flow_clients: dict[int, object] = {}
        self.target_host: dict[ServerSpec, str] = {}
        self.probes: dict[ServerSpec, asyncio.Task] = {}
        self.capacity = asyncio.Event()
        self.stopping = False
        self.counts = {"assigned_primary": 0, "assigned_backup": 0, "rejected": 0, "failures": 0}
        # We use a known R2 host from prior requests to test CONNECT without any signed URL.

    def _notify(self):
        event = self.capacity
        self.capacity = asyncio.Event()
        event.set()

    def _available(self, via: ServerSpec, limit: int) -> bool:
        return via not in self.failed and sum(x == via for x in self.assignments.values()) < limit

    def _select(self):
        if self.primary not in self.failed:
            return self.primary if self._available(self.primary, self.limit_primary) else "wait"
        if self.backup not in self.failed:
            return self.backup if self._available(self.backup, self.limit_backup) else "wait"
        return "direct" if self.fallback_direct else "reject"

    async def requestheaders(self, flow: http.HTTPFlow):
        request = getattr(flow, "request", None)
        if (not self.enabled or request is None or not
                is_upload_part(request.method, request.host, request.url)):
            return
        key = id(flow)
        if key in self.assignments or self.stopping:
            return
        while not self.stopping:
            route = self._select()
            if route != "wait":
                break
            event = self.capacity
            await event.wait()
        if self.stopping:
            return
        if route == "reject":
            self.counts["rejected"] += 1
            flow.response = http.Response.make(503, b"R2 upload proxy routes unavailable\n",
                                               {"Content-Type": "text/plain"})
            return
        if route == "direct":
            self.assignments[key] = "direct"
            self.flow_clients[key] = getattr(getattr(flow, "client_conn", None), "id", None)
            return
        self.assignments[key] = route
        self.flow_clients[key] = getattr(getattr(flow, "client_conn", None), "id", None)
        self.target_host[route] = request.host
        self.counts["assigned_primary" if route == self.primary else "assigned_backup"] += 1
        server = flow.server_conn
        # A previously-open server connection MUST NOT be repurposed across routes.
        if server.via != route:
            if server.state is ConnectionState.OPEN:
                server = flow.server_conn = Server(
                    address=server.address,
                    transport_protocol=server.transport_protocol,
                )
            server.via = route

    def _release(self, flow):
        key = id(flow)
        if key in self.assignments:
            self.assignments.pop(key, None)
            self.flow_clients.pop(key, None)
            self._notify()

    def response(self, flow):
        # HTTP 4xx/5xx are business responses, not evidence of proxy failure.
        self._release(flow)

    def error(self, flow):
        via = self.assignments.get(id(flow))
        error = str(getattr(getattr(flow, "error", None), "msg", ""))
        if via in (self.primary, self.backup):
            address = f"{via[1][0]}:{via[1][1]}"
            pre_tls = getattr(getattr(flow, "server_conn", None), "timestamp_tls_setup", None) is None
            if (f"Upstream proxy {address} refused HTTP CONNECT request" in error
                    or f"Error connecting to {address}" in error
                    or (pre_tls and error.lower().startswith(("connection closed", "connection reset")))):
                self._mark_failed(via)
        self._release(flow)

    def server_connect_error(self, data):
        conn = getattr(data, "server", None)
        addr = getattr(conn, "address", None)
        client_id = getattr(getattr(data, "client", None), "id", None)
        for via in (self.primary, self.backup):
            if addr == via[1] and any(
                route == via and self.flow_clients.get(key) == client_id
                for key, route in self.assignments.items()
            ):
                self._mark_failed(via)

    def client_disconnected(self, client):
        cid = getattr(client, "id", None)
        for key, value in list(self.flow_clients.items()):
            if value == cid:
                self.assignments.pop(key, None)
                self.flow_clients.pop(key, None)
        self._notify()

    def _mark_failed(self, via):
        if via in self.failed:
            return
        self.failed.add(via)
        self.counts["failures"] += 1
        self._notify()
        LOG.warning("R2 upload proxy connection failure, route=%s", via[1][1])
        if via not in self.probes:
            try:
                self.probes[via] = asyncio.get_running_loop().create_task(self._probe_loop(via))
            except RuntimeError:
                pass

    async def _probe_loop(self, via):
        try:
            while not self.stopping and via in self.failed:
                await asyncio.sleep(self.probe_interval)
                host = self.target_host.get(via)
                if not host or await self._connect_probe(via, host):
                    # Missing a host cannot prove CONNECT support. Do not restore it.
                    if not host:
                        continue
                    self.failed.discard(via)
                    self._notify()
                    LOG.info("R2 upload proxy recovered, route=%s", via[1][1])
        except asyncio.CancelledError:
            raise
        finally:
            self.probes.pop(via, None)

    async def _connect_probe(self, via, host):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(*via[1]), timeout=self.probe_timeout)
            try:
                wire = f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode("ascii")
                writer.write(wire)
                await asyncio.wait_for(writer.drain(), timeout=self.probe_timeout)
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=self.probe_timeout)
                return response.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 200") or \
                    response.split(b"\r\n", 1)[0].startswith(b"HTTP/1.0 200")
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError, UnicodeError):
            return False

    def done(self):
        self.stopping = True
        self._notify()
        for task in list(self.probes.values()):
            task.cancel()
        self.probes.clear()
        self.assignments.clear()
        self.flow_clients.clear()


addons = [R2UploadRouter()]
