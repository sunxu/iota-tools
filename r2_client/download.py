"""Slow R2 GET detection and capacity-aware proxy takeover.

A tiny loopback HTTP relay owns the asynchronous upstream streams. mitmproxy
rewrites eligible GETs to this relay and streams its response to the IOTA client.
This avoids blocking mitmproxy's synchronous response.stream callback.
"""
from __future__ import annotations

import asyncio
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import ssl
import time
from typing import Any

import certifi
from aiohttp import ClientResponse, ClientSession, ClientTimeout, TCPConnector, web
from multidict import CIMultiDict
from mitmproxy import http
from yarl import URL

from r2_client.eligibility import is_r2_object_get
from tah_control.config import Settings, ensure_runtime, load_settings

LOG = logging.getLogger("iota.r2.download")
_INTERNAL_TOKEN = "X-Iota-Download-Token"
_INTERNAL_REQUEST = "X-Iota-Download-Request"
_FLOW_ID = "iota_r2_download_id"
_CHUNK_SIZE = 64 * 1024
_REPLACEMENT_HEADER_TIMEOUT = 20.0
_REPLACEMENT_STREAM_STALL_TIMEOUT = 30.0
_EVENT_HISTORY_LIMIT = 1000
_REQUEST_CAPTURE_MAX_BYTES = 10 * 1024 * 1024
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}


class _ReplacementStreamStalled(Exception):
    """The replacement response body made no progress within its stall timeout."""


@dataclass
class _RequestContext:
    request_id: str
    url: str
    headers: tuple[tuple[bytes, bytes], ...]
    client_id: object
    range_requested: bool
    started: float
    task: asyncio.Task | None = None
    delivered_bytes: int = 0
    delivered_hash: Any = field(default_factory=hashlib.sha256)
    takeover_attempted: bool = False
    slot_reserved: bool = False
    replacement_open_ms: float | None = None
    prefix_validation_bytes: int = 0
    prefix_validation_ms: float | None = None
    replacement_stream_started: float | None = None
    replacement_bytes: int = 0
    replacement_stream_completed: bool = False
    response_status: int | None = None
    response_content_length: int | None = None
    min_10s_window_rate_kib_s: float | None = None
    slow_detected: bool = False
    capacity_full_count: int = 0
    capacity_full_event_recorded: bool = False
    takeover_skip_reason: str | None = None
    final_status: str = "failed"
    summary_recorded: bool = False
    relay_started: bool = False
    slot_reserved_at: float | None = None
    slot_held_ms: float | None = None
    takeover_trigger: str | None = None
    capacity_bypassed: bool = False


class _RateWindow:
    """A rolling byte counter. The first complete window starts at request creation."""

    def __init__(self, started: float, window_seconds: int) -> None:
        self.started = started
        self.window_seconds = window_seconds
        self.samples: deque[tuple[float, int]] = deque()
        self.total = 0
        self.next_check = started + 1.0

    def add(self, timestamp: float, size: int) -> None:
        if size > 0:
            self.samples.append((timestamp, size))
            self.total += size

    def sample(self, now: float) -> float | None:
        if now < self.next_check:
            return None
        self.next_check = now + 1.0
        if now - self.started < self.window_seconds:
            return None
        cutoff = now - self.window_seconds
        while self.samples and self.samples[0][0] < cutoff:
            _, size = self.samples.popleft()
            self.total -= size
        return self.total / (self.window_seconds * 1024)


def _connection_tokens(headers) -> set[str]:
    tokens: set[str] = set()
    for value in headers.getall("Connection", []):
        tokens.update(piece.strip().lower() for piece in value.split(",") if piece.strip())
    return tokens


def _forward_request_headers(raw_headers) -> CIMultiDict:
    headers = CIMultiDict()
    original = CIMultiDict(
        [(name.decode("latin-1"), value.decode("latin-1")) for name, value in raw_headers]
    )
    tokens = _connection_tokens(original)
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("latin-1")
        value = raw_value.decode("latin-1")
        lower = name.lower()
        if lower in _HOP_BY_HOP or lower in tokens:
            continue
        headers.add(name, value)
    return headers


def _response_headers(response: ClientResponse) -> CIMultiDict:
    headers = CIMultiDict()
    tokens = _connection_tokens(response.headers)
    for raw_name, raw_value in response.raw_headers:
        name = raw_name.decode("latin-1")
        lower = name.lower()
        if lower in _HOP_BY_HOP or lower in tokens:
            continue
        headers.add(name, raw_value.decode("latin-1"))
    return headers


def _response_is_takeover_eligible(response: ClientResponse, ctx: _RequestContext) -> bool:
    if ctx.range_requested:
        return response.status == 206 and bool(response.headers.get("Content-Range"))
    return response.status == 200


def _same_representation(old: ClientResponse, new: ClientResponse) -> bool:
    if old.status != new.status:
        return False
    etag = old.headers.get("ETag", "")
    if not etag or etag.lstrip().lower().startswith("w/"):
        return False
    if new.headers.get("ETag", "") != etag:
        return False
    for name in ("Content-Length", "Content-Range", "Content-Encoding",
                 "Content-Type", "Last-Modified"):
        if old.headers.get(name, "") != new.headers.get(name, ""):
            return False
    return True


def _same_unstarted_representation(old: ClientResponse, new: ClientResponse) -> bool:
    """Validate original/replacement headers when no body was delivered."""
    if old.status != new.status:
        return False
    old_length = _content_length(old)
    if old_length is None or old_length != _content_length(new):
        return False
    for name in ("Content-Range", "Content-Encoding", "Content-Type", "Last-Modified"):
        if old.headers.get(name, "") != new.headers.get(name, ""):
            return False
    etag = old.headers.get("ETag", "")
    if etag and new.headers.get("ETag", "") != etag:
        return False
    return True


def _content_length(response: Any) -> int | None:
    raw = response.headers.get("Content-Length")
    if raw is None:
        return None
    try:
        length = int(raw)
    except (TypeError, ValueError):
        return None
    return length if length >= 0 else None


def _progress_percent(delivered_bytes: int, content_length: int | None) -> float | None:
    if content_length is None or content_length <= 0:
        return None
    return min(100.0, delivered_bytes * 100.0 / content_length)


class R2DownloadRouter:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        self.config = self.settings.section("r2", "download")
        self.enabled = self.settings.section("r2")["enabled"] and self.config["enabled"]
        self.capture_requests = self.config["capture_requests"]
        self.threshold_kib_s = self.config["slow_threshold_kib_s"]
        self.window_seconds = self.config["slow_window_seconds"]
        self.replacement_proxy = self.config["replacement_proxy"]
        self.max_concurrent = self.config["max_concurrent_takeovers"]
        self.direct_takeover_threshold_bytes = (
            self.config["direct_takeover_threshold_mib"] * 1024 * 1024
        )
        self._token = secrets.token_urlsafe(32)
        self._contexts: dict[str, _RequestContext] = {}
        self._active_takeovers = 0
        self._active_direct_takeovers = 0
        self._port: int | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._session: ClientSession | None = None
        self._stats = {
            "eligible_gets": 0,
            "slow_detected": 0,
            "takeover_started": 0,
            "slow_takeover_started": 0,
            "direct_takeover_started": 0,
            "takeover_succeeded": 0,
            "takeover_failed": 0,
            "takeover_completed": 0,
            "takeover_stream_failed": 0,
            "takeover_stream_cancelled": 0,
            "takeover_stream_stalled": 0,
            "capacity_skipped": 0,
            "takeover_slot_released": 0,
            "download_summaries": 0,
        }
        self._last_event: dict | None = None

    @property
    def status_path(self) -> Path:
        return self.settings.runtime / "r2-download-status.json"

    @property
    def event_history_path(self) -> Path:
        return self.settings.runtime / "r2-download-events.jsonl"

    @property
    def request_capture_path(self) -> Path:
        return self.settings.runtime / "r2-download-requests.jsonl"

    def _capture_request(self, context: _RequestContext, method: str) -> None:
        """Best-effort private credential-bearing log, separate from ordinary events."""
        if not self.capture_requests:
            return
        try:
            entry = {
                "schema": "iota_r2_download_request_v1",
                "timestamp": time.time(),
                "request_id": context.request_id,
                "method": method,
                "url": context.url,
                "headers": [
                    [name.decode("latin-1"), value.decode("latin-1")]
                    for name, value in context.headers
                ],
                "replacement_proxy": self.replacement_proxy,
            }
            encoded = (
                json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            if len(encoded) > _REQUEST_CAPTURE_MAX_BYTES:
                return

            path = self.request_capture_path
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.parent.chmod(0o700)
            if path.is_symlink():
                raise OSError("request capture path cannot be a symlink")
            if path.exists():
                path.chmod(0o600)
                if path.stat().st_size + len(encoded) > _REQUEST_CAPTURE_MAX_BYTES:
                    os.replace(path, path.with_name(path.name + ".1"))

            fd = os.open(
                path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(fd, "ab") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(encoded)
            # Intentionally no per-record fsync: crash may lose the tail.
        except Exception:
            LOG.warning("Unable to update private R2 download request history")

    async def running(self) -> None:
        if not self.enabled:
            self._write_status()
            return
        try:
            ensure_runtime(self.settings)
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            extra_ca = os.environ.get("IOTA_R2_UPSTREAM_CA")
            if extra_ca:
                ssl_context.load_verify_locations(cafile=extra_ca)
            timeout = ClientTimeout(total=None, connect=20, sock_connect=15, sock_read=None)
            connector = TCPConnector(ssl=ssl_context, limit=100, enable_cleanup_closed=True)
            self._session = ClientSession(
                connector=connector,
                timeout=timeout,
                auto_decompress=False,
                trust_env=False,
                skip_auto_headers={"Accept", "Accept-Encoding", "User-Agent"},
            )
            app = web.Application(client_max_size=0)
            app.router.add_get("/{request_id}", self._relay)
            self._runner = web.AppRunner(app, access_log=None)
            await self._runner.setup()
            self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
            await self._site.start()
            addresses = self._runner.addresses
            if not addresses:
                raise RuntimeError("local R2 download relay did not bind")
            self._port = int(addresses[0][1])
            self._write_status()
            LOG.info("R2 download relay ready on loopback, port=%s", self._port)
        except Exception as exc:
            self._port = None
            if self._runner:
                await self._runner.cleanup()
                self._runner = None
            if self._session:
                await self._session.close()
                self._session = None
            LOG.error("R2 download relay unavailable; GET passthrough remains enabled: %s",
                      type(exc).__name__)
            self._write_status()

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        if not self.enabled or self._port is None:
            return
        if flow.metadata.get(_FLOW_ID):
            return
        if not is_r2_object_get(request.method, request.host, request.url, request.headers):
            return

        request_id = secrets.token_hex(8)
        context = _RequestContext(
            request_id=request_id,
            url=request.url,
            headers=tuple(request.headers.fields),
            client_id=getattr(flow.client_conn, "id", None),
            range_requested=bool(request.headers.get("Range")),
            started=asyncio.get_running_loop().time(),
        )
        self._contexts[request_id] = context
        flow.metadata[_FLOW_ID] = request_id
        self._stats["eligible_gets"] += 1
        self._capture_request(context, request.method)
        self._write_status()

        request.scheme = "http"
        request.host = "127.0.0.1"
        request.port = self._port
        request.path = f"/{request_id}"
        request.authority = f"127.0.0.1:{self._port}"
        request.headers.clear()
        request.host_header = f"127.0.0.1:{self._port}"
        request.headers[_INTERNAL_TOKEN] = self._token
        request.headers[_INTERNAL_REQUEST] = request_id

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get(_FLOW_ID) and flow.response:
            flow.response.stream = True

    def response(self, flow: http.HTTPFlow) -> None:
        request_id = flow.metadata.get(_FLOW_ID)
        if request_id:
            self._finalize_unstarted_context(
                request_id, "completed", "RELAY_NOT_STARTED", flow.response
            )

    def error(self, flow: http.HTTPFlow) -> None:
        request_id = flow.metadata.get(_FLOW_ID)
        if request_id:
            self._finalize_unstarted_context(request_id, "failed", "RELAY_ERROR")

    def _finalize_unstarted_context(
        self,
        request_id: str,
        final_status: str,
        reason: str,
        response: Any | None = None,
    ) -> None:
        context = self._contexts.get(request_id)
        if context is None or context.relay_started:
            return
        self._contexts.pop(request_id, None)
        context.final_status = final_status
        context.takeover_skip_reason = context.takeover_skip_reason or reason
        if response is not None:
            context.response_status = getattr(response, "status_code", None)
            context.response_content_length = _content_length(response)
        self._record_download_summary(context)
        self._write_status()

    def client_disconnected(self, client) -> None:
        client_id = getattr(client, "id", None)
        for context in list(self._contexts.values()):
            if context.client_id == client_id and context.task and not context.task.done():
                context.task.cancel()

    async def done(self) -> None:
        for context in list(self._contexts.values()):
            if context.task and not context.task.done():
                context.task.cancel()
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        if self._session:
            await self._session.close()
            self._session = None
        for context in list(self._contexts.values()):
            if not context.summary_recorded:
                context.final_status = "cancelled"
                context.takeover_skip_reason = context.takeover_skip_reason or "REQUEST_CANCELLED"
                self._record_download_summary(context)
        self._contexts.clear()
        self._port = None
        self._write_status()

    async def _open_upstream(self, context: _RequestContext, proxy: str | None = None) -> ClientResponse:
        if self._session is None:
            raise RuntimeError("R2 download HTTP session is not ready")
        return await self._session.get(
            URL(context.url, encoded=True),
            headers=_forward_request_headers(context.headers),
            allow_redirects=False,
            proxy=proxy,
        )

    async def _relay(self, request: web.Request) -> web.StreamResponse:
        request_id = request.match_info["request_id"]
        context = self._contexts.get(request_id)
        supplied_token = request.headers.get(_INTERNAL_TOKEN, "")
        if (context is None or not hmac.compare_digest(supplied_token, self._token)
                or request.headers.get(_INTERNAL_REQUEST) != request_id):
            raise web.HTTPNotFound()
        context.task = asyncio.current_task()
        context.relay_started = True
        initial_task: asyncio.Task | None = None
        upstream: ClientResponse | None = None
        downstream: web.StreamResponse | None = None
        replacement_last_data_at: float | None = None
        try:
            window = _RateWindow(context.started, self.window_seconds)
            initial_task = asyncio.create_task(self._open_upstream(context))

            while not initial_task.done():
                await asyncio.wait({initial_task}, timeout=1.0)
                now = asyncio.get_running_loop().time()
                rate = window.sample(now)
                self._observe_rate(context, rate)
                if (rate is not None and rate < self.threshold_kib_s
                        and not context.takeover_attempted
                        and context.takeover_skip_reason is None):
                    replacement = await self._consider_takeover(context, None, rate)
                    if replacement is not None:
                        if not initial_task.done():
                            initial_task.cancel()
                        with suppress(asyncio.CancelledError, Exception):
                            original_result = await initial_task
                            if original_result is not replacement:
                                original_result.close()
                        upstream = replacement
                        replacement_last_data_at = asyncio.get_running_loop().time()
                        break

            if upstream is None:
                upstream = await initial_task

            self._set_response_metadata(context, upstream)
            if not _response_is_takeover_eligible(upstream, context):
                context.takeover_skip_reason = "RESPONSE_NOT_ELIGIBLE"
                return await self._stream_without_takeover(request, upstream, context)

            if self._should_direct_takeover(context, upstream):
                replacement = await self._try_takeover(
                    context, upstream, None, trigger="file_size"
                )
                if replacement is not None:
                    upstream.close()
                    upstream = replacement
                    self._set_response_metadata(context, upstream)
                    replacement_last_data_at = asyncio.get_running_loop().time()

            while True:
                loop = asyncio.get_running_loop()
                read_timeout = 1.0
                if replacement_last_data_at is not None:
                    remaining = _REPLACEMENT_STREAM_STALL_TIMEOUT - (
                        loop.time() - replacement_last_data_at
                    )
                    read_timeout = min(read_timeout, max(0.001, remaining))
                try:
                    data = await asyncio.wait_for(
                        upstream.content.read(_CHUNK_SIZE), timeout=read_timeout
                    )
                except asyncio.TimeoutError:
                    data = None

                now = loop.time()
                if data is not None:
                    if data:
                        window.add(now, len(data))
                        if replacement_last_data_at is not None:
                            replacement_last_data_at = now
                    else:
                        if downstream is None:
                            downstream = self._make_downstream(upstream)
                        if not downstream.prepared:
                            await downstream.prepare(request)
                        await downstream.write_eof()
                        if (context.replacement_stream_started is not None
                                and not context.replacement_stream_completed):
                            self._complete_replacement(context)
                        context.final_status = "completed"
                        return downstream

                if (
                    data is None
                    and replacement_last_data_at is not None
                    and now - replacement_last_data_at >= _REPLACEMENT_STREAM_STALL_TIMEOUT
                ):
                    self._record_replacement_stream_stalled(
                        context, stage="replacement_stream"
                    )
                    raise _ReplacementStreamStalled()

                rate = window.sample(now)
                self._observe_rate(context, rate)
                if (rate is not None and rate < self.threshold_kib_s
                        and not context.takeover_attempted
                        and context.takeover_skip_reason is None):
                    replacement = await self._consider_takeover(context, upstream, rate)
                    if replacement is not None:
                        upstream.close()
                        upstream = replacement
                        self._set_response_metadata(context, upstream)
                        replacement_last_data_at = asyncio.get_running_loop().time()
                        if downstream is None or not downstream.prepared:
                            downstream = self._make_downstream(upstream)
                        continue

                if data is None:
                    continue
                if downstream is None:
                    downstream = self._make_downstream(upstream)
                if not downstream.prepared:
                    await downstream.prepare(request)
                await downstream.write(data)
                context.delivered_bytes += len(data)
                context.delivered_hash.update(data)
                if context.replacement_stream_started is not None:
                    context.replacement_bytes += len(data)

        except _ReplacementStreamStalled:
            context.final_status = "failed"
            if downstream is not None and downstream.prepared:
                if request.transport:
                    request.transport.close()
                return downstream
            return web.Response(status=502, text="R2 replacement download stalled\n")
        except asyncio.CancelledError:
            context.final_status = "cancelled"
            if (context.replacement_stream_started is not None
                    and not context.replacement_stream_completed):
                self._stats["takeover_stream_cancelled"] += 1
                self._record(
                    context,
                    "takeover_stream_cancelled",
                    stage="replacement_stream",
                    reason="CancelledError",
                    exception_type="CancelledError",
                    **self._replacement_metrics(context),
                )
            raise
        except Exception as exc:
            context.final_status = "failed"
            if (context.replacement_stream_started is not None
                    and not context.replacement_stream_completed):
                self._stats["takeover_stream_failed"] += 1
                self._record(
                    context,
                    "takeover_stream_failed",
                    stage="replacement_stream",
                    reason=type(exc).__name__,
                    exception_type=type(exc).__name__,
                    **self._replacement_metrics(context),
                )
                LOG.warning(
                    "R2 replacement stream failed request_id=%s reason=%s",
                    context.request_id,
                    type(exc).__name__,
                )
            else:
                self._record(
                    context,
                    "relay_error",
                    stage="original_or_relay_stream",
                    reason=type(exc).__name__,
                    exception_type=type(exc).__name__,
                )
                LOG.warning(
                    "R2 download relay failed request_id=%s reason=%s",
                    context.request_id,
                    type(exc).__name__,
                )
            if downstream is not None and downstream.prepared:
                if request.transport:
                    request.transport.close()
                return downstream
            return web.Response(status=502, text="R2 download relay failed\n")
        finally:
            if initial_task:
                if not initial_task.done():
                    initial_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    initial_result = await initial_task
                    if initial_result is not upstream:
                        initial_result.close()
            if upstream:
                upstream.close()
            self._release_slot(context)
            context.task = None
            self._contexts.pop(request_id, None)
            self._record_download_summary(context)
            self._write_status()

    def _make_downstream(self, upstream: ClientResponse) -> web.StreamResponse:
        return web.StreamResponse(
            status=upstream.status,
            reason=upstream.reason,
            headers=_response_headers(upstream),
        )

    async def _stream_without_takeover(
        self, request: web.Request, upstream: ClientResponse, context: _RequestContext
    ) -> web.StreamResponse:
        downstream = self._make_downstream(upstream)
        await downstream.prepare(request)
        async for data in upstream.content.iter_chunked(_CHUNK_SIZE):
            await downstream.write(data)
            context.delivered_bytes += len(data)
        await downstream.write_eof()
        context.final_status = "completed"
        return downstream

    def _reserve_slot(self, context: _RequestContext, *, bypass: bool = False) -> bool:
        if context.slot_reserved:
            return True
        if not bypass and self._active_takeovers >= self.max_concurrent:
            return False
        if bypass:
            self._active_direct_takeovers += 1
        else:
            self._active_takeovers += 1
        context.slot_reserved = True
        context.capacity_bypassed = bypass
        context.slot_reserved_at = asyncio.get_running_loop().time()
        self._stats["takeover_started"] += 1
        self._stats["direct_takeover_started" if bypass else "slow_takeover_started"] += 1
        self._write_status()
        return True

    def _release_slot(self, context: _RequestContext) -> None:
        if not context.slot_reserved:
            return
        now = asyncio.get_running_loop().time()
        if context.slot_reserved_at is not None:
            context.slot_held_ms = round(max(0.0, now - context.slot_reserved_at) * 1000, 2)
        context.slot_reserved = False
        context.slot_reserved_at = None
        if context.capacity_bypassed:
            self._active_direct_takeovers = max(0, self._active_direct_takeovers - 1)
        else:
            self._active_takeovers = max(0, self._active_takeovers - 1)
        self._stats["takeover_slot_released"] += 1
        self._write_status()

    def _observe_rate(self, context: _RequestContext, rate: float | None) -> None:
        if rate is None:
            return
        current = context.min_10s_window_rate_kib_s
        if current is None or rate < current:
            context.min_10s_window_rate_kib_s = round(rate, 2)

    def _set_response_metadata(
        self, context: _RequestContext, response: ClientResponse
    ) -> None:
        context.response_status = response.status
        context.response_content_length = _content_length(response)

    def _should_direct_takeover(
        self, context: _RequestContext, response: ClientResponse
    ) -> bool:
        size = _content_length(response)
        return (
            not context.takeover_attempted
            and context.takeover_skip_reason is None
            and _response_is_takeover_eligible(response, context)
            and size is not None
            and size > self.direct_takeover_threshold_bytes
        )

    async def _consider_takeover(
        self, context: _RequestContext, original: ClientResponse | None, rate: float
    ) -> ClientResponse | None:
        if not context.slow_detected:
            context.slow_detected = True
            self._stats["slow_detected"] += 1
            self._record(context, "slow_detected", rate=rate, stage="slow_window")

        progress = _progress_percent(
            context.delivered_bytes, context.response_content_length
        )
        if progress is not None and progress >= 70.0:
            context.takeover_skip_reason = "DOWNLOAD_70_PERCENT_REACHED"
            self._record(
                context,
                "takeover_skipped",
                rate=rate,
                reason=context.takeover_skip_reason,
                stage="progress_limit",
                extra_fields={"progress_percent": round(progress, 2)},
            )
            return None
        return await self._try_takeover(context, original, rate)

    def _record_download_summary(self, context: _RequestContext) -> None:
        if context.summary_recorded:
            return
        context.summary_recorded = True

        loop = asyncio.get_running_loop()
        duration_ms = round(max(0.0, loop.time() - context.started) * 1000, 2)
        progress = _progress_percent(
            context.delivered_bytes, context.response_content_length
        )

        if context.takeover_skip_reason == "REPLACEMENT_STREAM_STALLED":
            takeover_result = "stalled"
        elif context.replacement_stream_completed:
            takeover_result = "completed"
        elif context.replacement_stream_started is not None:
            if context.final_status == "cancelled":
                takeover_result = "cancelled"
            elif context.final_status == "failed":
                takeover_result = "stream_failed"
            else:
                takeover_result = "succeeded"
        elif context.takeover_attempted:
            takeover_result = "failed"
        elif context.capacity_full_count:
            takeover_result = "not_attempted_capacity_full"
        else:
            takeover_result = "not_attempted"

        if context.final_status == "cancelled":
            skip_reason = "REQUEST_CANCELLED"
        elif context.final_status == "failed":
            if context.takeover_skip_reason == "REPLACEMENT_STREAM_STALLED":
                skip_reason = "REPLACEMENT_STREAM_STALLED"
            elif (context.replacement_stream_started is not None
                    and not context.replacement_stream_completed):
                skip_reason = "REPLACEMENT_STREAM_FAILED"
            elif context.takeover_attempted and context.replacement_stream_started is None:
                skip_reason = "TAKEOVER_FAILED"
            else:
                skip_reason = "RELAY_FAILED"
        elif context.replacement_stream_completed:
            skip_reason = None
        elif context.takeover_skip_reason:
            skip_reason = context.takeover_skip_reason
        elif context.takeover_attempted:
            skip_reason = "TAKEOVER_FAILED"
        elif context.capacity_full_count:
            skip_reason = "CAPACITY_FULL"
        elif not context.slow_detected:
            skip_reason = (
                "INSUFFICIENT_DURATION"
                if duration_ms < self.window_seconds * 1000
                else "THRESHOLD_NOT_REACHED"
            )
        else:
            skip_reason = "TAKEOVER_NOT_PERFORMED"

        self._stats["download_summaries"] += 1
        self._record(
            context,
            "download_summary",
            reason=skip_reason,
            stage="final",
            extra_fields={
                "final_status": context.final_status,
                "response_status": context.response_status,
                "response_content_length": context.response_content_length,
                "duration_ms": duration_ms,
                "progress_percent": round(progress, 2) if progress is not None else None,
                "progress_unknown": progress is None,
                "min_10s_window_rate_kib_s": context.min_10s_window_rate_kib_s,
                "slow_detected": context.slow_detected,
                "capacity_full_count": context.capacity_full_count,
                "takeover_attempted": context.takeover_attempted,
                "takeover_result": takeover_result,
                "trigger": context.takeover_trigger,
                "capacity_bypassed": context.capacity_bypassed,
                "skip_reason": skip_reason,
                "slot_held_ms": context.slot_held_ms,
                "slow_threshold_kib_s": self.threshold_kib_s,
                "slow_window_seconds": self.window_seconds,
            },
        )

    async def _try_takeover(
        self,
        context: _RequestContext,
        original: ClientResponse | None,
        rate: float | None,
        *,
        trigger: str = "slow_speed",
    ) -> ClientResponse | None:
        if context.takeover_attempted:
            return None
        bypass = trigger == "file_size"
        if not self._reserve_slot(context, bypass=bypass):
            context.capacity_full_count += 1
            self._stats["capacity_skipped"] += 1
            if not context.capacity_full_event_recorded:
                context.capacity_full_event_recorded = True
                self._record(
                    context, "capacity_full", rate=rate, stage="capacity_check",
                    extra_fields={"capacity_full_count": context.capacity_full_count},
                )
            else:
                self._write_status()
            return None

        context.takeover_attempted = True
        context.takeover_trigger = trigger
        self._record(context, "takeover_started", rate=rate, stage="replacement_open")
        replacement: ClientResponse | None = None
        stage = "replacement_open"
        loop = asyncio.get_running_loop()
        open_started = loop.time()
        response_status: int | None = None
        response_content_length: int | None = None
        try:
            try:
                replacement = await asyncio.wait_for(
                    self._open_upstream(context, proxy=self.replacement_proxy),
                    timeout=_REPLACEMENT_HEADER_TIMEOUT,
                )
            finally:
                context.replacement_open_ms = (loop.time() - open_started) * 1000

            response_status = replacement.status
            raw_length = replacement.headers.get("Content-Length")
            if raw_length is not None:
                try:
                    response_content_length = int(raw_length)
                except ValueError:
                    response_content_length = None

            stage = "replacement_response_validation"
            if not _response_is_takeover_eligible(replacement, context):
                raise ValueError("replacement_response_not_eligible")
            if bypass and (
                original is None
                or not _same_unstarted_representation(original, replacement)
            ):
                raise ValueError("replacement_validator_mismatch")

            if context.delivered_bytes:
                stage = "prefix_validation"
                prefix_started = loop.time()
                try:
                    if original is None or not _same_representation(original, replacement):
                        raise ValueError("replacement_validator_mismatch")
                    digest = hashlib.sha256()
                    remaining = context.delivered_bytes
                    while remaining:
                        piece = await asyncio.wait_for(
                            replacement.content.read(min(_CHUNK_SIZE, remaining)),
                            timeout=_REPLACEMENT_STREAM_STALL_TIMEOUT,
                        )
                        if not piece:
                            raise ValueError("replacement_prefix_truncated")
                        digest.update(piece)
                        context.prefix_validation_bytes += len(piece)
                        remaining -= len(piece)
                    if digest.digest() != context.delivered_hash.digest():
                        raise ValueError("replacement_prefix_mismatch")
                finally:
                    context.prefix_validation_ms = (loop.time() - prefix_started) * 1000

            context.replacement_stream_started = loop.time()
            self._stats["takeover_succeeded"] += 1
            self._record(
                context,
                "takeover_succeeded",
                rate=rate,
                stage="handoff_ready",
                response_status=response_status,
                response_content_length=response_content_length,
                replacement_open_ms=context.replacement_open_ms,
                prefix_validation_bytes=context.prefix_validation_bytes,
                prefix_validation_ms=context.prefix_validation_ms,
            )
            return replacement
        except asyncio.CancelledError:
            if replacement:
                replacement.close()
            self._record(
                context,
                "takeover_cancelled",
                rate=rate,
                stage=stage,
                reason="CancelledError",
                exception_type="CancelledError",
                replacement_open_ms=context.replacement_open_ms,
                prefix_validation_bytes=context.prefix_validation_bytes,
                prefix_validation_ms=context.prefix_validation_ms,
                response_status=response_status,
                response_content_length=response_content_length,
            )
            self._release_slot(context)
            raise
        except Exception as exc:
            if replacement:
                replacement.close()
            if stage == "prefix_validation" and isinstance(exc, asyncio.TimeoutError):
                self._record_replacement_stream_stalled(context, stage=stage)
                self._release_slot(context)
                raise _ReplacementStreamStalled() from exc
            self._stats["takeover_failed"] += 1
            safe_reasons = {
                "replacement_response_not_eligible", "replacement_validator_mismatch",
                "replacement_prefix_truncated", "replacement_prefix_mismatch",
            }
            reason = (
                str(exc)
                if isinstance(exc, ValueError) and str(exc) in safe_reasons
                else type(exc).__name__
            )
            self._record(
                context,
                "takeover_failed",
                rate=rate,
                stage=stage,
                reason=reason,
                exception_type=type(exc).__name__,
                replacement_open_ms=context.replacement_open_ms,
                prefix_validation_bytes=context.prefix_validation_bytes,
                prefix_validation_ms=context.prefix_validation_ms,
                response_status=response_status,
                response_content_length=response_content_length,
            )
            LOG.warning(
                "R2 takeover failed request_id=%s stage=%s reason=%s",
                context.request_id,
                stage,
                reason,
            )
            self._release_slot(context)
            return None

    def _record_replacement_stream_stalled(
        self, context: _RequestContext, *, stage: str
    ) -> None:
        if context.takeover_skip_reason == "REPLACEMENT_STREAM_STALLED":
            return
        context.final_status = "failed"
        context.takeover_skip_reason = "REPLACEMENT_STREAM_STALLED"
        self._stats["takeover_stream_stalled"] += 1
        self._record(
            context,
            "takeover_stream_stalled",
            stage=stage,
            reason="REPLACEMENT_STREAM_STALLED",
            exception_type="TimeoutError",
            replacement_open_ms=context.replacement_open_ms,
            prefix_validation_bytes=context.prefix_validation_bytes,
            prefix_validation_ms=context.prefix_validation_ms,
            extra_fields={
                "stall_timeout_seconds": _REPLACEMENT_STREAM_STALL_TIMEOUT,
            },
            **self._replacement_metrics(context),
        )
        LOG.warning(
            "R2 replacement stream stalled request_id=%s stage=%s timeout_seconds=%s",
            context.request_id,
            stage,
            _REPLACEMENT_STREAM_STALL_TIMEOUT,
        )

    def _replacement_metrics(self, context: _RequestContext) -> dict[str, int | float | None]:
        started = context.replacement_stream_started
        if started is None:
            return {
                "replacement_bytes": 0,
                "replacement_elapsed_ms": 0.0,
                "replacement_avg_kib_s": None,
            }
        elapsed_ms = max(0.0, (asyncio.get_running_loop().time() - started) * 1000)
        elapsed_seconds = elapsed_ms / 1000
        average = (
            round(context.replacement_bytes / 1024 / elapsed_seconds, 2)
            if elapsed_seconds > 0 else None
        )
        return {
            "replacement_bytes": context.replacement_bytes,
            "replacement_elapsed_ms": round(elapsed_ms, 2),
            "replacement_avg_kib_s": average,
        }

    def _complete_replacement(self, context: _RequestContext) -> None:
        if context.replacement_stream_completed:
            return
        context.replacement_stream_completed = True
        self._stats["takeover_completed"] += 1
        self._record(
            context,
            "takeover_completed",
            stage="replacement_stream_complete",
            replacement_open_ms=context.replacement_open_ms,
            prefix_validation_bytes=context.prefix_validation_bytes,
            prefix_validation_ms=context.prefix_validation_ms,
            **self._replacement_metrics(context),
        )

    def _record(
        self,
        context: _RequestContext,
        result: str,
        rate: float | None = None,
        reason: str | None = None,
        *,
        stage: str | None = None,
        exception_type: str | None = None,
        response_status: int | None = None,
        response_content_length: int | None = None,
        replacement_open_ms: float | None = None,
        prefix_validation_bytes: int | None = None,
        prefix_validation_ms: float | None = None,
        replacement_bytes: int | None = None,
        replacement_elapsed_ms: float | None = None,
        replacement_avg_kib_s: float | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        event: dict[str, Any] = {
            "schema": "iota_r2_download_event_v1",
            "request_id": context.request_id,
            "result": result,
            "rate_kib_s": round(rate, 2) if rate is not None else None,
            "delivered_bytes": context.delivered_bytes,
            "reason": reason,
            "timestamp": time.time(),
        }
        optional_fields = {
            "stage": stage,
            "exception_type": exception_type,
            "response_status": response_status,
            "response_content_length": response_content_length,
            "replacement_open_ms": (
                round(replacement_open_ms, 2) if replacement_open_ms is not None else None
            ),
            "prefix_validation_bytes": prefix_validation_bytes,
            "prefix_validation_ms": (
                round(prefix_validation_ms, 2) if prefix_validation_ms is not None else None
            ),
            "replacement_bytes": replacement_bytes,
            "replacement_elapsed_ms": (
                round(replacement_elapsed_ms, 2)
                if replacement_elapsed_ms is not None else None
            ),
            "replacement_avg_kib_s": replacement_avg_kib_s,
        }
        event.update({key: value for key, value in optional_fields.items() if value is not None})
        if context.takeover_trigger is not None:
            event["trigger"] = context.takeover_trigger
            event["capacity_bypassed"] = context.capacity_bypassed
        if extra_fields:
            event.update(extra_fields)
        self._last_event = event
        self._append_event_history(event)
        self._write_status()

    def _append_event_history(self, event: dict[str, Any]) -> None:
        path = self.event_history_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.parent.chmod(0o700)
            encoded = (
                json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "ab") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())

            with path.open("rb") as stream:
                lines = stream.readlines()
            if len(lines) > _EVENT_HISTORY_LIMIT:
                temp = path.with_name(path.name + ".tmp")
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(b"".join(lines[-_EVENT_HISTORY_LIMIT:]))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, path)
                path.chmod(0o600)
        except OSError:
            LOG.warning("Unable to update private R2 download event history")

    def _write_status(self) -> None:
        path = self.status_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.parent.chmod(0o700)
            payload = {
                "enabled": self.enabled,
                "process_pid": os.getpid(),
                "updated_at": time.time(),
                "relay_ready": self._port is not None,
                "active_takeovers": self._active_takeovers,
                "active_slow_takeovers": self._active_takeovers,
                "active_direct_takeovers": self._active_direct_takeovers,
                "active_total_takeovers": self._active_takeovers + self._active_direct_takeovers,
                "max_concurrent_takeovers": self.max_concurrent,
                "direct_takeover_threshold_mib": self.config["direct_takeover_threshold_mib"],
                "slow_threshold_kib_s": self.threshold_kib_s,
                "slow_window_seconds": self.window_seconds,
                "event_history_file": self.event_history_path.name,
                "event_history_limit": _EVENT_HISTORY_LIMIT,
                **self._stats,
                "last_event": self._last_event,
            }
            temp = path.with_name(path.name + ".tmp")
            fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            os.chmod(temp, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(payload, stream, ensure_ascii=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, path)
            finally:
                temp.unlink(missing_ok=True)
        except OSError:
            LOG.warning("Unable to update private R2 download status")
