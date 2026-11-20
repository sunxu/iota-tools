import asyncio
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, PropertyMock, patch

from aiohttp import ClientPayloadError, web
from multidict import CIMultiDict
from mitmproxy import http

from r2_client.download import (
    R2DownloadRouter,
    _RateWindow,
    _REPLACEMENT_STREAM_STALL_TIMEOUT,
    _RequestContext,
    _same_representation,
    _same_unstarted_representation,
    _progress_percent,
)
from r2_client.eligibility import is_r2_object_get
from tah_control.config import Settings, load_settings


HOST = "assets.1234567890abcdef.r2.cloudflarestorage.com"


class EligibilityTests(unittest.TestCase):
    def test_only_https_object_gets(self):
        self.assertTrue(is_r2_object_get("GET", HOST, f"https://{HOST}/object"))
        self.assertFalse(is_r2_object_get("HEAD", HOST, f"https://{HOST}/object"))
        self.assertFalse(is_r2_object_get("GET", HOST, f"https://{HOST}/"))
        self.assertFalse(is_r2_object_get("GET", HOST, f"http://{HOST}/object"))
        self.assertFalse(is_r2_object_get("GET", HOST, f"https://{HOST}/?list-type=2"))
        self.assertFalse(is_r2_object_get("GET", HOST, f"https://{HOST}/?uploadId=x"))
        self.assertFalse(is_r2_object_get("GET", "example.com", "https://example.com/object"))
        self.assertFalse(is_r2_object_get(
            "GET", HOST, f"https://{HOST}/object",
            CIMultiDict({"Range": "bytes=0-1,5-8"}),
        ))

    def test_signed_query_and_single_range_are_kept_eligible(self):
        url = f"https://{HOST}/folder%2Ffile?X-Amz-Signature=abc&versionId=v1"
        self.assertTrue(is_r2_object_get("GET", HOST, url, CIMultiDict({"Range": "bytes=10-"})))


class RateWindowTests(unittest.TestCase):
    def test_first_window_counts_zero_bytes(self):
        window = _RateWindow(100.0, 10)
        self.assertEqual(window.sample(110.0), 0.0)

    def test_threshold_is_strictly_less_than_500_kib_per_second(self):
        exact = _RateWindow(0.0, 10)
        exact.add(1.0, 500 * 1024 * 10)
        self.assertEqual(exact.sample(10.0), 500.0)

        low = _RateWindow(0.0, 10)
        low.add(1.0, 500 * 1024 * 10 - 1)
        self.assertLess(low.sample(10.0), 500.0)


class ProgressTests(unittest.TestCase):
    def test_replacement_stream_stall_timeout_is_30_seconds(self):
        self.assertEqual(_REPLACEMENT_STREAM_STALL_TIMEOUT, 30.0)

    def test_progress_is_unknown_without_a_positive_content_length(self):
        self.assertIsNone(_progress_percent(10, None))
        self.assertIsNone(_progress_percent(10, 0))

    def test_seventy_percent_boundary_is_inclusive(self):
        self.assertEqual(_progress_percent(69, 100), 69.0)
        self.assertEqual(_progress_percent(70, 100), 70.0)
        self.assertEqual(_progress_percent(120, 100), 100.0)


class ValidatorTests(unittest.TestCase):
    def test_midstream_takeover_requires_matching_strong_etag_and_metadata(self):
        old = SimpleNamespace(status=200, headers={
            "ETag": '"v1"', "Content-Length": "100", "Content-Encoding": "identity",
            "Content-Type": "application/octet-stream", "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT",
        })
        new = SimpleNamespace(status=200, headers=dict(old.headers))
        self.assertTrue(_same_representation(old, new))
        new.headers["ETag"] = '"v2"'
        self.assertFalse(_same_representation(old, new))
        new.headers["ETag"] = 'W/"v1"'
        self.assertFalse(_same_representation(old, new))


class DirectResponseValidatorTests(unittest.TestCase):
    def test_rejects_mismatched_length_range_and_etag(self):
        old = SimpleNamespace(status=206, headers={
            "Content-Length": "100", "Content-Range": "bytes 0-99/200",
            "ETag": '"v1"', "Content-Type": "application/octet-stream",
        })
        new = SimpleNamespace(status=206, headers=dict(old.headers))
        self.assertTrue(_same_unstarted_representation(old, new))
        for field, value in (
            ("Content-Length", "99"),
            ("Content-Range", "bytes 100-199/200"),
            ("ETag", '"v2"'),
            ("Content-Type", "text/plain"),
        ):
            new.headers[field] = value
            self.assertFalse(_same_unstarted_representation(old, new), field)
            new.headers[field] = old.headers[field]

    def test_no_etag_can_match_when_other_metadata_matches(self):
        old = SimpleNamespace(status=200, headers={"Content-Length": "100"})
        new = SimpleNamespace(status=200, headers={"Content-Length": "100"})
        self.assertTrue(_same_unstarted_representation(old, new))


class DownloadRouterUnitTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._runtime_tmp = tempfile.TemporaryDirectory()
        self._runtime_patch = patch.object(
            Settings,
            "runtime",
            new_callable=PropertyMock,
            return_value=Path(self._runtime_tmp.name),
        )
        self._runtime_patch.start()
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "config.toml"
            local.write_text(
                '[r2.download]\nslow_threshold_kib_s=5\nslow_window_seconds=1\n'
                'replacement_proxy="http://127.0.0.1:7893"\nmax_concurrent_takeovers=2\n'
            )
            self.settings = load_settings(local)
        self.router = R2DownloadRouter(self.settings)
        await self.router.running()

    async def asyncTearDown(self):
        try:
            await self.router.done()
        finally:
            self._runtime_patch.stop()
            self._runtime_tmp.cleanup()

    async def _run_replacement_stall_case(
        self, *, original_prefix: bytes, replacement_prefix: bytes, expected_stage: str
    ):
        body = bytes(range(64))
        stall_release = asyncio.Event()
        proxy_seen = asyncio.Event()
        origin_requests = 0
        proxy_requests = 0

        async def slow_origin(request):
            nonlocal origin_requests
            origin_requests += 1
            response = web.StreamResponse(
                status=200,
                headers={"ETag": '"same-object"', "Content-Length": str(len(body)),
                         "Content-Type": "application/octet-stream"},
            )
            await response.prepare(request)
            if original_prefix:
                await response.write(original_prefix)
            await stall_release.wait()
            if request.transport:
                request.transport.close()
            return response

        async def replacement_proxy(request):
            nonlocal proxy_requests
            proxy_requests += 1
            response = web.StreamResponse(
                status=200,
                headers={"ETag": '"same-object"', "Content-Length": str(len(body)),
                         "Content-Type": "application/octet-stream"},
            )
            await response.prepare(request)
            proxy_seen.set()
            if replacement_prefix:
                await response.write(replacement_prefix)
            await stall_release.wait()
            if request.transport:
                request.transport.close()
            return response

        async def start_server(handler):
            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", handler)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            return runner, port

        slow_runner, slow_port = await start_server(slow_origin)
        proxy_runner, proxy_port = await start_server(replacement_proxy)
        self.router.replacement_proxy = f"http://127.0.0.1:{proxy_port}"
        request_id = f"stall-{expected_stage}"
        context = _RequestContext(
            request_id=request_id,
            url=f"http://127.0.0.1:{slow_port}/object?signature=unchanged",
            headers=((b"Host", f"127.0.0.1:{slow_port}".encode()),),
            client_id="stall-test-client",
            range_requested=False,
            started=asyncio.get_running_loop().time(),
        )
        self.router._contexts[request_id] = context
        try:
            with patch("r2_client.download._REPLACEMENT_STREAM_STALL_TIMEOUT", 0.05):
                async with ClientSessionForTest() as client:
                    response = await client.get(
                        f"http://127.0.0.1:{self.router._port}/{request_id}",
                        headers={
                            "X-Iota-Download-Token": self.router._token,
                            "X-Iota-Download-Request": request_id,
                        },
                    )
                    expected_prefix = original_prefix or replacement_prefix
                    if expected_prefix:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(
                            await response.content.readexactly(len(expected_prefix)),
                            expected_prefix,
                        )
                        with self.assertRaises(ClientPayloadError):
                            await response.read()
                    else:
                        self.assertEqual(response.status, 502)
                        self.assertIn("stalled", await response.text())

            await asyncio.wait_for(proxy_seen.wait(), timeout=1.0)
            events = [
                json.loads(line)
                for line in self.router.event_history_path.read_text().splitlines()
            ]
            stalled = [event for event in events if event["result"] == "takeover_stream_stalled"]
            self.assertEqual(len(stalled), 1)
            self.assertEqual(stalled[0]["stage"], expected_stage)
            self.assertEqual(stalled[0]["reason"], "REPLACEMENT_STREAM_STALLED")
            self.assertEqual(stalled[0]["stall_timeout_seconds"], 0.05)
            summary = next(event for event in events if event["result"] == "download_summary")
            self.assertEqual(summary["final_status"], "failed")
            self.assertEqual(summary["takeover_result"], "stalled")
            self.assertEqual(summary["skip_reason"], "REPLACEMENT_STREAM_STALLED")
            self.assertIsNotNone(summary["slot_held_ms"])
            self.assertEqual(origin_requests, 1)
            self.assertEqual(proxy_requests, 1)
            self.assertEqual(self.router._stats["takeover_stream_stalled"], 1)
            self.assertEqual(self.router._stats["takeover_stream_failed"], 0)
            self.assertEqual(self.router._active_takeovers, 0)
            self.assertFalse(context.slot_reserved)
        finally:
            stall_release.set()
            await slow_runner.cleanup()
            await proxy_runner.cleanup()

    async def test_replacement_stream_stall_before_downstream_headers_returns_502(self):
        await self._run_replacement_stall_case(
            original_prefix=b"",
            replacement_prefix=b"",
            expected_stage="replacement_stream",
        )

    async def test_replacement_stream_stall_after_body_starts_closes_partial_response(self):
        await self._run_replacement_stall_case(
            original_prefix=b"",
            replacement_prefix=b"prefix",
            expected_stage="replacement_stream",
        )

    async def test_replacement_prefix_validation_stall_does_not_fall_back(self):
        await self._run_replacement_stall_case(
            original_prefix=b"prefix",
            replacement_prefix=b"",
            expected_stage="prefix_validation",
        )

    async def test_replacement_stream_data_resets_stall_timeout(self):
        body = b"abc"
        stall_release = asyncio.Event()
        proxy_seen = asyncio.Event()

        async def slow_origin(request):
            response = web.StreamResponse(
                status=200,
                headers={"ETag": '"same-object"', "Content-Length": str(len(body)),
                         "Content-Type": "application/octet-stream"},
            )
            await response.prepare(request)
            await stall_release.wait()
            if request.transport:
                request.transport.close()
            return response

        async def replacement_proxy(request):
            response = web.StreamResponse(
                status=200,
                headers={"ETag": '"same-object"', "Content-Length": str(len(body)),
                         "Content-Type": "application/octet-stream"},
            )
            await response.prepare(request)
            proxy_seen.set()
            await response.write(b"a")
            await asyncio.sleep(0.2)
            await response.write(b"b")
            await asyncio.sleep(0.2)
            await response.write(b"c")
            await response.write_eof()
            return response

        async def start_server(handler):
            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", handler)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            return runner, port

        slow_runner, slow_port = await start_server(slow_origin)
        proxy_runner, proxy_port = await start_server(replacement_proxy)
        self.router.replacement_proxy = f"http://127.0.0.1:{proxy_port}"
        request_id = "stall-reset-test"
        context = _RequestContext(
            request_id=request_id,
            url=f"http://127.0.0.1:{slow_port}/object",
            headers=((b"Host", f"127.0.0.1:{slow_port}".encode()),),
            client_id="stall-reset-client",
            range_requested=False,
            started=asyncio.get_running_loop().time(),
        )
        self.router._contexts[request_id] = context
        try:
            with patch("r2_client.download._REPLACEMENT_STREAM_STALL_TIMEOUT", 0.3):
                async with ClientSessionForTest() as client:
                    response = await client.get(
                        f"http://127.0.0.1:{self.router._port}/{request_id}",
                        headers={
                            "X-Iota-Download-Token": self.router._token,
                            "X-Iota-Download-Request": request_id,
                        },
                    )
                    self.assertEqual(response.status, 200)
                    self.assertEqual(await response.read(), body)

            self.assertTrue(proxy_seen.is_set())
            self.assertEqual(self.router._stats["takeover_completed"], 1)
            self.assertEqual(self.router._stats["takeover_stream_stalled"], 0)
            self.assertEqual(self.router._active_takeovers, 0)
        finally:
            stall_release.set()
            await slow_runner.cleanup()
            await proxy_runner.cleanup()

    async def test_request_is_rewritten_to_private_loopback_relay(self):
        request = http.Request.make("GET", f"https://{HOST}/object?X-Amz-Signature=private",
                                    headers={"Authorization": "private", "Range": "bytes=10-"})
        flow = SimpleNamespace(
            request=request,
            client_conn=SimpleNamespace(id="client-1"),
            metadata={},
        )
        self.router.requestheaders(flow)
        request_id = flow.metadata["iota_r2_download_id"]
        context = self.router._contexts[request_id]
        self.assertEqual(context.url, f"https://{HOST}/object?X-Amz-Signature=private")
        self.assertIn((b"Authorization", b"private"), context.headers)
        self.assertEqual(request.host, "127.0.0.1")
        self.assertEqual(request.port, self.router._port)
        self.assertEqual(request.headers["Host"], f"127.0.0.1:{self.router._port}")
        self.assertNotIn("Authorization", request.headers)
        self.assertEqual(request.headers["X-Iota-Download-Request"], request_id)

    async def test_response_streaming_is_enabled_for_relay_flows(self):
        flow = SimpleNamespace(
            metadata={"iota_r2_download_id": "request"},
            response=SimpleNamespace(stream=False),
        )
        self.router.responseheaders(flow)
        self.assertTrue(flow.response.stream)

    async def test_nonblocking_takeover_limit_is_configured(self):
        contexts = [
            _RequestContext(str(i), "https://example.invalid/x", (), None, False, 0.0)
            for i in range(3)
        ]
        self.assertTrue(self.router._reserve_slot(contexts[0]))
        self.assertTrue(self.router._reserve_slot(contexts[1]))
        self.assertFalse(self.router._reserve_slot(contexts[2]))
        self.router._release_slot(contexts[0])
        self.assertTrue(self.router._reserve_slot(contexts[2]))
        self.assertEqual(self.router._active_takeovers, 2)
        for context in contexts:
            self.router._release_slot(context)

    async def test_direct_threshold_strictly_above_24_mib_and_uses_range_length(self):
        ctx = _RequestContext("size-test", "https://example.invalid/x", (), None, False, 0.0)
        threshold = self.router.direct_takeover_threshold_bytes
        self.assertEqual(threshold, 24 * 1024 * 1024)
        for size, expected in ((threshold - 1, False), (threshold, False), (threshold + 1, True)):
            response = SimpleNamespace(
                status=200, headers=CIMultiDict({"Content-Length": str(size)})
            )
            self.assertEqual(self.router._should_direct_takeover(ctx, response), expected)
        no_length = SimpleNamespace(status=200, headers=CIMultiDict())
        self.assertFalse(self.router._should_direct_takeover(ctx, no_length))
        ctx.range_requested = True
        range_response = SimpleNamespace(
            status=206,
            headers=CIMultiDict({
                "Content-Length": str(16 * 1024 * 1024),
                "Content-Range": f"bytes 0-{16 * 1024 * 1024 - 1}/{100 * 1024 * 1024}",
            }),
        )
        self.assertFalse(self.router._should_direct_takeover(ctx, range_response))
        range_response.headers["Content-Length"] = str(threshold + 1)
        self.assertTrue(self.router._should_direct_takeover(ctx, range_response))

    async def test_direct_takeover_ignores_full_slow_capacity_and_releases_independently(self):
        occupied = [
            _RequestContext(str(i), "https://example.invalid/x", (), None, False, 0.0)
            for i in range(self.router.max_concurrent)
        ]
        for ctx in occupied:
            self.assertTrue(self.router._reserve_slot(ctx))
        target = _RequestContext(
            "direct-size", "https://example.invalid/x", (), None, False,
            asyncio.get_running_loop().time(),
        )
        original = SimpleNamespace(
            status=200,
            headers=CIMultiDict({"Content-Length": "100", "ETag": '"same"'}),
        )
        replacement = SimpleNamespace(
            status=200,
            headers=CIMultiDict({"Content-Length": "100", "ETag": '"same"'}),
        )
        self.router._open_upstream = AsyncMock(return_value=replacement)
        result = await self.router._try_takeover(
            target, original, None, trigger="file_size"
        )
        self.assertIs(result, replacement)
        self.assertTrue(target.slot_reserved)
        self.assertTrue(target.capacity_bypassed)
        self.assertEqual(self.router._active_takeovers, self.router.max_concurrent)
        self.assertEqual(self.router._active_direct_takeovers, 1)
        self.assertEqual(self.router._stats["direct_takeover_started"], 1)
        event = self.router._last_event
        self.assertEqual(event["trigger"], "file_size")
        self.assertTrue(event["capacity_bypassed"])
        self.router._release_slot(target)
        self.router._release_slot(target)
        self.assertEqual(self.router._active_direct_takeovers, 0)
        self.assertEqual(self.router._active_takeovers, self.router.max_concurrent)
        for ctx in occupied:
            self.router._release_slot(ctx)
        self.assertEqual(self.router._active_takeovers, 0)
        self.assertEqual(self.router._stats["takeover_slot_released"], len(occupied) + 1)

    async def test_direct_takeover_rejects_mismatched_response_and_keeps_original(self):
        ctx = _RequestContext(
            "direct-mismatch", "https://example.invalid/x", (), None, False,
            asyncio.get_running_loop().time(),
        )
        original = SimpleNamespace(
            status=200, headers=CIMultiDict({
                "Content-Length": "100", "ETag": '"old"',
            })
        )
        replacement = SimpleNamespace(
            status=200, headers=CIMultiDict({
                "Content-Length": "100", "ETag": '"different"',
            }), close=unittest.mock.Mock(),
        )
        self.router._open_upstream = AsyncMock(return_value=replacement)
        result = await self.router._try_takeover(
            ctx, original, None, trigger="file_size"
        )
        self.assertIsNone(result)
        replacement.close.assert_called_once()
        self.assertTrue(ctx.takeover_attempted)
        self.assertEqual(self.router._stats["takeover_failed"], 1)
        self.assertEqual(self.router._active_direct_takeovers, 0)
        self.assertEqual(self.router._active_takeovers, 0)
        event = self.router._last_event
        self.assertEqual(event["stage"], "replacement_response_validation")
        self.assertEqual(event["reason"], "replacement_validator_mismatch")
        self.assertEqual(event["trigger"], "file_size")
        self.router._record_download_summary(ctx)
        self.assertEqual(self.router._last_event["trigger"], "file_size")

    async def test_capacity_full_does_not_consume_attempt_and_retries_after_release(self):
        occupied = [
            _RequestContext(str(i), "https://example.invalid/x", (), None, False, 0.0)
            for i in range(2)
        ]
        target = _RequestContext(
            "capacity-retry", "https://example.invalid/x", (), None, False,
            asyncio.get_running_loop().time(),
        )
        for context in occupied:
            self.assertTrue(self.router._reserve_slot(context))

        replacement = SimpleNamespace(
            status=200,
            headers=CIMultiDict({"Content-Length": "100"}),
        )
        self.router._open_upstream = AsyncMock(return_value=replacement)

        result = await self.router._try_takeover(target, None, 4.0)
        self.assertIsNone(result)
        self.assertFalse(target.takeover_attempted)
        self.assertEqual(target.capacity_full_count, 1)
        self.assertEqual(self.router._active_takeovers, 2)

        self.router._release_slot(occupied[0])
        result = await self.router._try_takeover(target, None, 4.0)
        self.assertIs(result, replacement)
        self.assertTrue(target.takeover_attempted)
        self.assertTrue(target.slot_reserved)
        self.assertEqual(target.capacity_full_count, 1)
        self.assertEqual(self.router._active_takeovers, 2)

        self.router._release_slot(target)
        self.router._release_slot(occupied[1])
        self.assertEqual(self.router._active_takeovers, 0)
        self.assertEqual(self.router._stats["takeover_slot_released"], 3)

    async def test_slot_release_is_idempotent(self):
        context = _RequestContext(
            "slot-release", "https://example.invalid/x", (), None, False,
            asyncio.get_running_loop().time(),
        )
        self.assertTrue(self.router._reserve_slot(context))
        self.router._release_slot(context)
        self.router._release_slot(context)
        self.assertFalse(context.slot_reserved)
        self.assertEqual(self.router._active_takeovers, 0)
        self.assertEqual(self.router._stats["takeover_slot_released"], 1)
        self.assertGreaterEqual(context.slot_held_ms, 0.0)

    async def test_seventy_percent_progress_skips_takeover(self):
        context = _RequestContext(
            "progress-limit", "https://example.invalid/x", (), None, False,
            asyncio.get_running_loop().time(),
        )
        context.response_content_length = 100
        context.delivered_bytes = 70
        context.final_status = "completed"
        self.router._open_upstream = AsyncMock(side_effect=AssertionError("must not open proxy"))

        result = await self.router._consider_takeover(context, None, 4.0)

        self.assertIsNone(result)
        self.assertEqual(context.takeover_skip_reason, "DOWNLOAD_70_PERCENT_REACHED")
        self.assertFalse(context.takeover_attempted)
        self.router._record_download_summary(context)
        summary = self.router._last_event
        self.assertEqual(summary["result"], "download_summary")
        self.assertEqual(summary["progress_percent"], 70.0)
        self.assertEqual(summary["skip_reason"], "DOWNLOAD_70_PERCENT_REACHED")

    async def test_takeover_failure_persists_safe_stage_and_reason(self):
        context = _RequestContext(
            request_id="failure-test",
            url="https://assets.example.r2.cloudflarestorage.com/object?X-Amz-Signature=private-signature",
            headers=((b"Authorization", b"private-authorization"),),
            client_id="test-client",
            range_requested=False,
            started=asyncio.get_running_loop().time(),
        )
        self.router._open_upstream = AsyncMock(
            side_effect=RuntimeError("private-signature private-authorization")
        )

        result = await self.router._try_takeover(context, None, 4.25)

        self.assertIsNone(result)
        self.assertEqual(self.router._stats["takeover_failed"], 1)
        self.assertEqual(self.router._active_takeovers, 0)
        event = self.router._last_event
        self.assertEqual(event["result"], "takeover_failed")
        self.assertEqual(event["stage"], "replacement_open")
        self.assertEqual(event["reason"], "RuntimeError")
        self.assertEqual(event["exception_type"], "RuntimeError")

        raw = self.router.event_history_path.read_text(encoding="utf-8")
        self.assertNotIn("private-signature", raw)
        self.assertNotIn("private-authorization", raw)
        self.assertNotIn("X-Amz-Signature", raw)

    async def test_event_history_is_private_and_retains_last_1000_events(self):
        context = _RequestContext(
            request_id="history-test",
            url="https://assets.example.r2.cloudflarestorage.com/object",
            headers=(),
            client_id="test-client",
            range_requested=False,
            started=asyncio.get_running_loop().time(),
        )

        path = self.router.event_history_path
        path.write_text(
            "".join(json.dumps({"result": f"test_event_{index}"}) + "\n"
                    for index in range(1000)),
            encoding="utf-8",
        )
        self.router._append_event_history({"result": "test_event_1000"})
        events = [json.loads(line) for line in path.read_text().splitlines()]

        self.assertEqual(len(events), 1000)
        self.assertEqual(events[0]["result"], "test_event_1")
        self.assertEqual(events[-1]["result"], "test_event_1000")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    async def test_direct_takeover_open_failure_continues_original_response(self):
        body = b"original-response-must-remain-complete" * 4
        seen = []

        async def origin(request):
            return web.Response(
                body=body,
                headers={"ETag": '"unchanged"', "Content-Type": "application/octet-stream"},
            )

        app = web.Application()
        app.router.add_get("/object", origin)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        request_id = "failed-direct-continues-original"
        ctx = _RequestContext(
            request_id,
            f"http://127.0.0.1:{port}/object",
            ((b"Host", f"127.0.0.1:{port}".encode()),),
            "direct-failure-client", False, asyncio.get_running_loop().time(),
        )
        self.router._contexts[request_id] = ctx
        self.router.direct_takeover_threshold_bytes = 24
        original_open = self.router._open_upstream

        async def open_upstream(context, proxy=None):
            if proxy:
                seen.append(proxy)
                raise ConnectionError("replacement-unavailable")
            return await original_open(context)

        self.router._open_upstream = open_upstream
        try:
            async with ClientSessionForTest() as client:
                response = await client.get(
                    f"http://127.0.0.1:{self.router._port}/{request_id}",
                    headers={
                        "X-Iota-Download-Token": self.router._token,
                        "X-Iota-Download-Request": request_id,
                    },
                )
                self.assertEqual(response.status, 200)
                self.assertEqual(await response.read(), body)
            self.assertEqual(len(seen), 1)
            self.assertEqual(self.router._stats["takeover_failed"], 1)
            self.assertEqual(self.router._active_direct_takeovers, 0)
            self.assertEqual(self.router._active_takeovers, 0)
            events = [
                json.loads(line) for line in self.router.event_history_path.read_text().splitlines()
            ]
            failure = next(e for e in events if e["result"] == "takeover_failed")
            summary = next(e for e in events if e["result"] == "download_summary")
            self.assertEqual(failure["trigger"], "file_size")
            self.assertEqual(failure["stage"], "replacement_open")
            self.assertEqual(summary["final_status"], "completed")
            self.assertEqual(summary["takeover_result"], "failed")
            self.assertEqual(summary["delivered_bytes"], len(body))
            self.assertTrue(summary["capacity_bypassed"])
        finally:
            await runner.cleanup()

    async def test_direct_takeover_cancel_releases_direct_counter(self):
        ctx = _RequestContext(
            "direct-cancel", "https://example.invalid/x", (), None, False,
            asyncio.get_running_loop().time(),
        )
        original = SimpleNamespace(
            status=200, headers=CIMultiDict({"Content-Length": "100"})
        )
        opened = asyncio.Event()

        async def pending_open(*args, **kwargs):
            opened.set()
            await asyncio.Event().wait()

        self.router._open_upstream = pending_open
        task = asyncio.create_task(
            self.router._try_takeover(ctx, original, None, trigger="file_size")
        )
        await asyncio.wait_for(opened.wait(), timeout=2.0)
        self.assertEqual(self.router._active_direct_takeovers, 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.router._active_direct_takeovers, 0)
        self.assertEqual(self.router._active_takeovers, 0)
        self.assertFalse(ctx.slot_reserved)
        self.assertEqual(self.router._stats["takeover_slot_released"], 1)

    async def test_fast_large_get_direct_takeover_without_waiting_for_slow_window(self):
        body = bytes(range(128))
        seen = []

        async def origin(request):
            return web.Response(
                body=body,
                headers={"ETag": '"v1"', "Content-Type": "application/octet-stream"},
            )

        async def replacement_proxy(request):
            seen.append(request.raw_path)
            return web.Response(
                body=body,
                headers={"ETag": '"v1"', "Content-Type": "application/octet-stream"},
            )

        async def start_server(handler):
            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", handler)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            return runner, port

        origin_runner, origin_port = await start_server(origin)
        proxy_runner, proxy_port = await start_server(replacement_proxy)
        self.router.replacement_proxy = f"http://127.0.0.1:{proxy_port}"
        self.router.direct_takeover_threshold_bytes = 24
        request_id = "fast-direct-size"
        context = _RequestContext(
            request_id,
            f"http://127.0.0.1:{origin_port}/object?signature=unchanged",
            ((b"Host", f"127.0.0.1:{origin_port}".encode()),),
            "direct-test-client", False, asyncio.get_running_loop().time(),
        )
        self.router._contexts[request_id] = context
        try:
            async with ClientSessionForTest() as client:
                response = await client.get(
                    f"http://127.0.0.1:{self.router._port}/{request_id}",
                    headers={
                        "X-Iota-Download-Token": self.router._token,
                        "X-Iota-Download-Request": request_id,
                    },
                )
                self.assertEqual(response.status, 200)
                self.assertEqual(await response.read(), body)

            self.assertEqual(len(seen), 1)
            self.assertIn("signature=unchanged", seen[0])
            self.assertEqual(self.router._stats["takeover_succeeded"], 1)
            self.assertEqual(self.router._stats["direct_takeover_started"], 1)
            self.assertEqual(self.router._stats["slow_takeover_started"], 0)
            self.assertEqual(self.router._active_direct_takeovers, 0)
            events = [
                json.loads(line) for line in self.router.event_history_path.read_text().splitlines()
            ]
            started = next(e for e in events if e["result"] == "takeover_started")
            summary = next(e for e in events if e["result"] == "download_summary")
            self.assertEqual(started["trigger"], "file_size")
            self.assertTrue(started["capacity_bypassed"])
            self.assertEqual(summary["trigger"], "file_size")
            self.assertEqual(summary["takeover_result"], "completed")
            self.assertEqual(summary["delivered_bytes"], len(body))
            self.assertFalse(summary["slow_detected"])
        finally:
            await origin_runner.cleanup()
            await proxy_runner.cleanup()

    async def test_relay_streams_and_takes_over_a_slow_request(self):
        body = bytes(range(256)) * 64
        slow_started = asyncio.Event()
        proxy_seen = asyncio.Event()
        proxy_requests = []

        async def slow_origin(request):
            response = web.StreamResponse(
                status=200,
                headers={"ETag": '"same-object"', "Content-Length": str(len(body)),
                         "Content-Type": "application/octet-stream"},
            )
            await response.prepare(request)
            slow_started.set()
            try:
                for offset in range(0, len(body), 512):
                    await response.write(body[offset:offset + 512])
                    await asyncio.sleep(0.2)
                await response.write_eof()
            except ConnectionResetError:
                pass
            return response

        async def replacement_proxy(request):
            proxy_requests.append((request.raw_path, request.headers.get("X-Test-Header")))
            proxy_seen.set()
            return web.Response(
                body=body,
                headers={"ETag": '"same-object"', "Content-Length": str(len(body)),
                         "Content-Type": "application/octet-stream"},
            )

        async def start_server(handler):
            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", handler)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            return runner, port

        slow_runner, slow_port = await start_server(slow_origin)
        proxy_runner, proxy_port = await start_server(replacement_proxy)
        self.router.replacement_proxy = f"http://127.0.0.1:{proxy_port}"
        request_id = "integration-test"
        context = _RequestContext(
            request_id=request_id,
            url=f"http://127.0.0.1:{slow_port}/object?signature=unchanged",
            headers=((b"Host", f"127.0.0.1:{slow_port}".encode()), (b"X-Test-Header", b"preserved")),
            client_id="test-client",
            range_requested=False,
            started=asyncio.get_running_loop().time(),
        )
        self.router._contexts[request_id] = context
        try:
            async with ClientSessionForTest() as client:
                response = await client.get(
                    f"http://127.0.0.1:{self.router._port}/{request_id}",
                    headers={
                        "X-Iota-Download-Token": self.router._token,
                        "X-Iota-Download-Request": request_id,
                    },
                )
                received = await response.read()
                self.assertEqual(response.status, 200)
            self.assertTrue(slow_started.is_set())
            self.assertTrue(proxy_seen.is_set())
            self.assertEqual(received, body)
            self.assertEqual(len(proxy_requests), 1)
            self.assertIn("signature=unchanged", proxy_requests[0][0])
            self.assertEqual(proxy_requests[0][1], "preserved")
            self.assertEqual(self.router._stats["takeover_succeeded"], 1)
            self.assertEqual(self.router._stats["takeover_completed"], 1)
            self.assertEqual(self.router._active_takeovers, 0)

            events = [
                json.loads(line)
                for line in self.router.event_history_path.read_text().splitlines()
            ]
            succeeded = next(e for e in events if e["result"] == "takeover_succeeded")
            completed = next(e for e in events if e["result"] == "takeover_completed")
            self.assertEqual(
                succeeded["prefix_validation_bytes"],
                succeeded["delivered_bytes"],
            )
            self.assertEqual(
                completed["replacement_bytes"] + succeeded["delivered_bytes"],
                len(body),
            )
            self.assertGreater(completed["replacement_elapsed_ms"], 0)
            self.assertGreater(completed["replacement_avg_kib_s"], 0)
            summary = next(e for e in events if e["result"] == "download_summary")
            self.assertEqual(summary["final_status"], "completed")
            self.assertEqual(summary["takeover_result"], "completed")
            self.assertEqual(summary["progress_percent"], 100.0)
            self.assertIsNotNone(summary["min_10s_window_rate_kib_s"])
            self.assertIsNotNone(summary["slot_held_ms"])
            self.assertEqual(self.router._stats["download_summaries"], 1)
        finally:
            await slow_runner.cleanup()
            await proxy_runner.cleanup()


class ClientSessionForTest:
    async def __aenter__(self):
        from aiohttp import ClientSession
        self.session = ClientSession()
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        await self.session.close()


if __name__ == "__main__":
    unittest.main()
