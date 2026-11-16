import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from aiohttp import web
from multidict import CIMultiDict
from mitmproxy import http

from r2_client.download import (
    R2DownloadRouter,
    _RateWindow,
    _RequestContext,
    _same_representation,
)
from r2_client.eligibility import is_r2_object_get
from tah_control.config import load_settings


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


class DownloadRouterUnitTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
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
        await self.router.done()

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
            self.assertEqual(self.router._active_takeovers, 0)
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
