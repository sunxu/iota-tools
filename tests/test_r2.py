import asyncio
import os
from types import SimpleNamespace
import unittest

from mitmproxy.connection import Server
from r2_client.eligibility import is_upload_part
from r2_client.addon import R2UploadRouter
from tah_control.config import load_settings

HOST = "bucket.r2.cloudflarestorage.com"


def flow(n, method="PUT", host=HOST, url=None):
    return SimpleNamespace(
        request=SimpleNamespace(
            method=method, host=host,
            url=url or f"https://{host}/x?uploadId=abc&partNumber={n}"
        ),
        server_conn=Server(address=(host, 443)),
        client_conn=SimpleNamespace(id=f"client-{n}"),
        response=None,
        error=None,
    )


class R2Predicate(unittest.TestCase):
    def test_exact_upload_part(self):
        self.assertTrue(is_upload_part("PUT", HOST, f"https://{HOST}/?uploadId=x&partNumber=1"))
        self.assertFalse(is_upload_part("GET", HOST, f"https://{HOST}/?uploadId=x&partNumber=1"))
        self.assertFalse(is_upload_part("PUT", HOST, f"https://{HOST}/?uploadId=x"))
        self.assertFalse(is_upload_part("PUT", HOST, f"https://{HOST}/?uploadId=x&partNumber=0"))
        self.assertFalse(is_upload_part("PUT", "other.example.com", f"https://{HOST}/?uploadId=x&partNumber=1"))
        self.assertFalse(is_upload_part("PUT", HOST, f"https://{HOST}/?uploadId=x&uploadId=y&partNumber=1"))


class R2RouterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        os.environ["IOTA_RELAY_CA_READY"] = "1"
        self.router = R2UploadRouter(load_settings())
        self.router.limit_primary = 1

    async def asyncTearDown(self):
        self.router.done()
        os.environ.pop("IOTA_RELAY_CA_READY", None)

    async def test_busy_primary_waits_not_fallback(self):
        first, second = flow(1), flow(2)
        await self.router.requestheaders(first)
        self.assertEqual(first.server_conn.via, self.router.primary)
        task = asyncio.create_task(self.router.requestheaders(second))
        await asyncio.sleep(0.01)
        self.assertFalse(task.done())
        self.router.response(first)
        await asyncio.wait_for(task, 1)
        self.assertEqual(second.server_conn.via, self.router.primary)
        self.assertEqual(self.router.counts["assigned_backup"], 0)

    async def test_waiter_disconnected_is_not_sent(self):
        first, second = flow(1), flow(2)
        await self.router.requestheaders(first)
        waiting = asyncio.create_task(self.router.requestheaders(second))
        await asyncio.sleep(0.01)
        self.router.client_disconnected(second.client_conn)
        await asyncio.wait_for(waiting, 1)
        self.assertIsNone(second.server_conn.via)
        self.assertNotIn(id(second), self.router.assignments)
        self.router.response(first)

    async def test_proxy_error_changes_future_route(self):
        first = flow(1)
        await self.router.requestheaders(first)
        first.error = SimpleNamespace(msg="Error connecting to 127.0.0.1:18585")
        self.router.error(first)
        second = flow(2)
        await self.router.requestheaders(second)
        self.assertEqual(second.server_conn.via, self.router.backup)

    async def test_business_error_does_not_disable_primary(self):
        first = flow(1)
        await self.router.requestheaders(first)
        first.response = SimpleNamespace(status_code=503)
        self.router.response(first)
        second = flow(2)
        await self.router.requestheaders(second)
        self.assertEqual(second.server_conn.via, self.router.primary)

    async def test_get_and_other_paths_passthrough(self):
        for candidate in (flow(1, method="GET"), flow(2, host="iota.api.macrocosmos.ai"),
                          flow(3, url=f"https://{HOST}/?uploadId=x")):
            await self.router.requestheaders(candidate)
            self.assertIsNone(candidate.server_conn.via)
            self.assertNotIn(id(candidate), self.router.assignments)

    async def test_both_routes_fail_closed(self):
        self.router.failed.update({self.router.primary, self.router.backup})
        candidate = flow(1)
        await self.router.requestheaders(candidate)
        self.assertEqual(candidate.response.status_code, 503)
        self.assertIsNone(candidate.server_conn.via)

    async def test_release_on_disconnect(self):
        candidate = flow(1)
        await self.router.requestheaders(candidate)
        self.router.client_disconnected(candidate.client_conn)
        self.assertFalse(self.router.assignments)


if __name__ == "__main__":
    unittest.main()
