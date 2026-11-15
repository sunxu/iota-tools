import threading
import unittest
from urllib.error import HTTPError
from urllib.request import build_opener, ProxyHandler

from speedtest.server import make_server


class SpeedtestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", 0, 500)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.opener = build_opener(ProxyHandler({}))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_latency(self):
        with self.opener.open(self.url + "/speedtest/latency.txt") as resp:
            self.assertEqual(resp.read(), b"test=test\n")

    def test_random_bytes(self):
        with self.opener.open(self.url + "/speedtest/random100x200.jpg") as resp:
            self.assertEqual(len(resp.read()), 40000)

    def test_unknown_path(self):
        with self.assertRaises(HTTPError) as error:
            self.opener.open(self.url + "/anything")
        self.assertEqual(error.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
