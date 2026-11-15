"""Local speedtest HTTP server. Based on the original local_speedtest.py."""
import argparse
import math
import re
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_SIZE = 4000
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
_RANDOM_RE = re.compile(r"^/(?:.*/)?random([1-9][0-9]*)x([1-9][0-9]*)\.jpg$")


class _RateLimiter:
    def __init__(self, mbps):
        self.bytes_per_second = mbps * 1_000_000 / 8
        self._lock = threading.Lock()
        self._next_time = time.monotonic()

    def wait_for(self, amount):
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next_time)
            self._next_time = start + amount / self.bytes_per_second
        if start > now:
            time.sleep(start - now)


class _SpeedtestHandler(BaseHTTPRequestHandler):
    server_version = "LocalSpeedtest/1.0"
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(1.0)
        super().setup()

    def log_message(self, *_args):
        return

    def _reply(self, status, body=b"", content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.endswith("/latency.txt") or path == "/latency.txt":
            self._reply(HTTPStatus.OK, b"test=test\n")
            return
        match = _RANDOM_RE.match(path)
        if not match:
            self._reply(HTTPStatus.NOT_FOUND, b"not found\n")
            return
        width, height = (int(value) for value in match.groups())
        if width > MAX_SIZE or height > MAX_SIZE:
            self._reply(HTTPStatus.BAD_REQUEST, b"invalid size\n")
            return
        total = width * height * 2
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(total))
        self.send_header("Connection", "close")
        self.end_headers()
        remaining = total
        try:
            while remaining:
                amount = min(CHUNK_SIZE, remaining)
                self.server.download_limiter.wait_for(amount)
                self.wfile.write(b"\0" * amount)
                remaining -= amount
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        path = urlsplit(self.path).path
        if not path.endswith("/upload.php") and path != "/upload.php":
            self._reply(HTTPStatus.NOT_FOUND, b"not found\n")
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except (TypeError, ValueError):
            self._reply(HTTPStatus.BAD_REQUEST, b"invalid content length\n")
            return
        if length < 0:
            self._reply(HTTPStatus.LENGTH_REQUIRED, b"content length required\n")
            return
        if length > MAX_UPLOAD_BYTES:
            self._reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b"upload too large\n")
            return
        remaining = length
        try:
            while remaining:
                amount = min(CHUNK_SIZE, remaining)
                chunk = self.rfile.read(amount)
                if not chunk:
                    self._reply(HTTPStatus.BAD_REQUEST, b"truncated upload\n")
                    return
                self.server.upload_limiter.wait_for(len(chunk))
                remaining -= len(chunk)
        except TimeoutError:
            self._reply(HTTPStatus.REQUEST_TIMEOUT, b"upload timeout\n")
            return
        except (BrokenPipeError, ConnectionResetError):
            return
        self._reply(HTTPStatus.OK, f"size={length}".encode())


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, mbps):
        super().__init__(address, _SpeedtestHandler)
        if not math.isfinite(mbps) or mbps <= 0:
            raise ValueError("mbps must be a positive finite number")
        self.download_limiter = _RateLimiter(mbps)
        self.upload_limiter = _RateLimiter(mbps)

    def handle_error(self, _request, _client_address):
        return


def make_server(host="127.0.0.1", port=8877, mbps=500):
    return _Server((host, int(port)), float(mbps))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--mbps", type=float, default=500)
    args = parser.parse_args(argv)
    server = make_server("127.0.0.1", args.port, args.mbps)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
