"""Manage only our own local subprocesses and private trust bundle."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

import certifi

from tah_control.config import ROOT, Settings, ensure_runtime


def clean_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy",
        "SOCKS_PROXY", "socks_proxy",
    ):
        env.pop(name, None)
    for name in ("XDG_CACHE_HOME", "UV_CACHE_DIR", "PIP_CACHE_DIR",
                 "HF_HOME", "HUGGINGFACE_HUB_CACHE", "TRANSFORMERS_CACHE"):
        if "/Volumes/DevRAM/xdg-cache" in env.get(name, ""):
            env.pop(name, None)
    return env


def save_private(path: Path, contents: bytes) -> None:
    # All generated certificates are public material, but keep state owner-private.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def require_free_port(port: int) -> None:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(f"127.0.0.1:{port} already in use; refusing to take over") from exc


def verify_hosts(host: str, port: int) -> None:
    addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    if addresses != {"127.0.0.1"}:
        raise RuntimeError(f"{host} must resolve only to 127.0.0.1; install marked /etc/hosts entry")


def mitmdump_path() -> Path:
    candidate = Path(sys.executable).resolve().parent / "mitmdump"
    if candidate.is_file():
        return candidate
    located = shutil.which("mitmdump")
    if located:
        return Path(located)
    raise RuntimeError("mitmdump unavailable; install requirements into the active Python environment")


def app_environment(settings: Settings) -> dict[str, str]:
    port = settings.section("proxy")["port"]
    host = settings.section("speedtest")["host"]
    proxy = f"http://127.0.0.1:{port}"
    ca = settings.runtime / "combined-ca.pem"
    return {
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
        "http_proxy": proxy, "https_proxy": proxy,
        "NO_PROXY": f"localhost,127.0.0.1,::1,{host}",
        "no_proxy": f"localhost,127.0.0.1,::1,{host}",
        "ALL_PROXY": "", "all_proxy": "",
        "SSL_CERT_FILE": str(ca),
        "REQUESTS_CA_BUNDLE": str(ca),
        "CURL_CA_BUNDLE": str(ca),
    }


def generate_cas(settings: Settings) -> bool:
    """Generate private trust bundle; require both explicitly configured relay CA files."""
    runtime = ensure_runtime(settings)
    base = Path(certifi.where()).read_bytes().rstrip() + b"\n"
    mitm = runtime / "mitmproxy" / "mitmproxy-ca-cert.pem"
    if not mitm.is_file():
        raise RuntimeError("mitmproxy CA missing after process readiness")
    save_private(runtime / "combined-ca.pem", base + mitm.read_bytes().rstrip() + b"\n")
    certificates = settings.section("certificates")
    sources = [Path(certificates[name]).expanduser()
               for name in ("relay_root_ca", "relay_mitm_ca")]
    if not all(item.is_file() for item in sources):
        (runtime / "relay-upstream-ca.pem").unlink(missing_ok=True)
        return False
    save_private(runtime / "relay-upstream-ca.pem",
                 base + b"".join(item.read_bytes().rstrip() + b"\n" for item in sources))
    return True


def relay_ca_available(settings: Settings) -> bool:
    certs = settings.section("certificates")
    return all(Path(certs[name]).expanduser().is_file()
               for name in ("relay_root_ca", "relay_mitm_ca"))


def start_speedtest(settings: Settings) -> subprocess.Popen | None:
    cfg = settings.section("speedtest")
    if not cfg["enabled"]:
        return None
    verify_hosts(cfg["host"], cfg["port"])
    require_free_port(cfg["port"])
    return subprocess.Popen(
        [sys.executable, "-m", "speedtest.server", "--port", str(cfg["port"]),
         "--mbps", str(cfg["mbps"])],
        cwd=ROOT, env=clean_env(), start_new_session=True,
    )


def start_proxy(settings: Settings) -> subprocess.Popen:
    port = settings.section("proxy")["port"]
    require_free_port(port)
    runtime = ensure_runtime(settings)
    confdir = runtime / "mitmproxy"
    confdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    confdir.chmod(0o700)
    # mitmproxy will generate a new local CA in its private confdir on first start.
    allowed = (r"^((www|c)\.speedtest\.net|iota\.api\.macrocosmos\.ai|"
               r"([a-zA-Z0-9-]+\.)*cloudflarestorage\.com)(:[0-9]+)?$")
    args = [
        str(mitmdump_path()), "--listen-host", "127.0.0.1", "--listen-port", str(port),
        "--allow-hosts", allowed,
        "-s", str(ROOT / "speedtest" / "addon.py"),
        "--set", f"confdir={confdir}",
        "--set", "connection_strategy=lazy",
        "--set", "upstream_cert=false",
        "--set", "flow_detail=0",
        "--set", "termlog_verbosity=warn",
    ]
    if settings.section("r2")["enabled"]:
        args.extend(["-s", str(ROOT / "r2_client" / "addon.py")])
    env = clean_env()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    # Refresh trust from the current on-disk CA files BEFORE accepting uploads.
    # The very first launch only generates mitmproxy CA, then Supervisor restarts it.
    if (runtime / "mitmproxy" / "mitmproxy-ca-cert.pem").is_file():
        generate_cas(settings)
    trust_path = runtime / "relay-upstream-ca.pem"
    relay_ready = relay_ca_available(settings) and trust_path.is_file()
    env["IOTA_RELAY_CA_READY"] = "1" if relay_ready else "0"
    if relay_ready:
        args.extend(["--set", f"ssl_verify_upstream_trusted_ca={trust_path}"])
    return subprocess.Popen(args, cwd=ROOT, env=env, start_new_session=True)


def wait_proxy(settings: Settings, proc: subprocess.Popen, seconds: float = 20) -> None:
    deadline = time.monotonic() + seconds
    port = settings.section("proxy")["port"]
    ca = settings.runtime / "mitmproxy" / "mitmproxy-ca-cert.pem"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"mitmdump startup failed: exit {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                if ca.is_file():
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("mitmdump startup timeout")


def stop_owned(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def verify_local_https(settings: Settings) -> None:
    """Optional live probe, not a prerequisite for offline supervisor operation."""
    from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
    context = ssl.create_default_context(cafile=str(settings.runtime / "combined-ca.pem"))
    port = settings.section("proxy")["port"]
    opener = build_opener(
        ProxyHandler({"https": f"http://127.0.0.1:{port}"}),
        HTTPSHandler(context=context),
    )
    req = Request("https://www.speedtest.net/speedtest-servers-static.php",
                  headers={"User-Agent": "iota-tools-check/1"})
    with opener.open(req, timeout=15) as response:
        if response.status != 200 or b"speedtest.jsqiuying.com" not in response.read():
            raise RuntimeError("proxy server-list rewrite validation failed")
