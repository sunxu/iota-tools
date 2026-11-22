"""Intercept only the Speedtest server-list endpoint; no request logging."""
from pathlib import Path
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from mitmproxy import http
from tah_control.config import load_settings

port = load_settings().section("speedtest")["port"]
SERVERS_XML = Path(__file__).with_name("servers.xml").read_bytes().replace(b":8877", f":{port}".encode())
NODES = ET.fromstring(SERVERS_XML).findall(".//server")
if len(NODES) != 1 or NODES[0].get("host") != f"speedtest.jsqiuying.com:{port}":
    raise RuntimeError("pinned local server XML is inconsistent")


def request(flow: http.HTTPFlow) -> None:
    req = flow.request
    if (req.method.upper() == "GET" and req.host.lower() in {"www.speedtest.net", "c.speedtest.net"}
            and urlsplit(req.url).path in {"/speedtest-servers-static.php", "/speedtest-servers.php"}):
        flow.response = http.Response.make(200, SERVERS_XML, {
            "Content-Type": "application/xml; charset=utf-8",
            "Cache-Control": "no-store",
        })


class SpeedtestServerListAddon:
    """Expose the existing handler through the mitmdump addon contract."""

    def request(self, flow: http.HTTPFlow) -> None:
        request(flow)


addons = [SpeedtestServerListAddon()]
