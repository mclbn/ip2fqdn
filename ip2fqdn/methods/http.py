import urllib.parse

from ip2fqdn.common import Finding
from ip2fqdn.proto import http

NAME = "http"
HELP = "GET / on web ports: host name of a Location header"
KIND = "active"
PRESETS = ("default", "active")
PORTS = (80, 8080)
PROTOCOL = "tcp"
NMAP_SERVICES = ("http", "http-alt", "http-proxy")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""


def location_names(values, base):
    names = []
    for value in values:
        try:
            parts = urllib.parse.urlsplit(urllib.parse.urljoin(base, value.strip()))
            host = parts.hostname
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or "@" in parts.netloc or not host:
            continue
        host = host.removesuffix(".")
        if host and not http.is_ip(host):
            names.append(host)
    return names


async def lookup(ip, port, ctx):
    response, tls = await http.exchange(ip, port, ctx, "GET", "/", [("Connection", "close")])
    if response is None:
        return
    status, fields = response
    scheme = "https" if tls else "http"
    base = f"{scheme}://{http.host_header(ip, port, tls)}/"
    for name in location_names(fields.get("location", []), base):
        yield Finding(ip, name, f"{port} Location ({status})")
