import asyncio
import ipaddress

from ip2fqdn.common import USER_AGENT
from ip2fqdn.proto import net

MAX_HEAD = 64 * 1024
MAX_FIELDS = 100
MAX_INTERIM = 5
TLS_PORTS = (443, 8443, 5986)


def host_header(ip, port, tls):
    host = f"[{ip}]" if ":" in ip else ip
    if port == (443 if tls else 80):
        return host
    return f"{host}:{port}"


def uses_tls(ip, port, ctx):
    return port in TLS_PORTS or ctx.nmap_tls(ip, port)


def build_request(method, path, host, headers=()):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {USER_AGENT}",
             "Accept: */*"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


async def exchange(ip, port, ctx, method, path, headers=()):
    tls = uses_tls(ip, port, ctx)
    async with net.connection(ip, port, ctx.connect_timeout) as (reader, writer):
        if tls:
            await net.start_tls(writer)
        writer.write(build_request(method, path, host_header(ip, port, tls), headers))
        await writer.drain()
        return await read_response(reader, ctx), tls


async def read_response(reader, ctx=None):
    for _ in range(MAX_INTERIM + 1):
        head = await read_head(reader, ctx)
        if head is None or not 100 <= head[0] < 200:
            return head
    return None


async def read_head(reader, ctx=None):
    try:
        status_line = await _readline(reader)
    except (ValueError, asyncio.LimitOverrunError):
        return None
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or not parts[1].isdigit():
        return None
    fields = {}
    total = len(status_line)
    last = None
    while True:
        try:
            line = await _readline(reader)
        except (ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            _over_limit(ctx)
            break
        total += len(line)
        stripped = line.rstrip(b"\r\n")
        if not stripped:
            break
        if total > MAX_HEAD or sum(len(v) for v in fields.values()) >= MAX_FIELDS:
            _over_limit(ctx)
            break
        last = _add_field(fields, stripped, last)
    return int(parts[1]), fields


async def _readline(reader):
    line = await reader.readline()
    if not line:
        raise asyncio.IncompleteReadError(b"", None)
    return line


def _add_field(fields, line, last):
    text = line.decode("latin-1")
    if text[:1] in (" ", "\t") and last is not None:
        fields[last][-1] += " " + text.strip()
        return last
    name, separator, value = text.partition(":")
    if not separator:
        return last
    key = name.strip().lower()
    fields.setdefault(key, []).append(value.strip())
    return key


def _over_limit(ctx):
    if ctx is not None:
        ctx.debug("HTTP header over the read limit")


def is_ip(text):
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True
