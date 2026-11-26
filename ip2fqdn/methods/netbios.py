import asyncio
import os
import struct

from ip2fqdn.common import Finding

NAME = "netbios"
HELP = "NetBIOS node status on UDP 137: computer name, workgroup or domain, MAC"
KIND = "active"
PRESETS = ("default", "active", "windows")
PORTS = (137,)
PROTOCOL = "udp"
NMAP_SERVICES = ("netbios-ns",)
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
WILDCARD = b"\x20" + b"CK" + b"A" * 30 + b"\x00"
ATTEMPTS = 2
MAX_REPLY = 64 * 1024
GROUP = 0x8000
DRG = 0x1000
CONFLICT = 0x0800


def request(transaction):
    return struct.pack(">HHHHHH", transaction, 0, 1, 0, 0, 0) + WILDCARD + \
        struct.pack(">HH", 0x21, 1)


def _skip_name(data, offset):
    for _ in range(128):
        if offset >= len(data):
            return None
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length > 63:
            return None
        offset += 1 + length
    return None


def parse_reply(data, transaction):
    if len(data) < 12 or len(data) > MAX_REPLY:
        return None
    reply_id, flags, _, answers = struct.unpack_from(">HHHH", data)
    if reply_id != transaction or not flags & 0x8000 or flags & 0x000F or answers < 1:
        return None
    offset = _skip_name(data, 12)
    if offset is None or offset + 11 > len(data):
        return None
    rr_type, _, _, rdlength = struct.unpack_from(">HHIH", data, offset)
    offset += 10
    if rr_type != 0x21:
        return None
    end = min(len(data), offset + rdlength)
    count = data[offset]
    offset += 1
    names = []
    for _ in range(count):
        if offset + 18 > end:
            break
        raw = data[offset:offset + 15].decode("latin-1").rstrip(" \x00")
        names.append((raw, data[offset + 15], struct.unpack_from(">H", data, offset + 16)[0]))
        offset += 18
    mac = data[offset:offset + 6] if offset + 6 <= end else b""
    return names, mac


def summarize(names, mac):
    usable = [(name, suffix, flags) for name, suffix, flags in names
              if not flags & (DRG | CONFLICT) and "__MSBROWSE__" not in name]
    unique = [(name, suffix) for name, suffix, flags in usable if not flags & GROUP]
    groups = [(name, suffix) for name, suffix, flags in usable if flags & GROUP]
    computer = next((name for name, kind in unique if kind == 0x00), None)
    domain = next((name for name, kind in groups if kind == 0x00), None)
    if domain is None:
        domain = next((name for name, kind in groups + unique if kind in (0x1C, 0x1E, 0x1B,
                                                                          0x1D)), None)
    mac_text = ":".join(f"{byte:02x}" for byte in mac) if len(mac) == 6 and any(mac) else ""
    return computer, domain, mac_text


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies = asyncio.Queue()

    def datagram_received(self, data, address):
        self.replies.put_nowait(data)

    def error_received(self, error):
        self.replies.put_nowait(error)


async def query(ip, port, connect_timeout):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(_Protocol,
                                                              remote_addr=(ip, port))
    try:
        transaction = int.from_bytes(os.urandom(2), "big")
        for _ in range(ATTEMPTS):
            transport.sendto(request(transaction))
            parsed = await _wait_reply(protocol, transaction, connect_timeout)
            if parsed is not None:
                return parsed
        return None
    finally:
        transport.close()


async def _wait_reply(protocol, transaction, connect_timeout):
    try:
        async with asyncio.timeout(connect_timeout):
            while True:
                item = await protocol.replies.get()
                if isinstance(item, Exception):
                    raise item
                parsed = parse_reply(item, transaction)
                if parsed is not None:
                    return parsed
    except TimeoutError:
        return None


async def lookup(ip, port, ctx):
    parsed = await query(ip, port, ctx.connect_timeout)
    if parsed is None:
        return
    computer, domain, mac = summarize(*parsed)
    if not computer:
        return
    detail = [f"{port} NetBIOS <00>"]
    if domain:
        detail.append(f"workgroup or domain {domain}")
    if mac:
        detail.append(f"MAC {mac}")
    yield Finding(ip, computer, ", ".join(detail))
