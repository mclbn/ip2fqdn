import struct

from ip2fqdn.proto import certs, net

NAME = "rdp"
HELP = "RDP negotiation on 3389, then TLS: certificate names"
KIND = "active"
PRESETS = ("default", "active", "windows", "cert")
PORTS = (3389,)
PROTOCOL = "tcp"
NMAP_SERVICES = ("ms-wbt-server",)
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
CONNECTION_REQUEST = bytes.fromhex("030000130ee00000000000010008000b000000")
MAX_TPKT = 512
TLS_PROTOCOLS = (1, 2, 8)


def selected_protocol(packet):
    if len(packet) < 11 or packet[0] != 3:
        return None
    length = struct.unpack_from(">H", packet, 2)[0]
    indicator = packet[4]
    if length != len(packet) or indicator + 5 > length or packet[5] & 0xF0 != 0xD0:
        return None
    if indicator < 14 or len(packet) < 19:
        return 0
    if packet[11] != 0x02:
        return None
    return struct.unpack_from("<I", packet, 15)[0]


async def read_tpkt(reader):
    head = await reader.readexactly(4)
    length = struct.unpack_from(">H", head, 2)[0]
    if head[0] != 3 or not 11 <= length <= MAX_TPKT:
        return None
    return head + await reader.readexactly(length - 4)


async def lookup(ip, port, ctx):
    async with net.connection(ip, port, ctx.connect_timeout) as (reader, writer):
        writer.write(CONNECTION_REQUEST)
        await writer.drain()
        packet = await read_tpkt(reader)
        protocol = selected_protocol(packet) if packet else None
        if protocol not in TLS_PROTOCOLS:
            ctx.debug("no TLS offered", ip=ip, port=port, protocol=protocol)
            return
        der = await net.start_tls(writer)
    for finding in certs.findings(ip, der, f"{port} RDP", ctx):
        yield finding
