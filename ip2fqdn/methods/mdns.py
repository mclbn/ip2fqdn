import asyncio

from ip2fqdn.common import Finding
from ip2fqdn.proto import linklocal

NAME = "mdns"
HELP = "mDNS reverse query to UDP 5353 of every IP (answers on the operator's segment only)"
KIND = "active"
PRESETS = ("active",)
PORTS = (5353,)
PROTOCOL = "udp"
NMAP_SERVICES = ("mdns", "zeroconf")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""


async def lookup(ip, port, ctx):
    query = linklocal.reverse_query(ip)
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(linklocal.Replies,
                                                              remote_addr=(ip, port))
    try:
        names = await linklocal.ask(transport, protocol, query, None, ctx.connect_timeout)
    finally:
        transport.close()
    for name in names or ():
        yield Finding(ip, name, f"{port} mDNS")
