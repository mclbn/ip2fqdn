import asyncio
import ipaddress
import socket

from ip2fqdn.common import Finding
from ip2fqdn.proto import linklocal

NAME = "llmnr"
HELP = "LLMNR reverse query by multicast (answers on the operator's segment only, IPv4)"
KIND = "active"
PRESETS = ("active",)
PORTS = (5355,)
PROTOCOL = "udp"
NMAP_SERVICES = ("llmnr",)
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
# RFC 4795 section 2: link-scope group. Unicast queries must go over TCP (section 2.4), and
# Windows listens on no TCP port ([MS-LLMNRP] note 4) and sends PTR queries by multicast.
GROUP_V4 = "224.0.0.252"


async def lookup(ip, port, ctx):
    if ipaddress.ip_address(ip.split("%")[0]).version != 4:
        ctx.count("IPv6 addresses not queried")
        return
    query = linklocal.reverse_query(ip)
    loop = asyncio.get_running_loop()
    # Unconnected socket: the answer comes from the host that owns the address, not the group.
    transport, protocol = await loop.create_datagram_endpoint(linklocal.Replies,
                                                              family=socket.AF_INET)
    try:
        transport.get_extra_info("socket").setsockopt(socket.IPPROTO_IP,
                                                       socket.IP_MULTICAST_TTL, 1)
        names = await linklocal.ask(transport, protocol, query, (GROUP_V4, port),
                                    ctx.connect_timeout)
    finally:
        transport.close()
    for name in names or ():
        yield Finding(ip, name, f"{port} LLMNR")
