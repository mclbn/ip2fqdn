import asyncio

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.reversename

from ip2fqdn.common import Finding

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
ATTEMPTS = 2
MAX_REPLY = 64 * 1024


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies = asyncio.Queue()

    def datagram_received(self, data, address):
        self.replies.put_nowait(data[:MAX_REPLY])

    def error_received(self, error):
        self.replies.put_nowait(error)


def ptr_names(data, query):
    try:
        reply = dns.message.from_wire(data)
    except (dns.exception.DNSException, ValueError):
        return None
    if reply.id != query.id or not reply.flags & dns.flags.QR or \
            reply.rcode() != dns.rcode.NOERROR:
        return None
    wanted = query.question[0].name
    names = []
    for rrset in reply.answer:
        if rrset.rdtype != dns.rdatatype.PTR or rrset.rdclass & 0x7FFF != 1 or \
                rrset.name != wanted:
            continue
        names.extend(rdata.target.to_text(omit_final_dot=True) for rdata in rrset)
    return names


async def lookup(ip, port, ctx):
    query = dns.message.make_query(dns.reversename.from_address(ip.split("%")[0]),
                                   dns.rdatatype.PTR)
    query.flags = 0
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(_Protocol,
                                                              remote_addr=(ip, port))
    try:
        names = None
        for _ in range(ATTEMPTS):
            transport.sendto(query.to_wire())
            names = await _wait(protocol, query, ctx.connect_timeout)
            if names is not None:
                break
    finally:
        transport.close()
    for name in names or ():
        yield Finding(ip, name, f"{port} mDNS")


async def _wait(protocol, query, timeout):
    try:
        async with asyncio.timeout(timeout):
            while True:
                item = await protocol.replies.get()
                if isinstance(item, Exception):
                    raise item
                names = ptr_names(item, query)
                if names is not None:
                    return names
    except TimeoutError:
        return None
