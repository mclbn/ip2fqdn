"""Reverse (PTR) queries answered by hosts on the operator's segment: mDNS and LLMNR."""
import asyncio

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.reversename

MAX_REPLY = 64 * 1024
ATTEMPTS = 2


class Replies(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies = asyncio.Queue()

    def datagram_received(self, data, address):
        self.replies.put_nowait(data[:MAX_REPLY])

    def error_received(self, error):
        self.replies.put_nowait(error)


def reverse_query(ip):
    query = dns.message.make_query(dns.reversename.from_address(ip.split("%")[0]),
                                   dns.rdatatype.PTR)
    query.flags = 0
    return query


def ptr_names(data, query):
    """PTR targets answering query, or None when data is not an answer to it."""
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


async def ask(transport, protocol, query, destination, timeout):
    """Names answering query, sent up to ATTEMPTS times; None without an answer."""
    for _ in range(ATTEMPTS):
        transport.sendto(query.to_wire(), destination)
        names = await _wait(protocol, query, timeout)
        if names is not None:
            return names
    return None


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
