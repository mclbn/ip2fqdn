import argparse
import asyncio
import os

from ip2fqdn.common import Finding
from ip2fqdn.proto import ber, linklocal

NAME = "snmp"
HELP = "SNMP sysName with community public, then each --snmp-community (v2c and v1)"
KIND = "active"
PRESETS = ("active",)
PORTS = (161,)
PROTOCOL = "udp"
NMAP_SERVICES = ("snmp",)
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
DEFAULT_COMMUNITY = "public"
MAX_COMMUNITY = 255
SYS_NAME = ber.object_identifier("1.3.6.1.2.1.1.5.0")  # SNMPv2-MIB sysName.0 (RFC 3418)
VERSIONS = (1, 0)  # SNMPv2c (RFC 1901), then SNMPv1 (RFC 1157), sent together
GET_REQUEST = 0xA0
GET_RESPONSE = 0xA2


def community(text):
    if not text or len(text.encode("utf-8")) > MAX_COMMUNITY:
        raise argparse.ArgumentTypeError(f"1 to {MAX_COMMUNITY} bytes: {text!r}")
    return text


def add_arguments(group):
    group.add_argument("--snmp-community", type=community, action="append", metavar="NAME",
                       help="community tried after public; repeat for several")


def communities(ctx):
    """public first, then the operator's communities in command-line order, without repeats."""
    return list(dict.fromkeys([DEFAULT_COMMUNITY, *(ctx.option("community") or [])]))


def label(index):
    return DEFAULT_COMMUNITY if index == 0 else f"community {index}"


def get_request(version, name, request_id):
    """GetRequest for sysName.0 (RFC 1157 section 4.1.2, RFC 3416 section 3)."""
    binding = ber.sequence(SYS_NAME, ber.null())
    pdu = ber.sequence(ber.integer(request_id), ber.integer(0), ber.integer(0),
                       ber.sequence(binding), tag=GET_REQUEST)
    return ber.sequence(ber.integer(version), ber.octets(name.encode("utf-8")), pdu)


def sys_name(data, request_ids):
    """sysName in a GetResponse to one of request_ids; None for anything else."""
    tag, content, _ = ber.read(data)
    parts = ber.children(content) if tag == ber.SEQUENCE else []
    if len(parts) < 3 or parts[2][0] != GET_RESPONSE:
        return None
    fields = ber.children(parts[2][1])
    if len(fields) < 4 or fields[0][0] != ber.INTEGER or fields[1][0] != ber.INTEGER:
        return None
    if ber.to_int(fields[0][1]) not in request_ids or ber.to_int(fields[1][1]) != 0:
        return None
    bindings = ber.children(fields[3][1]) if fields[3][0] == ber.SEQUENCE else []
    binding = ber.children(bindings[0][1]) if bindings and bindings[0][0] == ber.SEQUENCE else []
    if len(binding) < 2 or ber.encode(*binding[0]) != SYS_NAME:
        return None
    value_tag, value = binding[1]
    if value_tag != ber.OCTET_STRING:  # v2c exceptions noSuchObject... are 0x80 to 0x82
        return None
    return value.decode("utf-8", "replace").strip("\x00 \t\r\n") or None


async def lookup(ip, port, ctx):
    """One round per community, both versions at once, stopping at the first answer: a device
    that accepts public never receives the operator's communities."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(linklocal.Replies,
                                                              remote_addr=(ip, port))
    try:
        for index, name in enumerate(communities(ctx)):
            ids = set()
            for version in VERSIONS:
                request_id = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
                ids.add(request_id)
                transport.sendto(get_request(version, name, request_id))
            found = await _wait(protocol, ids, ctx, ip)
            if found:
                yield Finding(ip, found, f"{port} SNMP sysName ({label(index)})")
                return
    finally:
        transport.close()


async def _wait(protocol, ids, ctx, ip):
    try:
        async with asyncio.timeout(ctx.connect_timeout):
            while True:
                item = await protocol.replies.get()
                if isinstance(item, Exception):
                    raise item
                try:
                    found = sys_name(item, ids)
                except ber.BerError:
                    ctx.count("unreadable replies")
                    ctx.debug("unreadable reply", ip=ip)
                    continue
                if found:
                    return found
    except TimeoutError:
        return None
