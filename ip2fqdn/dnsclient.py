import asyncio
import ipaddress
import struct

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from ip2fqdn.addresses import is_public
from ip2fqdn.common import UsageError

ATTEMPT_TIMEOUT = 2.0
ATTEMPTS = 2
DROP_AFTER = 20
PER_SERVER = 50
MAX_CNAME_HOPS = 8
TRANSFER_IDLE = 60.0
MAX_TRANSFER_RECORDS = 1_000_000
RESOLV_CONF = "/etc/resolv.conf"
ADDRESS_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


class DnsServer:
    def __init__(self, ip, port=53, origin="named"):
        self.ip = ip
        self.port = port
        self.origin = origin
        self.loopback = ipaddress.ip_address(ip.split("%")[0]).is_loopback
        self.semaphore = asyncio.Semaphore(PER_SERVER)
        self.unanswered = 0
        self.dropped = False

    def label(self):
        if self.port == 53:
            return self.ip
        return f"[{self.ip}]:{self.port}" if ":" in self.ip else f"{self.ip}:{self.port}"

    def can_transfer(self):
        return self.origin == "named" or not self.loopback


def parse_servers(text):
    servers = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        ip, port = _split_server(item)
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise UsageError(f"--dns-server: not an IP address: {item}") from None
        if not 0 < port < 65536:
            raise UsageError(f"--dns-server: bad port: {item}")
        servers.append(DnsServer(ip, port, "named"))
    return servers


def _split_server(item):
    try:
        if item.startswith("["):
            address, _, rest = item[1:].partition("]")
            return address, int(rest[1:]) if rest.startswith(":") else 53
        if item.count(":") == 1:
            address, port = item.split(":")
            return address, int(port)
    except ValueError:
        raise UsageError(f"--dns-server: bad port: {item}") from None
    return item, 53


def resolv_conf_servers(path=RESOLV_CONF):
    servers = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        servers.append(DnsServer(str(ipaddress.ip_address(parts[1])), 53,
                                                 "resolv.conf"))
                    except ValueError:
                        continue
    except OSError:
        return []
    return servers


def choose_servers(named, resolv, has_private, protected_dns, log):
    protected = protected_dns or has_private
    if named:
        if has_private:
            for server in named:
                if is_public(server.ip):
                    log.note(f"internal addresses in the input: DNS server {server.label()} "
                             "has a public address; it receives the internal addresses and "
                             "names of this run")
        servers = named
    elif protected:
        servers = []
    else:
        servers = resolv
    return servers, protected


class Reply:
    def __init__(self, message):
        self.message = message
        self.rcode = message.rcode()

    def rrsets(self, rdtype, section="answer"):
        found = []
        for rrset in getattr(self.message, section):
            if rrset.rdtype == rdtype and rrset.rdclass == dns.rdataclass.IN:
                found.append(rrset)
        return found


class DnsService:
    def __init__(self, servers, log):
        self.servers = servers
        self.log = log
        self.queries = 0

    def active(self):
        return [server for server in self.servers if not server.dropped]

    async def query(self, server, name, rdtype, counts=True):
        if server.dropped:
            return None
        message = dns.message.make_query(name, rdtype)
        async with server.semaphore:
            for _ in range(ATTEMPTS):
                self.queries += 1
                try:
                    response, _ = await dns.asyncquery.udp_with_fallback(
                        message, server.ip, timeout=ATTEMPT_TIMEOUT, port=server.port,
                        ignore_unexpected=True, ignore_errors=True)
                except (dns.exception.DNSException, OSError, EOFError, ValueError):
                    continue
                server.unanswered = 0
                return Reply(response)
        if counts:
            self._unanswered(server)
        return None

    def _unanswered(self, server):
        server.unanswered += 1
        if server.unanswered >= DROP_AFTER and not server.dropped:
            server.dropped = True
            self.log.warning(f"DNS server {server.label()}: {DROP_AFTER} queries in a row "
                          "unanswered, dropped for the run")

    async def addresses(self, server, name):
        statuses = await asyncio.gather(*(self._addresses_of_type(server, name, rdtype)
                                          for rdtype in ADDRESS_TYPES))
        found = set()
        for status, values in statuses:
            if status == "ok":
                found |= values
        if found:
            return "ok", found
        if all(status == "none" for status, _ in statuses):
            return "none", found
        return "error", found

    async def _addresses_of_type(self, server, name, rdtype):
        target = name
        for _ in range(MAX_CNAME_HOPS):
            reply = await self.query(server, target, rdtype)
            if reply is None or reply.rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return "error", set()
            values, alias = _chain(reply, target, rdtype)
            if values:
                return "ok", values
            if alias is None:
                return "none", set()
            target = alias
        return "error", set()

    async def is_zone_apex(self, name):
        for server in self.active():
            reply = await self.query(server, name, dns.rdatatype.SOA)
            if reply is None or reply.rcode != dns.rcode.NOERROR:
                continue
            wanted = dns.name.from_text(name)
            if any(rrset.name == wanted for rrset in reply.rrsets(dns.rdatatype.SOA)):
                return True
        return False


def _chain(reply, name, rdtype):
    start = current = dns.name.from_text(name)
    for _ in range(MAX_CNAME_HOPS + 1):
        values, alias = _scan_answer(reply, current, rdtype)
        if values:
            return values, None
        if alias is None:
            return set(), None if current == start else current.to_text()
        current = alias
    return set(), current.to_text()


def _scan_answer(reply, owner, rdtype):
    values = set()
    alias = None
    for rrset in reply.message.answer:
        if rrset.name != owner or rrset.rdclass != dns.rdataclass.IN:
            continue
        if rrset.rdtype == rdtype:
            values |= {str(ipaddress.ip_address(rdata.address)) for rdata in rrset}
        elif rrset.rdtype == dns.rdatatype.CNAME and len(rrset):
            alias = rrset[0].target
    return values, alias


def owner_text(name):
    return name.to_text(omit_final_dot=True)


async def transfer(server, zone, connect_timeout, wanted, idle=TRANSFER_IDLE,
                   max_records=MAX_TRANSFER_RECORDS):
    origin = dns.name.from_text(zone)
    query = dns.message.make_query(origin, dns.rdatatype.AXFR)
    async with asyncio.timeout(connect_timeout):
        reader, writer = await asyncio.open_connection(server.ip, server.port)
    try:
        wire = query.to_wire()
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        return await _read_transfer(reader, query, origin, wanted, idle, max_records)
    finally:
        writer.transport.abort()


async def _read_transfer(reader, query, origin, wanted, idle, max_records):
    found = []
    soa_seen = records = 0
    first = True
    while True:
        async with asyncio.timeout(idle):
            (length,) = struct.unpack("!H", await reader.readexactly(2))
            data = await reader.readexactly(length)
        message = dns.message.from_wire(data, xfr=True, origin=None)
        if not query.is_response(message, xfr_continuation=not first) or \
                message.rcode() != dns.rcode.NOERROR:
            return found, "refused" if first else "error"
        first = False
        for rrset in message.answer:
            if rrset.rdtype == dns.rdatatype.SOA and rrset.name == origin:
                soa_seen += 1
                if soa_seen == 2:
                    return found, "complete"
                continue
            if not rrset.name.is_subdomain(origin):
                continue
            records += len(rrset)
            if rrset.rdtype in ADDRESS_TYPES and rrset.rdclass == dns.rdataclass.IN:
                for rdata in rrset:
                    address = str(ipaddress.ip_address(rdata.address))
                    if address in wanted:
                        found.append((address, owner_text(rrset.name)))
        if soa_seen == 0:
            return found, "error"
        if records >= max_records:
            return found, "capped"
        await asyncio.sleep(0)
