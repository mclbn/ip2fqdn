import dns.rdatatype

from ip2fqdn import aio, dnsclient
from ip2fqdn.common import Finding

NAME = "dns-enum"
HELP = "NS, MX, SOA, ANY and service records of every zone; names pointing to listed IPs"
KIND = "dns"
PRESETS = ("default", "dns", "passive")
PORTS = ()
PROTOCOL = "udp"
NMAP_SERVICES = ()
RATE = 0
TIMEOUT = None
PHASE = 2
PARALLEL = None
NEEDS = "DNS server"
WORKERS = 20
SERVICES = ("_ldap._tcp.dc._msdcs", "_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_vlmcs._tcp",
            "_autodiscover._tcp", "_sip._tls", "_sipfederationtls._tcp", "_xmpp-server._tcp",
            "_xmpp-client._tcp", "_submission._tcp", "_imaps._tcp")
ADDRESS_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


def queries(zone):
    found = [(zone, dns.rdatatype.NS), (zone, dns.rdatatype.MX), (zone, dns.rdatatype.SOA),
             (zone, dns.rdatatype.ANY)]
    found += [(f"{service}.{zone}", dns.rdatatype.SRV) for service in SERVICES]
    return found


def hosts_and_addresses(reply):
    hosts, addresses = [], []
    for rrset in reply.message.answer:
        owner = dnsclient.owner_text(rrset.name)
        for rdata in rrset:
            if rrset.rdtype in ADDRESS_TYPES:
                addresses.append((owner, rdata.address))
                continue
            target = _target(rrset.rdtype, rdata)
            if target is not None and target.to_text() != ".":
                hosts.append(dnsclient.owner_text(target))
    return hosts, addresses


def _target(rdtype, rdata):
    if rdtype in (dns.rdatatype.NS, dns.rdatatype.CNAME, dns.rdatatype.PTR):
        return rdata.target
    if rdtype == dns.rdatatype.MX:
        return rdata.exchange
    if rdtype == dns.rdatatype.SRV:
        return rdata.target
    if rdtype == dns.rdatatype.SOA:
        return rdata.mname
    return None


async def lookup_all(ips, ctx):
    wanted = set(ips)
    jobs = [(zone, query, server) for zone, _ in ctx.zones for query in queries(zone)
            for server in ctx.dns.active()]
    ctx.set_total(len(jobs))
    async for result in aio.stream(jobs, lambda job: _query(job, wanted, ctx), WORKERS):
        ctx.advance()
        if isinstance(result, Exception):
            ctx.failure(result)
            continue
        for finding in result:
            yield finding


async def _query(job, wanted, ctx):
    _, (name, rdtype), server = job
    reply = await ctx.dns.query(server, name, rdtype, counts=rdtype != dns.rdatatype.ANY)
    if reply is None:
        return []
    detail = f"{name} {dns.rdatatype.to_text(rdtype)} @{server.label()}"
    hosts, addresses = hosts_and_addresses(reply)
    found = [Finding(str(address), owner, detail) for owner, address in addresses
             if str(address) in wanted]
    for host in dict.fromkeys(hosts):
        _, resolved = await ctx.dns.addresses(server, host)
        found.extend(Finding(address, host, detail) for address in resolved if address in wanted)
    return found
