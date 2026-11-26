import dns.rdatatype

from ip2fqdn import aio, dnsclient
from ip2fqdn.common import Finding

NAME = "axfr"
HELP = "zone transfers of the zones named with --zones and of the zones learned"
KIND = "dns"
PRESETS = ("default", "dns")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 0
TIMEOUT = None
PHASE = 2
PARALLEL = None
NEEDS = "DNS server"
WORKERS = 10
REVERSE = ("in-addr.arpa", "ip6.arpa")


async def lookup_all(ips, ctx):
    wanted = set(ips)
    jobs = await _jobs(ctx)
    async for result in aio.stream(jobs, lambda job: _transfer(job, wanted, ctx), WORKERS):
        if isinstance(result, Exception):
            ctx.failure(result)
            continue
        for finding in result:
            yield finding


async def _jobs(ctx):
    servers = ctx.dns.active()
    usable = [server for server in servers if server.can_transfer()]
    if len(usable) < len(servers):
        ctx.run.log.note("axfr: no zone transfer through the loopback DNS server of "
                         "/etc/resolv.conf; name the real server with --dns-server")
    jobs, seen = [], set()
    for zone, named in ctx.zones:
        if zone.endswith(REVERSE) or zone in ("in-addr.arpa", "ip6.arpa"):
            continue
        targets = list(usable)
        if named:
            targets += await _own_servers(zone, ctx)
        for server in targets:
            key = (zone, server.ip, server.port)
            if key not in seen:
                seen.add(key)
                jobs.append((zone, server))
    return jobs


async def _own_servers(zone, ctx):
    found = {}
    for server in ctx.dns.active():
        reply = await ctx.dns.query(server, zone, dns.rdatatype.NS)
        if reply is None:
            continue
        for rrset in reply.rrsets(dns.rdatatype.NS):
            for rdata in rrset:
                host = dnsclient.owner_text(rdata.target)
                _, addresses = await ctx.dns.addresses(server, host)
                for address in addresses:
                    found.setdefault(address, dnsclient.DnsServer(address, 53, "zone NS"))
    return list(found.values())


async def _transfer(job, wanted, ctx):
    zone, server = job
    found, status = await dnsclient.transfer(server, zone, ctx.connect_timeout, wanted)
    ctx.debug("transfer", zone=zone, server=server.ip, status=status, found=len(found))
    ctx.count(f"transfers {status}")
    return [Finding(ip, owner, f"AXFR {zone} @{server.label()}") for ip, owner in found]
