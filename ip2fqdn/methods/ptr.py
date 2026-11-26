import dns.rdatatype
import dns.reversename

from ip2fqdn import aio
from ip2fqdn.common import Finding

NAME = "ptr"
HELP = "reverse DNS (PTR) of every IP, asked of every DNS server"
KIND = "dns"
PRESETS = ("default", "dns", "passive")
PORTS = ()
PROTOCOL = "udp"
NMAP_SERVICES = ()
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = "DNS server"
WORKERS_PER_SERVER = 50


async def lookup_all(ips, ctx):
    servers = ctx.dns.active()
    ctx.set_total(len(ips) * len(servers))
    pairs = ((ip, server) for ip in ips for server in servers)
    async for result in aio.stream(pairs, lambda pair: _ptr(pair, ctx),
                                   WORKERS_PER_SERVER * len(servers)):
        ctx.advance()
        if isinstance(result, Exception):
            ctx.failure(result)
            continue
        for finding in result:
            yield finding


async def _ptr(pair, ctx):
    ip, server = pair
    ctx.done(ip)
    name = dns.reversename.from_address(ip.split("%")[0])
    reply = await ctx.dns.query(server, name, dns.rdatatype.PTR)
    if reply is None:
        ctx.timeouts += 1
        return []
    found = []
    for rrset in reply.rrsets(dns.rdatatype.PTR):
        if rrset.name != name:
            continue
        for rdata in rrset:
            found.append(Finding(ip, rdata.target.to_text(omit_final_dot=True),
                                 f"PTR @{server.label()}"))
    return found
