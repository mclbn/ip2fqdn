from ip2fqdn.common import Finding

NAME = "nmap-names"
HELP = "names already in the nmap files: user and PTR names, service host names, scripts"
KIND = "file"
PRESETS = ("default", "passive")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = "nmap files"


async def lookup_all(ips, ctx):
    for ip, host in ctx.nmap.hosts.items():
        ctx.done(ip)
        for name, detail, when in host.names:
            yield Finding(ip, name, detail, when, when)
