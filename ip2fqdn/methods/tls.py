from ip2fqdn.proto import certs, net

NAME = "tls"
HELP = "TLS certificate names (CN and SAN), handshake without SNI"
KIND = "active"
PRESETS = ("default", "active", "cert")
PORTS = (443, 8443, 9443, 636, 465, 993, 995, 5986)
PROTOCOL = "tcp"
NMAP_SERVICES = ("https", "ssl")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""


async def lookup(ip, port, ctx):
    async with net.connection(ip, port, ctx.connect_timeout) as (_, writer):
        der = await net.start_tls(writer)
    ctx.tls_answered(ip, port)
    for finding in certs.findings(ip, der, str(port), ctx):
        yield finding
