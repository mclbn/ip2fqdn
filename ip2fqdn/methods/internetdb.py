from ip2fqdn import apihelp

NAME = "internetdb"
HELP = "Shodan InternetDB (free, no key): host names from PTR and certificates"
KIND = "api"
PRESETS = ("api", "passive", "free")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 0.2
RATE_BACKOFF = True
TIMEOUT = None
PHASE = 1
PARALLEL = None
KEY = None
KEY_REQUIRED = False
NEEDS = ""
BASE = "https://internetdb.shodan.io"


async def lookup_all(ips, ctx):
    base = ctx.base_url()

    async def fetch(ip):
        response = await ctx.request(f"{base}/{ip}", [ip])
        if response.status == 404:
            return []
        if response.status != 200:
            ctx.count(f"HTTP {response.status}")
            return None
        document = apihelp.mapping(response.json())
        return [apihelp.finding(ip, name, "internetdb hostname")
                for name in apihelp.as_list(document.get("hostnames"))]

    async for answer in apihelp.per_ip(ips, ctx, fetch):
        yield answer
