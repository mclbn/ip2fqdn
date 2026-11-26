from ip2fqdn import apihelp

NAME = "otx"
HELP = "AlienVault OTX passive DNS (key optional: OTX_API_KEY)"
KIND = "api"
PRESETS = ("api", "passive", "free")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 3.6
TIMEOUT = None
PHASE = 1
PARALLEL = None
KEY = "OTX_API_KEY"
KEY_REQUIRED = False
NEEDS = "OTX_API_KEY (optional)"
BASE = "https://otx.alienvault.com"


def pace(key):
    return 0.36 if key else RATE


async def lookup_all(ips, ctx):
    base = ctx.base_url()
    key = ctx.api_key()
    headers = {"X-OTX-API-KEY": key} if key else {}

    async def fetch(ip):
        family = "IPv6" if ":" in ip else "IPv4"
        response = await ctx.request(f"{base}/api/v1/indicators/{family}/{ip}/passive_dns",
                                     [ip], headers=headers)
        apihelp.check_status(response, ctx)
        if response.status == 404:
            return []
        if response.status != 200:
            ctx.count(f"HTTP {response.status}")
            return None
        found = []
        for record in apihelp.items(apihelp.mapping(response.json()).get("passive_dns")):
            if record.get("address") not in (ip, None):
                continue
            first = apihelp.date_of(record.get("first"))
            last = apihelp.date_of(record.get("last"))
            for name in apihelp.as_list(record.get("hostname")):
                found.append(apihelp.Finding(ip, name, "otx passive DNS", first, last))
        return found

    async for answer in apihelp.per_ip(ips, ctx, fetch):
        yield answer
