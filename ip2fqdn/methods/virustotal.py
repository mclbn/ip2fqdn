from ip2fqdn import apihelp

NAME = "virustotal"
HELP = "VirusTotal resolutions of the IP (free key required: VIRUSTOTAL_API_KEY)"
KIND = "api"
PRESETS = ("api", "passive", "free")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 15.0
TIMEOUT = None
PHASE = 1
PARALLEL = None
KEY = "VIRUSTOTAL_API_KEY"
KEY_REQUIRED = True
NEEDS = "VIRUSTOTAL_API_KEY"
BASE = "https://www.virustotal.com/api/v3"
PAGE_SIZE = 40


async def lookup_all(ips, ctx):
    base = ctx.base_url()
    headers = {"x-apikey": ctx.api_key()}

    async def fetch(ip):
        response = await ctx.request(f"{base}/ip_addresses/{ip}/resolutions", [ip],
                                     headers=headers, params={"limit": PAGE_SIZE},
                                     waits=(60,), quota_after_waits=True)
        apihelp.check_status(response, ctx)
        if response.status == 404:
            return []
        if response.status != 200:
            ctx.count(f"HTTP {response.status}")
            return None
        found = []
        for record in apihelp.items(apihelp.mapping(response.json()).get("data")):
            attributes = apihelp.mapping(record.get("attributes"))
            when = apihelp.date_of(attributes.get("date"))
            for name in apihelp.as_list(attributes.get("host_name")):
                found.append(apihelp.finding(ip, name, "virustotal resolution", when))
        return found

    async for answer in apihelp.per_ip(ips, ctx, fetch):
        yield answer
