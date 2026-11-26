from ip2fqdn import apihelp

NAME = "urlscan"
HELP = "urlscan.io scans whose page was on the IP: domains (key optional: URLSCAN_API_KEY)"
KIND = "api"
PRESETS = ("api", "passive", "free")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 36.0
TIMEOUT = None
PHASE = 1
PARALLEL = None
KEY = "URLSCAN_API_KEY"
KEY_REQUIRED = False
NEEDS = "URLSCAN_API_KEY (optional)"
BASE = "https://urlscan.io"
PAGE_SIZE = 100


async def lookup_all(ips, ctx):
    base = ctx.base_url()
    key = ctx.api_key()
    headers = {"api-key": key} if key else {}

    async def fetch(ip):
        response = await ctx.request(f"{base}/api/v1/search/", [ip], headers=headers,
                                     params={"q": f'page.ip:"{ip}"', "size": PAGE_SIZE})
        apihelp.check_status(response, ctx)
        if response.status != 200:
            ctx.count(f"HTTP {response.status}")
            return None
        found = []
        for result in apihelp.items(apihelp.mapping(response.json()).get("results")):
            page = apihelp.mapping(result.get("page"))
            if not page or page.get("ip") not in (ip, None):
                continue
            when = apihelp.date_of(apihelp.mapping(result.get("task")).get("time"))
            for field in ("domain", "ptr"):
                for name in apihelp.as_list(page.get(field)):
                    found.append(apihelp.finding(ip, name, f"urlscan page.{field}", when))
        return found

    async for answer in apihelp.per_ip(ips, ctx, fetch):
        yield answer
