from ip2fqdn import apihelp

NAME = "mnemonic"
HELP = "mnemonic public passive DNS (no key)"
KIND = "api"
PRESETS = ("api", "passive", "free")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 6.0
TIMEOUT = None
PHASE = 1
PARALLEL = None
KEY = None
KEY_REQUIRED = False
NEEDS = ""
BASE = "https://api.mnemonic.no"
LIMIT = 1000


def _name(record, ip):
    kind = str(record.get("rrtype") or "").lower()
    if kind in ("a", "aaaa") and record.get("answer") == ip:
        return record.get("query")
    if kind == "ptr":
        return record.get("answer")
    return None


async def lookup_all(ips, ctx):
    base = ctx.base_url()

    async def fetch(ip):
        response = await ctx.request(f"{base}/pdns/v3/{ip}", [ip], params={"limit": LIMIT})
        if response.status == 402:
            raise ctx.quota_spent("HTTP 402, resource limit exceeded")
        if response.status != 200:
            ctx.count(f"HTTP {response.status}")
            return None
        found = []
        for record in apihelp.items(apihelp.mapping(response.json()).get("data")):
            name = _name(record, ip)
            if not isinstance(name, str):
                continue
            first = apihelp.date_of(record.get("firstSeenTimestamp"))
            last = apihelp.date_of(record.get("lastSeenTimestamp"))
            found.append(apihelp.Finding(ip, name, "mnemonic passive DNS",
                                         first / 1000 if first else None,
                                         last / 1000 if last else None))
        return found

    async for answer in apihelp.per_ip(ips, ctx, fetch):
        yield answer
