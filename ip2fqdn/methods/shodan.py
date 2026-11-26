import ipaddress

from ip2fqdn import apihelp
from ip2fqdn.apiclient import RequestFailed
from ip2fqdn.common import Answer
from ip2fqdn.proto import certs

NAME = "shodan"
HELP = "Shodan host lookups, planned with free /24 counts (key required: SHODAN_API_KEY)"
KIND = "api"
PRESETS = ("api", "passive")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 1.0
TIMEOUT = None
PHASE = 1
PARALLEL = None
KEY = "SHODAN_API_KEY"
KEY_REQUIRED = True
NEEDS = "SHODAN_API_KEY"
BASE = "https://api.shodan.io"
BATCH = 100
SEARCH_MINIMUM = 10
SEARCH_PAGE = 100
MAX_SEARCH_PAGES = 100


def add_arguments(group):
    group.add_argument("--shodan-search", action="store_true",
                       help="range searches (query credits) for /24 ranges where Shodan "
                            "knows 10 IPs or more")


def group_by_24(ips):
    groups, single = {}, []
    for ip in ips:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            single.append(ip)
            continue
        network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        groups.setdefault(network, []).append(ip)
    for network, members in list(groups.items()):
        if len(members) < 2:
            single.extend(members)
            del groups[network]
    return groups, single


def host_findings(ip, host):
    found = []
    last = apihelp.date_of(host.get("last_update"))
    for name in apihelp.as_list(host.get("hostnames")):
        found.append(apihelp.finding(ip, name, "shodan hostname", last))
    for banner in apihelp.items(host.get("data")):
        found.extend(banner_findings(ip, banner))
    return found


def banner_findings(ip, banner):
    if not isinstance(banner, dict):
        return []
    when = apihelp.date_of(banner.get("timestamp"))
    port = banner.get("port")
    found = [apihelp.finding(ip, name, "shodan hostname", when)
             for name in apihelp.as_list(banner.get("hostnames"))]
    ssl = apihelp.mapping(banner.get("ssl"))
    chain = apihelp.as_list(ssl.get("chain"))
    names = certs.pem_names(chain[0]) if chain else None
    if names is None:
        subject = apihelp.mapping(apihelp.mapping(ssl.get("cert")).get("subject"))
        names = [(name, "CN") for name in apihelp.as_list(subject.get("CN"))]
    found.extend(apihelp.finding(ip, name, f"{port} shodan certificate {where}", when)
                 for name, where in names)
    return found


class _Planner:
    def __init__(self, ctx):
        self.ctx = ctx
        self.base = ctx.base_url()
        self.key = ctx.api_key()
        self.batch_ok = None
        self.count_ok = None
        self.search_ok = None

    async def get(self, path, ips, params=None):
        return await self.ctx.request(f"{self.base}{path}", ips,
                                      params={"key": self.key, **(params or {})})

    async def count(self, network, members):
        if self.count_ok is False:
            return None
        try:
            response = await self.get("/shodan/host/count", members + [network.split("/")[0]],
                                      {"query": f"net:{network}", "facets": "ip:256"})
        except RequestFailed:
            return None
        if response.status != 200:
            self.count_ok = False
            self.ctx.debug("counts refused", status=response.status)
            return None
        document = response.json()
        if not isinstance(document, dict):
            return None
        values = apihelp.items(apihelp.mapping(document.get("facets")).get("ip"))
        known = {}
        for entry in values:
            if isinstance(entry.get("count"), int):
                known[str(entry.get("value"))] = entry["count"]
        if sum(known.values()) != document.get("total"):
            self.ctx.count("facet counts not trusted")
            return None
        return set(known)

    async def lookups(self, ips):
        remaining = list(ips)
        while remaining:
            if self.batch_ok is not False and len(remaining) > 1:
                chunk = remaining[:BATCH]
                answers = await self._batch(chunk)
                if answers is not None:
                    remaining = remaining[len(chunk):]
                    for answer in answers:
                        yield answer
                    continue
            ip = remaining.pop(0)
            answer = await self._single(ip)
            if answer is not None:
                yield answer

    async def _batch(self, chunk):
        try:
            response = await self.get(f"/shodan/host/{','.join(chunk)}", chunk)
        except RequestFailed:
            self.batch_ok = False
            return None
        document = response.json() if response.status == 200 else None
        if not isinstance(document, list):
            self.batch_ok = False
            self.ctx.debug("batch lookups refused", status=response.status)
            return None
        self.batch_ok = True
        hosts = {host.get("ip_str"): host for host in document if isinstance(host, dict)}
        return [Answer(ip, host_findings(ip, hosts[ip]) if ip in hosts else [])
                for ip in chunk]

    async def _single(self, ip):
        try:
            response = await self.get(f"/shodan/host/{ip}", [ip])
        except RequestFailed:
            self.ctx.count("failed requests")
            return None
        apihelp.check_status(response, self.ctx)
        if response.status == 404:
            return Answer(ip, [])
        document = response.json() if response.status == 200 else None
        if not isinstance(document, dict):
            self.ctx.count(f"HTTP {response.status}")
            return None
        return Answer(ip, host_findings(ip, document))

    async def search(self, network, members):
        banners = {ip: [] for ip in members}
        for page in range(1, MAX_SEARCH_PAGES + 1):
            try:
                response = await self.get("/shodan/host/search",
                                          members + [network.split("/")[0]],
                                          {"query": f"net:{network}", "page": page})
            except RequestFailed:
                return None
            if response.status != 200:
                self.search_ok = False
                self.ctx.debug("range searches refused", status=response.status)
                return None
            document = response.json()
            if not isinstance(document, dict):
                return None
            matches = apihelp.items(document.get("matches"))
            for banner in matches:
                if banner.get("ip_str") in banners:
                    banners[banner["ip_str"]].append(banner)
            if len(matches) < SEARCH_PAGE:
                break
        return [Answer(ip, [f for banner in found for f in banner_findings(ip, banner)])
                for ip, found in banners.items()]


async def lookup_all(ips, ctx):
    planner = _Planner(ctx)
    groups, to_look_up = group_by_24(ips)
    for network, members in groups.items():
        known = await planner.count(network, members)
        if known is None:
            to_look_up.extend(members)
            continue
        for ip in members:
            if ip not in known:
                yield Answer(ip, [])
        listed = [ip for ip in members if ip in known]
        if ctx.args.shodan_search and planner.search_ok is not False and \
                len(known) >= SEARCH_MINIMUM and listed:
            answers = await planner.search(network, listed)
            if answers is not None:
                for answer in answers:
                    yield answer
                continue
        to_look_up.extend(listed)
    async for answer in planner.lookups(to_look_up):
        yield answer
