import json
from collections import Counter

from ip2fqdn import apihelp
from ip2fqdn.apiclient import RequestFailed
from ip2fqdn.common import Answer

NAME = "onyphe"
HELP = "Onyphe summary of each IP, in bulk when allowed (key required: ONYPHE_API_KEY)"
KIND = "api"
PRESETS = ("api", "passive")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 1.0
TIMEOUT = None
PHASE = 1
PARALLEL = None
KEY = "ONYPHE_API_KEY"
KEY_REQUIRED = True
NEEDS = "ONYPHE_API_KEY"
BASE = "https://www.onyphe.io/api/v2"
BULK = 100
NO_CREDITS = 1005
INVALID_KEY = 3
NAME_FIELDS = ("hostname", "reverse", "forward")
CATEGORIES = ("datascan", "riskscan", "ip", "pastries", "resolver", "sniffer", "topsite",
              "whois", "none")


def document_ips(document):
    value = document.get("ip") if isinstance(document, dict) else None
    if isinstance(value, str):
        return [value]
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def document_findings(ip, document):
    if not isinstance(document, dict):
        return []
    if document.get("ip") is not None and ip not in document_ips(document):
        return []
    category = document.get("@category") or "?"
    when = apihelp.date_of(document.get("@timestamp")) or apihelp.date_of(
        document.get("seen_date"))
    found = []
    for field in NAME_FIELDS:
        for name in apihelp.as_list(document.get(field)):
            found.append(apihelp.finding(ip, name, f"onyphe {category} {field}", when))
    subject = apihelp.mapping(document.get("subject"))
    for field in ("commonname", "altname"):
        for name in apihelp.as_list(subject.get(field)):
            found.append(apihelp.finding(ip, name, f"onyphe {category} subject.{field}", when))
    return found


def _error_code(document):
    if not isinstance(document, dict) or document.get("status") != "nok":
        return None
    code = document.get("error")
    return code if isinstance(code, int) and not isinstance(code, bool) else 0


def _check_error(document, ctx):
    code = _error_code(document)
    if code == NO_CREDITS:
        raise ctx.quota_spent("Onyphe error 1005, no more credits")
    if code == INVALID_KEY:
        raise ctx.switch_off("Onyphe refused the API key (error 3, invalid API key format); "
                             "check ONYPHE_API_KEY")
    return code is None


def bulk_findings(chunk, body, ctx):
    found = {ip: [] for ip in chunk}
    categories = Counter()
    lines = ip_lists = 0
    for line in body.splitlines():
        lines += 1
        try:
            document = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not _check_error(document, ctx):
            return None
        if not isinstance(document, dict):
            categories["other"] += 1
            continue
        category = document.get("@category")
        categories[category if category in CATEGORIES else "other"] += 1
        ip_lists += isinstance(document.get("ip"), list)
        for ip in document_ips(document):
            if ip in found:
                found[ip].extend(document_findings(ip, document))
    ctx.debug("bulk lines", lines=lines, ip_lists=ip_lists,
              categories=",".join(f"{name}:{n}" for name, n in sorted(categories.items())))
    return found


def _failure(response, document):
    code = _error_code(document)
    return f"HTTP {response.status}" + (f", Onyphe error {code}" if code else "")


class _Client:
    def __init__(self, ctx):
        self.ctx = ctx
        self.base = ctx.base_url()
        self.headers = {"Authorization": f"bearer {ctx.api_key()}"}
        self.bulk_ok = None

    async def bulk(self, chunk):
        body = ("\n".join(chunk) + "\n").encode("ascii")
        try:
            response = await self.ctx.request(f"{self.base}/bulk/summary/ip", chunk,
                                              method="POST", body=body,
                                              headers={**self.headers,
                                                       "Content-Type": "application/json"})
        except RequestFailed:
            self.bulk_ok = False
            return None
        if response.status != 200:
            _check_error(response.json(), self.ctx)
            self.ctx.debug("bulk requests refused", status=response.status)
            self.bulk_ok = False
            return None
        found = bulk_findings(chunk, response.body, self.ctx)
        if found is None:
            self.bulk_ok = False
            return None
        self.bulk_ok = True
        return [Answer(ip, findings) for ip, findings in found.items()]

    async def single(self, ip):
        try:
            response = await self.ctx.request(f"{self.base}/summary/ip/{ip}", [ip],
                                              headers=self.headers)
        except RequestFailed:
            self.ctx.count("failed requests")
            return None
        apihelp.check_status(response, self.ctx)
        document = response.json()
        if not _check_error(document, self.ctx) or response.status != 200:
            self.ctx.count(_failure(response, document))
            return None
        results = apihelp.items(apihelp.mapping(document).get("results"))
        findings = [f for item in results for f in document_findings(ip, item)]
        return Answer(ip, findings)


async def lookup_all(ips, ctx):
    client = _Client(ctx)
    remaining = list(ips)
    while remaining and client.bulk_ok is not False:
        chunk = remaining[:BULK]
        answers = await client.bulk(chunk)
        if answers is None:
            break
        remaining = remaining[len(chunk):]
        for answer in answers:
            yield answer
    for ip in remaining:
        answer = await client.single(ip)
        if answer is not None:
            yield answer
