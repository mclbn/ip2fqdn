from ip2fqdn.apiclient import RequestFailed
from ip2fqdn.common import Answer, Finding, parse_date

AUTH_STATUSES = (401, 403)


async def per_ip(ips, ctx, fetch):
    for ip in ips:
        try:
            findings = await fetch(ip)
        except RequestFailed as error:
            ctx.count("failed requests")
            ctx.debug("failed", ip=ip, error=str(error))
            continue
        if findings is not None:
            yield Answer(ip, findings)


def check_status(response, ctx):
    if response.status in AUTH_STATUSES:
        raise ctx.switch_off(f"access refused (HTTP {response.status}), check the API key")


def mapping(value):
    return value if isinstance(value, dict) else {}


def items(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return [value] if isinstance(value, str) else []


def finding(ip, name, detail, when=None):
    return Finding(ip, name, detail, when, when)


def date_of(value):
    if isinstance(value, (int, float)):
        return float(value)
    return parse_date(value)
