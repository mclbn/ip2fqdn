from ip2fqdn.common import Finding
from ip2fqdn.proto import http, ntlm

NAME = "http-ntlm"
HELP = "first NTLM step over HTTP: WinRM /wsman on 5985/5986, Exchange paths elsewhere"
KIND = "active"
PRESETS = ("default", "active", "windows")
PORTS = (5985, 5986, 443)
PROTOCOL = "tcp"
NMAP_SERVICES = ("wsman", "wsmans")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
WINRM_PORTS = (5985, 5986)
EXCHANGE_PATHS = ("/EWS/", "/Autodiscover/Autodiscover.xml", "/mapi/", "/OAB/", "/Rpc/", "/")


def requests_for(port):
    if port in WINRM_PORTS:
        return [("POST", "/wsman", [("Authorization", f"Negotiate {ntlm.NEGOTIATE_B64}"),
                                    ("Content-Type", "application/soap+xml;charset=UTF-8"),
                                    ("Content-Length", "0")])]
    return [("GET", path, [("Authorization", f"NTLM {ntlm.NEGOTIATE_B64}")])
            for path in EXCHANGE_PATHS]


async def lookup(ip, port, ctx):
    for method, path, headers in requests_for(port):
        response, _ = await http.exchange(ip, port, ctx, method, path, headers)
        if response is None:
            return
        parsed = ntlm.challenge_from_headers(response[1].get("www-authenticate", []))
        if not parsed:
            continue
        ctx.learn_zones(ntlm.zones(parsed))
        for name, detail in ntlm.findings_detail(parsed):
            yield Finding(ip, name, f"{port} {path} {detail}")
        return
