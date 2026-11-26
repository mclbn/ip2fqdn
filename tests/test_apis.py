import asyncio
import csv
import io
import json
import os
import urllib.parse

import fakes
import pytest
from conftest import DATA_DIR
from helpers import make_run, run_cli

from ip2fqdn import apiclient, dnsclient, runner
from ip2fqdn.methods import internetdb, mnemonic, onyphe, otx, shodan, urlscan, virustotal

API = "127.0.1.80"
DNS = "127.0.1.53"
PUBLIC_24 = "93.184.215."
ALL_API = (shodan, onyphe, internetdb, otx, virustotal, urlscan, mnemonic)


def example(name, replace=True):
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as handle:
        text = handle.read()
    return text.replace("192.0.2.", PUBLIC_24) if replace else text


class ApiFake:
    def __init__(self):
        self.routes = []
        self.requests = []

    def route(self, method, prefix, reply):
        self.routes.insert(0, (method, prefix, reply))

    def handler(self):
        async def handle(reader, writer):
            try:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                method, target, _ = lines[0].split(" ", 2)
                headers = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip()
                           for line in lines[1:] if ":" in line}
                body = await reader.readexactly(int(headers.get("content-length", "0")))
                path, _, query = target.partition("?")
                path = urllib.parse.unquote(path)
                request = {"method": method, "path": path, "headers": headers, "body": body,
                           "query": dict(urllib.parse.parse_qsl(query))}
                self.requests.append(request)
                status, extra, data = 404, {}, b'{"error": "no route"}'
                for verb, prefix, reply in self.routes:
                    if verb == method and path.startswith(prefix):
                        result = reply(request)
                        if asyncio.iscoroutine(result):
                            result = await result
                        if result is None:
                            return
                        status, extra, data = result
                        break
                if isinstance(data, str):
                    data = data.encode()
                extra_lines = "".join(f"{key}: {value}\r\n" for key, value in extra.items())
                writer.write(f"HTTP/1.1 {status} X\r\nContent-Length: {len(data)}\r\n"
                             f"Connection: close\r\n{extra_lines}\r\n".encode() + data)
                await writer.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
        return handle

    def carried(self):
        text = " ".join(r["path"] + " " + json.dumps(r["query"]) + " " +
                        r["body"].decode("latin-1") for r in self.requests)
        return text


@pytest.fixture
def no_pacing(monkeypatch):
    for module in ALL_API:
        monkeypatch.setattr(module, "RATE", 0)
    monkeypatch.setattr(otx, "pace", lambda key: 0)
    monkeypatch.setattr(apiclient, "DEFAULT_WAITS", (0.01, 0.01, 0.01))


@pytest.fixture
def api_lab(no_pacing):
    fake = ApiFake()
    dns_fake = fakes.FakeDns({("dns.google", "A"): ["8.8.8.8"],
                              ("www.sampleresponse.fr", "A"): ["51.83.59.99"]})
    with fakes.FakeNetwork() as network:
        port = network.tcp(API, 0, fake.handler())
        dns_port = fakes.start_dns(network, DNS, dns_fake)
        base = f"http://{API}:{port}"
        environ = {f"IP2FQDN_{module.NAME.upper()}_URL": base for module in ALL_API}
        yield fake, environ, [f"--dns-server={DNS}:{dns_port}"]


def _rows(text):
    return list(csv.DictReader(io.StringIO(text)))


def _ok(text):
    return lambda request: (200, {}, text)


def test_free_services_and_public_address_rule(api_lab):
    fake, environ, argv = api_lab
    environ["VIRUSTOTAL_API_KEY"] = "vt-key"
    fake.route("GET", "/51.83.59.99", _ok(example("internetdb-host.json")))
    fake.route("GET", "/api/v1/indicators/IPv4/8.8.8.8/passive_dns",
               _ok(example("otx-passive-dns-ipv4.json")))
    fake.route("GET", "/pdns/v3/8.8.8.8", _ok(example("mnemonic-pdns-ip-live-8.8.8.8.json")))
    fake.route("GET", "/ip_addresses/1.2.3.4/resolutions",
               _ok(example("virustotal-ip-resolutions.json")))
    fake.route("GET", "/api/v1/search/", _ok(example("urlscan-search.json", False)))
    code, out, err = run_cli(["51.83.59.99", "8.8.8.8", "1.2.3.4", "10.0.0.5", "-m", "free",
                              *argv], environ=environ)
    assert code == 0, err
    rows = {(row["ip"], row["fqdn"], row["source"]): row for row in _rows(out)}
    assert rows[("51.83.59.99", "www.sampleresponse.fr", "internetdb")]["dns"] == "match"
    assert rows[("51.83.59.99", "www.sampleresponse.fr", "internetdb")]["first_seen"] == ""
    assert ("8.8.8.8", "test.domain13.yulua.com", "otx") in rows
    assert ("8.8.8.8", "111001.xyz", "mnemonic") in rows
    assert rows[("1.2.3.4", "foo.com", "virustotal")]["first_seen"].startswith("2020-06-10")
    assert "10.0.0.5" not in fake.carried()
    assert "third-party services: 1 non-public addresses skipped" in err
    vt = [r for r in fake.requests if r["path"].startswith("/ip_addresses")]
    assert vt and all(r["headers"]["x-apikey"] == "vt-key" for r in vt)


def test_protected_dns_and_no_forward_confirm(api_lab, monkeypatch):
    fake, environ, argv = api_lab
    fake.route("GET", "/51.83.59.99", _ok(example("internetdb-host.json")))
    ip, port = argv[0].split("=", 1)[1].split(":")
    monkeypatch.setattr(dnsclient, "resolv_conf_servers",
                        lambda: [dnsclient.DnsServer(ip, int(port), "resolv.conf")])
    base = ["51.83.59.99", "-m", "internetdb"]
    code, out, err = run_cli(base, environ=environ)
    assert code == 0, err
    assert {row["dns"] for row in _rows(out)} == {"match"}
    code, out, err = run_cli([*base, "--protected-dns"], environ=environ)
    assert code == 0, err
    assert "--protected-dns: DNS methods and checks need the client's DNS servers" in err
    assert {row["dns"] for row in _rows(out)} == {""}
    code, out, err = run_cli([*base, "--no-forward-confirm", *argv], environ=environ)
    assert code == 0, err
    assert {row["dns"] for row in _rows(out)} == {""}


def test_shodan_count_plan_and_batch_fallback(api_lab):
    fake, environ, argv = api_lab
    environ["SHODAN_API_KEY"] = "sh-key"
    host = json.loads(example("shodan-host-with-ssl-constructed.json"))

    def single(request):
        ip = request["path"].rsplit("/", 1)[1]
        if ip == PUBLIC_24 + "77":
            return 404, {}, example("shodan-host-404.json")
        return 200, {}, json.dumps(dict(host, ip_str=ip))

    fake.route("GET", "/shodan/host/", single)
    fake.route("GET", "/shodan/host/count", _ok(example(
        "shodan-host-count-ip-facet-constructed.json")))
    ips = [PUBLIC_24 + "10", PUBLIC_24 + "77", PUBLIC_24 + "99", "8.8.4.4"]
    code, out, err = run_cli([*ips, "-m", "shodan", *argv], environ=environ)
    assert code == 0, err
    paths = [r["path"] for r in fake.requests]
    assert paths[0] == "/shodan/host/count"
    assert fake.requests[0]["query"] == {"key": "sh-key", "query": f"net:{PUBLIC_24}0/24",
                                         "facets": "ip:256"}
    assert f"/shodan/host/{PUBLIC_24}99" not in paths
    assert sorted(paths[2:]) == sorted(f"/shodan/host/{ip}" for ip in ips if not
                                       ip.endswith("99"))
    rows = {(row["ip"], row["fqdn"]) for row in _rows(out)}
    assert (PUBLIC_24 + "10", "dns.google") in rows and ("8.8.4.4", "dns.google") in rows
    names = {row["fqdn"] for row in _rows(out)}
    assert "gitlab.com" in names or any("gitlab" in name for name in names)


def test_onyphe_bulk(api_lab):
    fake, environ, argv = api_lab
    environ["ONYPHE_API_KEY"] = "on-key"
    fake.route("POST", "/bulk/summary/ip", _ok(example(
        "onyphe-bulk-summary-ip-constructed.ndjson")))
    code, out, err = run_cli([PUBLIC_24 + "10", "8.8.8.8", PUBLIC_24 + "99", "-m", "onyphe",
                              *argv], environ=environ)
    assert code == 0, err
    assert fake.requests[0]["body"] == f"8.8.8.8\n{PUBLIC_24}10\n{PUBLIC_24}99\n".encode()
    assert fake.requests[0]["headers"]["authorization"] == "bearer on-key"
    names = {(row["ip"], row["fqdn"]) for row in _rows(out)}
    assert (PUBLIC_24 + "10", "www.example.com") in names
    assert (PUBLIC_24 + "10", "example.com") in names
    assert ("8.8.8.8", "google-public-dns-a.google.com") in names
    assert ("8.8.8.8", "google.com") not in names
    assert not any(row["detail"].endswith(" domain") for row in _rows(out))


def test_cache_second_run_and_quota_stop(api_lab, tmp_path, monkeypatch):
    fake, environ, argv = api_lab
    calls = []

    def limited(request):
        calls.append(request["path"])
        if len(calls) > 1:
            return 402, {}, example("mnemonic-pdns-402.json")
        return 200, {}, example("mnemonic-pdns-ip-live-8.8.8.8.json")

    fake.route("GET", "/pdns/v3/", limited)
    output = str(tmp_path / "out.csv")
    code, _, err = run_cli(["8.8.8.8", "9.9.9.9", "-m", "mnemonic", "-o", output, *argv],
                           environ=environ)
    assert code == 0 and "mnemonic: quota spent" in err
    calls.clear()

    async def slow(request):
        await asyncio.sleep(0.5)
        return 200, {}, '{"data": [], "count": 0}'

    fake.route("GET", "/pdns/v3/", slow)
    monkeypatch.setattr(runner, "PROGRESS_EVERY", 0.1)
    code, _, err = run_cli(["8.8.8.8", "9.9.9.9", "-m", "mnemonic", "-o", output, *argv],
                           environ=environ)
    assert code == 0
    assert [r["path"] for r in fake.requests][-1] == "/pdns/v3/9.9.9.9"
    assert sum(r["path"] == "/pdns/v3/8.8.8.8" for r in fake.requests) == 1
    assert "API cache: 1 cached answers used" in err
    progress = [line for line in err.splitlines() if line.startswith("progress ")
                and "mnemonic" in line]
    assert progress and all("mnemonic 1/2" in line for line in progress)
    with open(output, encoding="utf-8") as handle:
        rows = _rows(handle.read())
    assert ("8.8.8.8", "111001.xyz") in {(row["ip"], row["fqdn"]) for row in rows}


def test_missing_key_rules(api_lab):
    _, environ, argv = api_lab
    code, _, err = run_cli(["8.8.8.8", "-m", "shodan", *argv], environ=environ)
    assert code == 2 and "SHODAN_API_KEY is not set" in err
    code, _, err = run_cli(["8.8.8.8", "-m", "api", "--skip", "free", *argv], environ=environ)
    assert code == 0 and "shodan skipped" in err


def test_client_refuses_non_public_addresses():
    async def go():
        run = make_run(["-m", "internetdb"], ips=["8.8.8.8"])
        run.api = apiclient.ApiClient(run.log, {})
        ctx = run.contexts["internetdb"]
        with pytest.raises(RuntimeError, match="non-public"):
            await ctx.request("http://127.0.1.80:2000/x", ["8.8.8.8", "10.0.0.1"])
    asyncio.run(go(), debug=True)


def test_retry_after_and_failures_switch_off(api_lab):
    fake, environ, argv = api_lab
    fake.route("GET", "/", lambda request: (503, {"Retry-After": "0"}, "busy"))
    ips = [f"8.8.{n}.1" for n in range(6)]
    code, _, err = run_cli([*ips, "-m", "internetdb", *argv], environ=environ)
    assert code == 0
    assert "internetdb: 5 requests in a row failed; switched off" in err
    assert len(fake.requests) == 5 * 4


def test_no_answer_is_not_retried(api_lab):
    fake, environ, argv = api_lab
    fake.route("GET", "/", lambda request: None)
    code, _, err = run_cli(["8.8.8.8", "-m", "internetdb", *argv], environ=environ)
    assert code == 0, err
    assert len(fake.requests) == 1
    assert "failed requests: 1" in err


def test_onyphe_bulk_lines_with_ip_lists(api_lab):
    fake, environ, argv = api_lab
    environ["ONYPHE_API_KEY"] = "on-key"
    lines = [
        {"@category": "resolver", "ip": [PUBLIC_24 + "10", "203.0.113.99"],
         "forward": "multi.example.com", "seen_date": "2026-11-20"},
        {"@category": "datascan", "ip": PUBLIC_24 + "11", "hostname": ["web.example.com"]},
        {"@category": "whois", "ip": {"weird": 1}, "hostname": "ignored.example.com"},
        {"@category": "newcategory", "ip": [1, None, ["x"]], "hostname": "also.ignored.com"},
        {"@category": "none", "ip": "8.8.8.8"},
        [PUBLIC_24 + "10"],
    ]
    body = "\n".join(json.dumps(line) for line in lines) + "\n"
    fake.route("POST", "/bulk/summary/ip", lambda request: (200, {}, body))
    code, out, err = run_cli([PUBLIC_24 + "10", PUBLIC_24 + "11", "8.8.8.8", "-m", "onyphe",
                              "--debug", *argv], environ=environ)
    assert code == 0, err
    rows = {(row["ip"], row["fqdn"]) for row in _rows(out)}
    assert (PUBLIC_24 + "10", "multi.example.com") in rows
    assert (PUBLIC_24 + "11", "web.example.com") in rows
    assert ("8.8.8.8", "") in rows
    assert not {name for _, name in rows} & {"ignored.example.com", "also.ignored.com"}
    assert "onyphe bulk lines lines=6 ip_lists=2 categories=datascan:1,none:1,other:2," \
        "resolver:1,whois:1" in err
    assert len(fake.requests) == 1


def test_shodan_batch_accepted_and_range_search(api_lab):
    fake, environ, argv = api_lab
    environ["SHODAN_API_KEY"] = "sh-key"
    host = json.loads(example("shodan-host-with-ssl-constructed.json"))
    facet = {"matches": [], "total": 12,
             "facets": {"ip": [{"count": 1, "value": f"{PUBLIC_24}{n}"} for n in range(1, 13)]}}

    def lookups(request):
        ips = request["path"].rsplit("/", 1)[1].split(",")
        return 200, {}, json.dumps([dict(host, ip_str=ip) for ip in ips])

    def search(request):
        banner = dict(host["data"][0], ip_str=PUBLIC_24 + "1", hostnames=["found.by.search"])
        return 200, {}, json.dumps({"matches": [banner], "total": 1})

    fake.route("GET", "/shodan/host/", lookups)
    fake.route("GET", "/shodan/host/count", _ok(json.dumps(facet)))
    fake.route("GET", "/shodan/host/search", search)
    code, out, err = run_cli(["8.8.4.4", "1.0.0.1", PUBLIC_24 + "1", PUBLIC_24 + "2", "-m",
                              "shodan", "--shodan-search", *argv], environ=environ)
    assert code == 0, err
    paths = [r["path"] for r in fake.requests]
    assert paths == ["/shodan/host/count", "/shodan/host/search", "/shodan/host/1.0.0.1,8.8.4.4"]
    rows = {(row["ip"], row["fqdn"]) for row in _rows(out)}
    assert (PUBLIC_24 + "1", "found.by.search") in rows and ("1.0.0.1", "dns.google") in rows
    assert (PUBLIC_24 + "2", "") in rows


def test_shodan_refused_capabilities_fall_back(api_lab):
    fake, environ, argv = api_lab
    environ["SHODAN_API_KEY"] = "sh-key"
    host = json.loads(example("shodan-host-with-ssl-constructed.json"))

    def lookups(request):
        ip = request["path"].rsplit("/", 1)[1]
        if "," in ip:
            return 401, {}, '{"error": "Requires a higher plan"}'
        return 200, {}, json.dumps(dict(host, ip_str=ip))

    fake.route("GET", "/shodan/host/", lookups)
    fake.route("GET", "/shodan/host/count", lambda request: (403, {}, '{"error": "denied"}'))
    ips = [PUBLIC_24 + "10", PUBLIC_24 + "11", "1.1.2.10", "1.1.2.11", "8.8.4.4"]
    code, out, err = run_cli([*ips, "-m", "shodan", *argv], environ=environ)
    assert code == 0, err
    assert "switched off" not in err
    paths = [r["path"] for r in fake.requests]
    assert paths.count("/shodan/host/count") == 1
    assert sum("," in path for path in paths) == 1
    rows = {(row["ip"], row["fqdn"]) for row in _rows(out)}
    assert all((ip, "dns.google") in rows for ip in ips)


@pytest.mark.parametrize("status, searches", [(403, 1), (503, 4)])
def test_shodan_failed_search_falls_back_to_lookups(api_lab, status, searches):
    fake, environ, argv = api_lab
    environ["SHODAN_API_KEY"] = "sh-key"
    host = json.loads(example("shodan-host-with-ssl-constructed.json"))
    facet = {"matches": [], "total": 12,
             "facets": {"ip": [{"count": 1, "value": f"{PUBLIC_24}{n}"} for n in range(1, 13)]}}
    fake.route("GET", "/shodan/host/", lambda request: (200, {}, json.dumps(dict(
        host, ip_str=request["path"].rsplit("/", 1)[1]))))
    fake.route("GET", "/shodan/host/count", _ok(json.dumps(facet)))
    fake.route("GET", "/shodan/host/search", lambda request: (
        status, {"Retry-After": "0"}, '{"error": "no"}'))
    ips = [PUBLIC_24 + "1", PUBLIC_24 + "2"]
    code, out, err = run_cli([*ips, "-m", "shodan", "--shodan-search", *argv],
                             environ=environ)
    assert code == 0, err
    paths = [r["path"] for r in fake.requests]
    assert paths[:1 + searches] == ["/shodan/host/count"] + ["/shodan/host/search"] * searches
    assert f"/shodan/host/{PUBLIC_24}2" in paths
    rows = {(row["ip"], row["fqdn"]) for row in _rows(out)}
    assert all((ip, "dns.google") in rows for ip in ips)


def test_shodan_invalid_key_switches_off(api_lab):
    fake, environ, argv = api_lab
    environ["SHODAN_API_KEY"] = "bad-key"
    fake.route("GET", "/shodan/host/", lambda request: (401, {}, '{"error": "Invalid key"}'))
    ips = [PUBLIC_24 + "10", PUBLIC_24 + "11", "1.1.2.10", "1.1.2.11", "8.8.4.4"]
    code, _, err = run_cli([*ips, "-m", "shodan", *argv], environ=environ)
    assert code == 0, err
    assert "shodan: access refused (HTTP 401), check the API key; switched off" in err
    paths = [r["path"] for r in fake.requests]
    assert len(paths) == 3 and paths[0] == "/shodan/host/count" and "," in paths[1]


def test_onyphe_invalid_key_format_switches_off(api_lab):
    fake, environ, argv = api_lab
    environ["ONYPHE_API_KEY"] = "bad!key"
    body = example("onyphe-error-3-live.json")
    fake.route("POST", "/bulk/summary/ip", lambda request: (400, {}, body))
    fake.route("GET", "/summary/ip/", lambda request: (400, {}, body))
    code, out, err = run_cli([PUBLIC_24 + "10", PUBLIC_24 + "11", "8.8.8.8", "-m", "onyphe",
                              *argv], environ=environ)
    assert code == 0, err
    assert "onyphe: Onyphe refused the API key (error 3, invalid API key format); check " \
        "ONYPHE_API_KEY; switched off for the run" in err
    assert len(fake.requests) == 1
    assert {row["fqdn"] for row in _rows(out)} == {""}


def test_onyphe_error_number_in_summary(api_lab):
    fake, environ, argv = api_lab
    environ["ONYPHE_API_KEY"] = "on-key"
    body = '{"status": "nok", "error": 1011, "text": "too many results"}'
    fake.route("POST", "/bulk/summary/ip", lambda request: (400, {}, body))
    fake.route("GET", "/summary/ip/", lambda request: (400, {}, body))
    code, _, err = run_cli([PUBLIC_24 + "10", "8.8.8.8", "-m", "onyphe", *argv],
                           environ=environ)
    assert code == 0, err
    assert "HTTP 400, Onyphe error 1011: 2" in err
    assert "shared ranges file missing (run: uv run python -m ip2fqdn.ranges)" in err


@pytest.mark.parametrize("status, body", [
    (200, '{"status": "nok", "error": 12, "text": "access denied"}\n'),
    (403, '{"status": "nok", "error": 12, "text": "access denied"}\n')])
def test_onyphe_falls_back_to_single_lookups(api_lab, status, body):
    fake, environ, argv = api_lab
    environ["ONYPHE_API_KEY"] = "on-key"
    fake.route("POST", "/bulk/summary/ip", lambda request: (status, {}, body))
    fake.route("GET", "/summary/ip/", _ok(example("onyphe-summary-ip-constructed.json")))
    code, out, err = run_cli([PUBLIC_24 + "10", "-m", "onyphe", *argv], environ=environ)
    assert code == 0, err
    assert [r["method"] for r in fake.requests] == ["POST", "GET"]
    assert (PUBLIC_24 + "10", "www.example.com") in {(row["ip"], row["fqdn"])
                                                     for row in _rows(out)}
