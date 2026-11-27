import asyncio
import io
import json
import os

import pytest
from helpers import make_run

from ip2fqdn import cli, dnsclient, merge, nmapxml, runner
from ip2fqdn.addresses import is_public
from ip2fqdn.apicache import ApiCache
from ip2fqdn.common import Answer, Finding, Log, UsageError, sanitize
from ip2fqdn.inputs import read_inputs
from ip2fqdn.names import check_name, is_generic, is_placeholder, name_kind, parent_zone
from ip2fqdn.output import build_rows, csv_text
from ip2fqdn.plan import build_plan, expand, parse_ports

# IANA special-purpose registries (IPv4 and IPv6), block edges; expected value under D24.
SPECIAL_BLOCKS = [
    ("0.0.0.0", False), ("0.255.255.255", False), ("10.0.0.0", False),
    ("10.255.255.255", False), ("100.64.0.0", False), ("100.127.255.255", False),
    ("127.0.0.1", False), ("169.254.0.1", False), ("172.16.0.0", False),
    ("172.31.255.255", False), ("192.0.0.0", False), ("192.0.0.8", False),
    ("192.0.0.9", True), ("192.0.0.10", True), ("192.0.0.170", False), ("192.0.0.171", False),
    ("192.0.0.255", False), ("192.0.2.0", False), ("192.0.2.255", False),
    ("192.31.196.0", True), ("192.52.193.255", True),
    ("192.168.0.0", False), ("192.168.255.255", False), ("192.175.48.1", True),
    ("198.18.0.0", False), ("198.19.255.255", False), ("198.51.100.1", False),
    ("203.0.113.255", False), ("240.0.0.0", False), ("255.255.255.255", False),
    ("224.0.0.1", False), ("239.1.1.1", False), ("8.8.8.8", True), ("1.1.1.1", True),
    ("::", False), ("::1", False), ("::ffff:10.0.0.1", False), ("::10.0.0.1", False),
    ("64:ff9b::10.0.0.1", False), ("64:ff9b::8.8.8.8", False), ("64:ff9b:1::1", False),
    ("100::1", False), ("2001:1::1", True), ("2001:1::2", True), ("2001:2::1", False),
    ("2001:3::1", True), ("2001:4:112::1", True), ("2001:10::1", False),
    ("2001:20::1", True), ("2001:30::1", True), ("2001:db8::1", False),
    ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", False), ("2620:4f:8000::1", True),
    ("fc00::1", False), ("fdff:ffff::1", False), ("fe80::1", False), ("febf::1", False),
    ("ff02::1", False), ("ff0e::1", False), ("2606:4700::1111", True),
    ("not-an-ip", False),
]


@pytest.mark.parametrize(("ip", "expected"), SPECIAL_BLOCKS)
def test_public_address_rule(ip, expected):
    assert is_public(ip) is expected


@pytest.mark.parametrize(("raw", "expected"), [
    ("Host.Example.COM.", "host.example.com"), ("*.example.com", "*.example.com"),
    ("FS01", "fs01"), ("_ldap._tcp.example.com", "_ldap._tcp.example.com"),
    ("10.0.0.1", None), ("bad name.example", None), ("café.example", None),
    ("a..b", None), ("evil.test\x00.good.test", None), ("x" * 64 + ".com", None),
    (".".join(["a" * 60] * 5), None), ("", None), ("*.", None), ("a.*.b", None),
    (None, None), ("xn--caf-dma.example", "xn--caf-dma.example"),
])
def test_check_name(raw, expected):
    assert check_name(raw) == expected


def test_name_kind_and_parent():
    assert [name_kind(name) for name in ("fs01", "pc.local", "*.x.y", "a.b.c")] == \
        ["short", "local", "wildcard", "dotted"]
    assert parent_zone("a.b.example.com") == "b.example.com"
    assert parent_zone("host.example.com") == "example.com"
    assert parent_zone("example.com") is None
    assert parent_zone("fs01") is None


@pytest.mark.parametrize(("name", "ip", "expected"), [
    ("203-0-113-10.static.isp.net", "203.0.113.10", True),
    ("ec2-3-4-5-6.compute-1.amazonaws.com", "3.4.5.6", True),
    ("10.113.0.203.in-addr.example", "203.0.113.10", True),
    ("host203000113010.isp.net", "203.0.113.10", True),
    ("x1203-0-113-10.isp.net", "203.0.113.10", False),
    ("203-0.113-10.isp.net", "203.0.113.10", False),
    ("www.example.com", "203.0.113.10", False),
    ("2001-db8--1.example", "2001:db8::1", False),
])
def test_generic_label(name, ip, expected):
    assert is_generic(name, ip) is expected


@pytest.mark.parametrize(("name", "expected"), [
    ("localhost", True), ("router.localdomain", True), ("www.example.com", True),
    ("kubernetes.default.svc", True), ("unifi", True), ("lab.test", False),
    ("myexample.com", False), ("routerlogin.net", True), ("pfsense.home.arpa", True),
])
def test_placeholder_label(name, expected):
    assert is_placeholder(name) is expected


def _log():
    stream = io.StringIO()
    return Log(stream), stream


def test_inputs_mix_files_ranges_and_stdin(tmp_path, data_dir):
    listing = tmp_path / "list.txt"
    listing.write_text("# comment\n10.0.0.1\n\n10.0.0.2 # trailing\nbad line\n10.0.0.0/30\n")
    log, stream = _log()
    inputs = read_inputs([str(listing), "10.0.0.9", "-",
                          os.path.join(data_dir, "nmap-windows-domain.xml")], 100, log,
                         stdin=io.BytesIO(b"2001:db8::1\n10.0.0.1\n"))
    assert inputs.ips[:6] == ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9",
                              "10.20.30.10"]
    assert inputs.ips[-1] == "2001:db8::1"
    text = stream.getvalue()
    assert f"{listing}:5: not an IP, CIDR range or host name, ignored" in text
    assert "nmap-windows-domain.xml: nmap XML, 4 hosts" in text
    assert "stdin: IP list, 2 entries" in text


@pytest.mark.parametrize(("arguments", "message"), [
    (["nosuchfile"], "not an IP, CIDR range or host name, and no such file"),
    (["*.corp.test"], "not an IP, CIDR range or host name, and no such file"),
    (["scans/a.XML"], "scans/a.XML: no such file"),
    (["10.0.0.0/8"], "more than 1000 IPs"),
    (["2001:db8::/64"], "more than 1000 IPs"),
])
def test_input_errors(arguments, message):
    log, _ = _log()
    with pytest.raises(UsageError, match=message):
        read_inputs(arguments, 1000, log)


def test_large_non_xml_file_refused(tmp_path):
    big = tmp_path / "big.txt"
    with open(big, "wb") as handle:
        handle.truncate((64 << 20) + 1)
    log, _ = _log()
    with pytest.raises(UsageError, match="over 64 MB"):
        read_inputs([str(big)], 10, log)


def test_no_ip_left(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n")
    log, _ = _log()
    with pytest.raises(UsageError, match="no IP to look up"):
        read_inputs([str(empty)], 10, log)


def test_inputs_with_host_names(tmp_path):
    listing = tmp_path / "list.txt"
    listing.write_text("www.corp.test\nDC01\n*.corp.test\nsrv01.corp.local.\n10.0.0.1\n"
                       "WWW.corp.test\n")
    log, stream = _log()
    inputs = read_inputs([str(listing), "app.corp.test", "ips.tx"], 100, log)
    assert inputs.ips == ["10.0.0.1"]
    assert inputs.names == {"www.corp.test": f"{listing}:1", "srv01.corp.local": f"{listing}:4",
                            "app.corp.test": None, "ips.tx": None}
    text = stream.getvalue()
    assert f"{listing}:2: not an IP, CIDR range or host name, ignored" in text
    assert f"{listing}:3: not an IP, CIDR range or host name, ignored" in text
    assert f"{listing}: IP list, 1 entries, 3 host names" in text
    only_names = read_inputs(["www.corp.test"], 100, log)
    assert only_names.ips == [] and list(only_names.names) == ["www.corp.test"]


def test_name_resolving_to_internal_address_notes_public_server():
    class StubDns:
        def __init__(self):
            self.servers = [dnsclient.DnsServer("8.8.8.8")]

        def active(self):
            return self.servers

        async def chain(self, server, name, rdtype):
            if rdtype == dnsclient.ADDRESS_TYPES[0]:
                return "ok", {"10.0.0.5"}, ["edge.corp.test"]
            return "none", set(), []

    log, stream = _log()
    run = make_run(["-m", "ptr", "--no-forward-confirm"], ips=["51.83.59.99"], dns=StubDns(),
                   log=log)
    run.inputs.names = {"www.corp.test": None}
    asyncio.run(run.resolve_names())
    assert run.inputs.ips == ["10.0.0.5", "51.83.59.99"]
    assert "DNS server 8.8.8.8 has a public address; it receives the internal addresses" \
        in stream.getvalue()
    rows = {(row.ip, row.name): row.details for row in run.results.rows.values()}
    assert rows == {("10.0.0.5", "www.corp.test"): ["A @8.8.8.8, CNAME edge.corp.test"],
                    ("10.0.0.5", "edge.corp.test"): ["CNAME of www.corp.test, A @8.8.8.8"]}


def test_ip_list_shows_ten_invalid_lines_then_count(tmp_path):
    listing = tmp_path / "list.txt"
    listing.write_text("junk\n" * 15 + "10.0.0.1\n")
    log, stream = _log()
    read_inputs([str(listing)], 10, log)
    assert stream.getvalue().count("not an IP, CIDR range or host name, ignored") == 10
    assert "15 invalid lines in all" in stream.getvalue()


def test_nmap_entities_refused_and_damaged_file(tmp_path):
    hostile = tmp_path / "hostile.xml"
    hostile.write_text('<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "b">]>'
                       '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/></host>'
                       '</nmaprun>')
    log, _ = _log()
    with pytest.raises(UsageError, match="entity declarations refused"):
        read_inputs([str(hostile)], 10, log)
    damaged = tmp_path / "damaged.xml"
    damaged.write_text('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>'
                       '<host><address addr="10.0.0.1" addrtype="ipv4"/></host>'
                       '<host><address addr="10.0.0.2" addrty')
    log, stream = _log()
    inputs = read_inputs([str(damaged)], 10, log)
    assert inputs.ips == ["10.0.0.1"]
    assert "damaged XML" in stream.getvalue()


def test_nmap_control_references_and_ranges():
    data = (b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun start="10">'
            b'<scaninfo type="syn" protocol="tcp" services="1-100,443"/>'
            b'<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
            b'<hostnames><hostname name="evil&#x1b;name" type="PTR"/></hostnames>'
            b'<ports><port protocol="tcp" portid="443"><state state="open"/>'
            b'<service name="http" tunnel="ssl"/></port></ports></host></nmaprun>')
    nmap_file = nmapxml.read_xml(io.BytesIO(data))
    host = nmap_file.hosts["10.0.0.5"]
    assert host.names == [("evil\\x1bname", "nmap PTR", 10)]
    assert nmap_file.ranges == {"tcp": [(1, 100), (443, 443)]}
    assert host.open_ports == {("tcp", 443): ("http", "ssl")}


def _nmap(*files):
    data = nmapxml.NmapData()
    for path in files:
        data.add(nmapxml.read_file(path))
    return data


def test_port_selection_with_nmap(data_dir):
    nmap = _nmap(os.path.join(data_dir, "nmap-windows-domain.xml"))
    run = make_run(["-m", "default"], ips=["10.20.30.10", "10.20.30.11", "10.20.30.40",
                                           "10.20.30.99"], nmap=nmap)
    plan = run.plan
    tls = plan.by_name["tls"]
    assert plan.ports_for(tls, "10.20.30.99", nmap) == list(tls.PORTS)
    assert plan.ports_for(tls, "10.20.30.11", nmap) == ()
    web = plan.ports_for(tls, "10.20.30.40", nmap)
    assert 443 in web and 636 not in web and 8443 in web and 1433 in web
    assert 25 not in web and 80 not in web
    dc = plan.ports_for(tls, "10.20.30.10", nmap)
    assert 3389 not in dc and 389 in dc and 53 in dc


def test_presets_and_skip():
    methods = cli.METHODS
    chosen, named = expand("default,ptr", methods, "-m")
    assert "tls" in [module.NAME for module in chosen] and named == {"ptr"}
    with pytest.raises(UsageError, match="unknown method or preset"):
        expand("nosuch", methods, "-m")
    assert parse_ports("default,10443", (443, 8443), "--tls-ports") == [443, 8443, 10443]
    assert parse_ports("10443", (443,), "--tls-ports") == [10443]
    with pytest.raises(UsageError):
        parse_ports("70000", (), "--tls-ports")
    args = cli.build_parser().parse_args(["10.0.0.1", "-m", "default", "--skip", "ptr"])
    log, _ = _log()
    plan = build_plan(args, methods, log, {})
    assert "ptr" not in plan.by_name and "tls" in plan.by_name


def test_csv_escaping_sorting_and_empty_ips():
    run = make_run(["-m", "tls"], ips=["10.0.0.2", "10.0.0.10", "2001:db8::1"])
    ctx = run.contexts["tls"]
    run.finding(ctx, Finding("10.0.0.10", "B.example.org", "443 CN", 1.0, 1.0))
    run.finding(ctx, Finding("10.0.0.10", "a.example.org", "443 SAN", 2.0, 2.0))
    run.finding(ctx, Finding("10.0.0.10", "a.example.org", "8443 SAN", 1.5, 1.5))
    run.finding(ctx, Finding("10.0.0.10", "bad\x01name", "443 CN"))
    rows = build_rows(run, None)
    assert [(row["ip"], row.get("fqdn")) for row in rows] == [
        ("10.0.0.2", None), ("10.0.0.10", "a.example.org"), ("10.0.0.10", "b.example.org"),
        ("2001:db8::1", None)]
    assert rows[1]["detail"] == "443 SAN; 8443 SAN"
    assert rows[2]["labels"] == "placeholder"
    assert ctx.dropped == 1
    text = csv_text([{"ip": "10.0.0.1", "detail": "a,b\x1b\n"}])
    assert text.splitlines()[1] == '10.0.0.1,,,"a,b\\x1b\\x0a",,,,,,'
    assert sanitize("x\ty") == "x\\x09y"


def test_dates_merge_and_time_format(paris):
    run = make_run(["-m", "tls"], ips=["10.0.0.1"])
    ctx = run.contexts["tls"]
    run.finding(ctx, Finding("10.0.0.1", "a.example.org", "x", 1795442531.0, 1795442531.0))
    run.finding(ctx, Finding("10.0.0.1", "a.example.org", "y", 1795000000.0, 1795000000.0))
    row = build_rows(run, None)[0]
    assert row["first_seen"] == "2026-11-18 12:06 +01:00"
    assert row["last_seen"] == "2026-11-23 15:02 +01:00"


def test_api_cache_round_trip(tmp_path):
    path = str(tmp_path / "out.csv.api-cache")
    log, _ = _log()
    cache = ApiCache(path, log)
    cache.load()
    cache.record("tls", Answer("8.8.8.8", [Finding("8.8.8.8", "dns.google", "pdns", 1.0, 2.0)]))
    cache.record("tls", Answer("1.1.1.1", []))
    cache.close()
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("{damaged\n")
    run = make_run(["-m", "tls"], ips=["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    reread = ApiCache(path, log)
    reread.load()
    ctx = run.contexts["tls"]
    left = reread.remaining(ctx, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    assert left == ["9.9.9.9"]
    assert reread.used == 2 and ctx.ips == {"8.8.8.8", "1.1.1.1"}
    row = run.results.rows[("8.8.8.8", "dns.google", "tls")]
    assert (row.first_seen, row.last_seen) == (1.0, 2.0)
    with open(path, encoding="utf-8") as handle:
        assert json.loads(handle.readline())["format"] == "ip2fqdn-api-cache"


def test_debug_masking():
    stream = io.StringIO()
    log = Log(stream, debug=True)
    log.debug("tls connect", ip="10.0.0.1", port=443, host="dc01.corp.example",
              error="TimeoutError")
    log.debug("again", ip="10.0.0.1", path="/scans/a.xml", text="secret banner")
    lines = stream.getvalue().splitlines()
    assert lines[0] == "[debug] tls connect ip=IP4-1 port=443 host=HOST-1 error=TimeoutError"
    assert lines[1] == "[debug] again ip=IP4-1 path=PATH-1.xml text=TEXT-1[len=13]"


def test_dns_server_parsing_and_protected_rule():
    servers = dnsclient.parse_servers("10.0.0.10,127.0.1.5:5353,[::1]:5300,2001:db8::53")
    assert [(s.ip, s.port) for s in servers] == [("10.0.0.10", 53), ("127.0.1.5", 5353),
                                                  ("::1", 5300), ("2001:db8::53", 53)]
    with pytest.raises(UsageError):
        dnsclient.parse_servers("dns.example.com")
    log, stream = _log()
    named = dnsclient.parse_servers("10.0.0.10,8.8.8.8")
    resolv = dnsclient.parse_servers("192.168.1.1")
    chosen, protected = dnsclient.choose_servers(named, resolv, True, False, log)
    assert [s.ip for s in chosen] == ["10.0.0.10", "8.8.8.8"] and protected
    assert "internal addresses in the input: DNS server 8.8.8.8 has a public address; it " \
        "receives the internal addresses and names of this run" in stream.getvalue()
    assert "10.0.0.10 has a public address" not in stream.getvalue()
    chosen, protected = dnsclient.choose_servers([], resolv, True, False, log)
    assert chosen == [] and protected
    chosen, protected = dnsclient.choose_servers([], resolv, False, False, log)
    assert [s.ip for s in chosen] == ["192.168.1.1"] and not protected
    chosen, protected = dnsclient.choose_servers([], resolv, False, True, log)
    assert chosen == [] and protected
    named = dnsclient.parse_servers("8.8.8.8")
    chosen, _ = dnsclient.choose_servers(named, resolv, False, True, log)
    assert [s.ip for s in chosen] == ["8.8.8.8"]


def _csv_row(ip, fqdn="", source="", **values):
    row = dict.fromkeys(merge.COLUMNS, "")
    row.update(ip=ip, fqdn=fqdn, source=source, **values)
    return row


def test_merge_rows_rules():
    old = [_csv_row("10.0.0.1", "a.test", "ptr", detail="PTR @10.0.0.53", dns="match",
                    first_seen="2026-11-01 10:00 +01:00", last_seen="2026-11-01 10:00 +01:00"),
           _csv_row("10.0.0.2"),
           _csv_row("10.0.0.3", "c.test", "tls", detail="443 CN", sni="served",
                    first_seen="01/11/2026", last_seen="01/11/2026"),
           _csv_row("", "d.test", "input", detail="A none @10.0.0.53", dns="none"),
           _csv_row("", "e.test", "input", detail="not resolved: --dns-server missing")]
    new = [_csv_row("10.0.0.1", "a.test", "ptr", detail="PTR @10.0.0.54; PTR @10.0.0.53",
                    name_kind="dotted", first_seen="2026-11-26 09:00 +00:00",
                    last_seen="2026-11-26 09:00 +00:00"),
           _csv_row("10.0.0.2", "b.test", "smb", detail="445 NTLM DNS computer name"),
           _csv_row("10.0.0.3", "c.test", "tls", detail="443 CN", sni="",
                    first_seen="2026-11-26 09:00 +00:00", last_seen="2026-11-26 09:00 +00:00"),
           _csv_row("10.0.0.4"),
           _csv_row("10.0.0.5", "d.test", "input", detail="A @10.0.0.53"),
           _csv_row("10.0.0.6", "e.test", "ptr", detail="PTR @10.0.0.53")]
    merged = merge.merge_rows(old, new)
    assert [(row["ip"], row["fqdn"]) for row in merged] == [
        ("10.0.0.1", "a.test"), ("10.0.0.2", "b.test"), ("10.0.0.3", "c.test"), ("10.0.0.4", ""),
        ("10.0.0.5", "d.test"), ("10.0.0.6", "e.test"), ("", "e.test")]
    first = merged[0]
    assert first["detail"] == "PTR @10.0.0.53; PTR @10.0.0.54"
    assert (first["dns"], first["name_kind"]) == ("match", "dotted")
    assert (first["first_seen"], first["last_seen"]) == ("2026-11-01 10:00 +01:00",
                                                         "2026-11-26 09:00 +00:00")
    third = merged[2]
    assert third["sni"] == "served"
    assert (third["first_seen"], third["last_seen"]) == ("2026-11-26 09:00 +00:00",
                                                         "2026-11-26 09:00 +00:00")
    assert merge.merge_rows(merged, merged) == merged


def test_merge_reads_only_ip2fqdn_files(tmp_path):
    missing = tmp_path / "none.csv"
    assert merge.read_existing(str(missing)) is None
    good = tmp_path / "good.csv"
    good.write_text(",".join(merge.COLUMNS) + "\n10.0.0.1,a.test,ptr\n2001:db8::1\n")
    rows = merge.read_existing(str(good))
    assert [(row["ip"], row["fqdn"], row["dns"]) for row in rows] == [
        ("10.0.0.1", "a.test", ""), ("2001:db8::1", "", "")]
    foreign = tmp_path / "foreign.csv"
    foreign.write_text("name,value\na,b\n")
    with pytest.raises(UsageError, match="not an ip2fqdn CSV \\(header differs\\), not merged"):
        merge.read_existing(str(foreign))
    damaged = tmp_path / "damaged.csv"
    damaged.write_text(",".join(merge.COLUMNS) + "\n10.0.0.1,a.test,ptr\nnot-an-ip,b.test,ptr\n")
    with pytest.raises(UsageError, match="damaged.csv:3: not an IP in column ip, not merged"):
        merge.read_existing(str(damaged))
    names = tmp_path / "names.csv"
    names.write_text(",".join(merge.COLUMNS) + "\n,d.test,input\n")
    assert [(row["ip"], row["fqdn"]) for row in merge.read_existing(str(names))] == [
        ("", "d.test")]
    nameless = tmp_path / "nameless.csv"
    nameless.write_text(",".join(merge.COLUMNS) + "\n,,input\n")
    with pytest.raises(UsageError, match="nameless.csv:2: not an IP in column ip, not merged"):
        merge.read_existing(str(nameless))


def test_progress_text():
    class Task:
        def __init__(self, finished):
            self.finished = finished

        def done(self):
            return self.finished

    run = make_run(["-m", "tls,ptr,internetdb,axfr"])
    now = 1000.0
    run.started = now - 42
    run.results.names = {("127.0.1.1", f"n{i}.test"): "tls" for i in range(37)}
    tls, internetdb, axfr = (run.contexts[name] for name in ("tls", "internetdb", "axfr"))
    tls.set_total(1270)
    tls.finished, tls.running, tls.last_progress = 254, True, now - 1
    tls.ips.add("127.0.1.1")
    internetdb.total, internetdb.running, internetdb.last_progress = 61, True, now - 72
    axfr.set_total(5)
    axfr.finished, axfr.running, axfr.last_progress = 2, True, now
    run.confirmations = {"a.test": Task(True), "b.test": Task(False)}
    assert runner.progress_text(run, now) == (
        "0:42  37 names  tls 254/1270  internetdb 0/61 (no progress for 72 s)  axfr 2/5  "
        "checks 1/2")
    assert runner.clock(3725) == "1:02:05"


def test_status_line_cut_to_terminal_width():
    class Terminal(io.StringIO):
        def isatty(self):
            return True

    stream = Terminal()
    Log(stream).status("x" * 200)
    line = stream.getvalue().split("\r\x1b[K")[-1]
    assert len(line) == 79 and line.endswith("...")
