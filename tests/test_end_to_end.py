import asyncio
import csv
import io
import os
import signal
import subprocess
import sys
import time

import fakes
import ntlm_vectors
import pytest
from conftest import SITE_DIR
from helpers import make_run, run_cli
from test_active import http_server, rdp_server
from test_protocols import ldap_server
from test_windows import smb_server

from ip2fqdn import dnsclient, runner
from ip2fqdn.common import Log

WINDOWS, WEB, DEAD, SLOW, DNS = "127.0.1.10", "127.0.1.11", "127.0.1.12", "127.0.1.13", \
    "127.0.1.53"
METHOD_PORTS = ("tls", "smb", "rdp", "http", "smtp", "netbios", "http-ntlm", "ldap", "imap",
                "pop3", "ftp", "mssql")
COMMAND = os.path.join(os.path.dirname(sys.executable), "ip2fqdn")


def dns_records():
    return {
        ("10.1.0.127.in-addr.arpa", "PTR"): ["dc01.corp.test."],
        ("11.1.0.127.in-addr.arpa", "PTR"): ["127-0-1-11.static.isp.test."],
        ("dc01.corp.test", "A"): ["127.0.1.10"],
        ("www.corp.test", "A"): ["127.0.1.11"],
        ("intranet.corp.test", "A"): ["127.0.1.11"],
        ("corp.test", "SOA"): ["ns1.corp.test. admin.corp.test. 1 60 60 60 60"],
        ("corp.test", "NS"): ["ns1.corp.test."],
        ("ns1.corp.test", "A"): ["127.0.1.53"],
        ("_ldap._tcp.corp.test", "SRV"): ["0 100 389 dc01.corp.test."],
        ("_kerberos._tcp.corp.test", "SRV"): ["0 100 88 kdc.corp.test."],
        ("kdc.corp.test", "A"): ["127.0.1.10"],
    }


def transfers():
    return {"corp.test": [("fs01.corp.test", "A", "127.0.1.10"),
                          ("print.corp.test", "A", "127.0.1.99"),
                          ("web.corp.test", "A", "127.0.1.11")]}


@pytest.fixture
def lab():
    ports = {name: fakes.free_port() for name in METHOD_PORTS}
    dc_cert = fakes.make_cert("DC01.corp.test")
    web_cert = fakes.make_cert("www.corp.test", ["www.corp.test"])
    intranet_cert = fakes.make_cert("intranet.corp.test", ["intranet.corp.test",
                                                           "portal.corp.test"])
    seen = []
    with fakes.FakeNetwork() as network:
        fake_dns = fakes.FakeDns(dns_records(), transfers())
        dns_port = fakes.start_dns(network, DNS, fake_dns)
        context = fakes.server_context(dc_cert)
        network.tcp(WINDOWS, ports["tls"], fakes.tls_handler(context), context)
        network.tcp(WINDOWS, ports["smb"], smb_server(ntlm_vectors.windows_challenge()))
        hybrid = bytes.fromhex("030000130ed00000123400021f080008000000")
        network.tcp(WINDOWS, ports["rdp"], rdp_server(dc_cert, hybrid))
        network.tcp(WINDOWS, ports["ldap"], ldap_server(
            {"dnsHostName": ["DC01.corp.test"], "defaultNamingContext": ["DC=corp,DC=test"]}))
        web_context = fakes.server_context(web_cert, {"intranet.corp.test": intranet_cert},
                                           seen)
        network.tcp(WEB, ports["tls"], fakes.tls_handler(web_context), web_context)
        network.tcp(WEB, ports["http"], http_server(
            b"HTTP/1.1 302 Found\r\nLocation: http://intranet.corp.test/\r\n\r\n"))
        for method in ("tls", "http", "smb"):
            network.tcp(SLOW, ports[method], fakes.silent_handler())
        argv = [f"--dns-server={DNS}:{dns_port}", "--connect-timeout", "1", "--timeout", "2"]
        argv += [f"--{name}-ports={port}" for name, port in ports.items()]
        yield argv, fake_dns, seen


def _rows(out):
    return list(csv.DictReader(io.StringIO(out)))


def test_small_lab_default_methods(lab, tmp_path):
    argv, fake_dns, seen = lab
    output = tmp_path / "out.csv"
    code, _, err = run_cli([WINDOWS, f"{WEB}/32", DEAD, SLOW, "-o", str(output), *argv])
    assert code == 0, err
    rows = _rows(output.read_text())
    found = {(row["ip"], row["fqdn"], row["source"]): row for row in rows}
    assert found[(WINDOWS, "dc01.corp.test", "smb")]["dns"] == "match"
    assert found[(WINDOWS, "dc01", "smb")]["name_kind"] == "short"
    assert found[(WINDOWS, "dc01.corp.test", "rdp")]["detail"].endswith("RDP CN")
    assert found[(WINDOWS, "dc01.corp.test", "ldap")]["dns"] == "match"
    assert found[(WINDOWS, "dc01.corp.test", "ptr")]["dns"] == "match"
    assert found[(WINDOWS, "fs01.corp.test", "axfr")]["detail"].startswith("AXFR corp.test")
    assert (WINDOWS, "kdc.corp.test", "dns-enum") in found
    assert found[(WEB, "www.corp.test", "tls")]["sni"] == "served"
    assert found[(WEB, "intranet.corp.test", "http")]["sni"] == "served"
    assert found[(WEB, "portal.corp.test", "sni")]["dns"] == "none"
    assert found[(WEB, "127-0-1-11.static.isp.test", "ptr")]["labels"] == "generic"
    assert found[(WEB, "web.corp.test", "axfr")]["dns"] == "none"
    assert [row["fqdn"] for row in rows if row["ip"] in (DEAD, SLOW)] == ["", ""]
    assert "intranet.corp.test" in seen and "127-0-1-11.static.isp.test" not in seen
    assert ("corp.test", "AXFR") in fake_dns.queries
    assert "tls: 4 IPs" in err and "timeouts" in err
    assert f"output: {output}" in err
    assert "unexpected" not in err, err


def test_protected_rule_without_named_server(lab):
    argv, fake_dns, _ = lab
    argv = [item for item in argv if not item.startswith("--dns-server")]
    code, out, err = run_cli([WINDOWS, "-m", "smb,ptr", *argv])
    assert code == 0
    assert "internal addresses in the input: DNS methods and checks need" in err
    assert fake_dns.queries == []
    rows = _rows(out)
    assert {row["source"] for row in rows} == {"smb"} and all(not r["dns"] for r in rows)


def name_records():
    return {("www.corp.test", "A"): ["127.0.1.11"],
            ("app.corp.test", "CNAME"): ["edge.cdn.test."],
            ("edge.cdn.test", "A"): ["127.0.1.11", "127.0.1.12"],
            ("v6.corp.test", "AAAA"): ["::1"],
            ("old.corp.test", "CNAME"): ["gone.cdn.test."],
            ("11.1.0.127.in-addr.arpa", "PTR"): ["web01.corp.test."],
            ("corp.test", "SOA"): ["ns1.corp.test. admin.corp.test. 1 60 60 60 60"]}


def test_host_name_inputs(tmp_path):
    listing = tmp_path / "names.txt"
    listing.write_text("www.corp.test\nmissing.corp.test\n")
    fake = fakes.FakeDns(name_records())
    with fakes.FakeNetwork() as network:
        port = fakes.start_dns(network, DNS, fake)
        server = f"{DNS}:{port}"
        code, out, err = run_cli([str(listing), "app.corp.test", "v6.corp.test", "ips.tx",
                                  "old.corp.test", "-m", "ptr,dns-enum",
                                  f"--dns-server={server}"])
        too_many = run_cli(["app.corp.test", "--max-ips", "1", "-m", "ptr",
                            f"--dns-server={server}"])
    assert code == 0, err
    rows = {(row["ip"], row["fqdn"], row["source"]): row for row in _rows(out)}
    www = rows[("127.0.1.11", "www.corp.test", "input")]
    assert (www["detail"], www["dns"], www["name_kind"]) == (f"A @{server}", "match", "dotted")
    assert rows[("127.0.1.12", "app.corp.test", "input")]["detail"] == \
        f"A @{server}, CNAME edge.cdn.test"
    edge = rows[("127.0.1.12", "edge.cdn.test", "input")]
    assert (edge["detail"], edge["dns"]) == (f"CNAME of app.corp.test, A @{server}", "match")
    assert rows[("::1", "v6.corp.test", "input")]["detail"] == f"AAAA @{server}"
    assert ("127.0.1.11", "web01.corp.test", "ptr") in rows
    assert ("corp.test", "SOA") in fake.queries
    assert f"{listing}:2: missing.corp.test: no address" in err
    assert "ips.tx: no such file, and no address as a host name" in err
    assert "input: 6 host names, 3 addresses, 3 without address" in err
    missing = rows[("", "missing.corp.test", "input")]
    assert (missing["detail"], missing["dns"], missing["name_kind"]) == (
        f"A none @{server}; AAAA none @{server}", "none", "dotted")
    assert missing["first_seen"] and missing["last_seen"]
    dangling = rows[("", "old.corp.test", "input")]["detail"]
    assert dangling == (f"A none @{server}, CNAME gone.cdn.test; "
                        f"AAAA none @{server}, CNAME gone.cdn.test")
    assert [row["fqdn"] for row in _rows(out) if not row["ip"]] == [
        "ips.tx", "missing.corp.test", "old.corp.test"]
    ips = [row["ip"] for row in _rows(out)]
    assert ips[-3:] == ["", "", ""] and "" not in ips[:-3]
    assert too_many[0] == 2 and "more than 1 IPs to look up" in too_many[2]


def test_host_names_need_named_server(monkeypatch):
    fake = fakes.FakeDns(name_records())
    with fakes.FakeNetwork() as network:
        port = fakes.start_dns(network, DNS, fake)
        monkeypatch.setattr(dnsclient, "resolv_conf_servers",
                            lambda: [dnsclient.DnsServer(DNS, port, "resolv.conf")])
        code, out, err = run_cli(["51.83.59.99", "www.corp.test", "-m", "ptr"])
        only_names = run_cli(["www.corp.test", "app.corp.test", "-m", "ptr"])
    assert code == 0, err
    message = ("--dns-server missing: 1 host names in the input not resolved (www.corp.test); "
               "host names are resolved only by servers given with --dns-server")
    assert err.count(message) == 2
    assert err.rindex(message) > err.index("total time")
    assert ("99.59.83.51.in-addr.arpa", "PTR") in fake.queries
    assert not [query for query in fake.queries if query[0].endswith("corp.test")]
    assert [row["ip"] for row in _rows(out)] == ["51.83.59.99", ""]
    unresolved = _rows(out)[1]
    assert (unresolved["fqdn"], unresolved["source"], unresolved["detail"]) == (
        "www.corp.test", "input", "not resolved: --dns-server missing")
    assert (unresolved["dns"], unresolved["first_seen"]) == ("", "")
    assert only_names[0] == 2
    assert "error: --dns-server missing: 2 host names in the input not resolved " \
        "(www.corp.test, app.corp.test)" in only_names[2]


def test_host_name_without_address_after_error(monkeypatch):
    monkeypatch.setattr(dnsclient, "ATTEMPT_TIMEOUT", 0.05)
    with fakes.FakeNetwork() as network:
        port = fakes.start_dns(network, DNS, fakes.FakeDns(name_records()))
        silent = fakes.start_dns(network, SLOW, fakes.FakeDns(silent=True))
        code, out, err = run_cli(["missing.corp.test", "-m", "ptr",
                                  f"--dns-server={DNS}:{port},{SLOW}:{silent}"])
    assert code == 0, err
    [row] = _rows(out)
    assert (row["ip"], row["fqdn"], row["source"], row["dns"]) == (
        "", "missing.corp.test", "input", "error")
    assert row["detail"] == (f"A none @{DNS}:{port}; AAAA none @{DNS}:{port}; "
                             f"A error @{SLOW}:{silent}; AAAA error @{SLOW}:{silent}")


def test_merge_results(tmp_path):
    output = tmp_path / "out.csv"
    fake = fakes.FakeDns({("10.1.0.127.in-addr.arpa", "PTR"): ["dc01.corp.test."],
                          ("11.1.0.127.in-addr.arpa", "PTR"): ["web01.corp.test."]})
    with fakes.FakeNetwork() as network:
        port = fakes.start_dns(network, DNS, fake)
        base = ["-m", "ptr", "--no-forward-confirm", f"--dns-server={DNS}:{port}", "-o",
                str(output), "--merge-results"]
        first = run_cli([WINDOWS, *base])
        second = run_cli([WEB, DEAD, *base])
        again = run_cli([WEB, DEAD, *base])
        merged = output.read_text()
        foreign = tmp_path / "foreign.csv"
        foreign.write_text("name,value\n")
        queries = len(fake.queries)
        refused = run_cli([WINDOWS, *base[:-3], "-o", str(foreign), "--merge-results"])
        assert len(fake.queries) == queries
    assert first[0] == 0 and f"{output}: new file" in first[2]
    assert second[0] == 0 and f"{output}: 1 rows before, 3 after merge" in second[2]
    assert again[0] == 0 and f"{output}: 3 rows before, 3 after merge" in again[2]
    assert [(row["ip"], row["fqdn"]) for row in _rows(merged)] == [
        (WINDOWS, "dc01.corp.test"), (WEB, "web01.corp.test"), (DEAD, "")]
    assert refused[0] == 2 and "not an ip2fqdn CSV (header differs), not merged" in refused[2]
    assert foreign.read_text() == "name,value\n"
    assert not os.path.exists(f"{output}.tmp")
    code, _, err = run_cli([WINDOWS, "--merge-results"])
    assert code == 2 and "--merge-results needs -o FILE" in err


def test_progress_lines_when_not_a_terminal(monkeypatch):
    monkeypatch.setattr(runner, "PROGRESS_EVERY", 0.3)
    with fakes.FakeNetwork() as network:
        port = fakes.free_port()
        network.tcp(SLOW, port, fakes.silent_handler())
        code, _, err = run_cli([SLOW, "-m", "tls", f"--tls-ports={port}", "--connect-timeout",
                                "1", "--timeout", "1.5"])
    assert code == 0, err
    assert "progress 0:00  0 names  tls 0/1\n" in err
    assert "\r" not in err


def test_sni_progress_counts_names(lab):
    argv = [item for item in lab[0] if not item.startswith("--dns-server")]

    async def go():
        run = make_run(["-m", "tls,sni", *argv], ips=[WINDOWS, WEB])
        await run.execute()
        return run

    sni = asyncio.run(go()).contexts["sni"]
    assert sni.counting and sni.total >= 2 and sni.progress() == sni.total and not sni.running


def test_progress_counts_reach_totals():
    fake = fakes.FakeDns({("10.1.0.127.in-addr.arpa", "PTR"): ["dc01.corp.test."],
                          ("www.corp.test", "A"): ["127.0.1.10"],
                          ("corp.test", "SOA"): ["ns1.corp.test. admin.corp.test. 1 60 60 60 60"]},
                         {"corp.test": [("fs01.corp.test", "A", "127.0.1.10")]})

    async def go(port):
        log = Log(io.StringIO())
        service = dnsclient.DnsService([dnsclient.DnsServer(DNS, port)], log)
        run = make_run(["-m", "ptr,axfr,dns-enum"], ips=[WINDOWS], dns=service, log=log)
        run.inputs.names = {"www.corp.test": None}
        await run.execute()
        return run

    with fakes.FakeNetwork() as network:
        run = asyncio.run(go(fakes.start_dns(network, DNS, fake)))
    for ctx in (run.input_ctx, *run.contexts.values()):
        assert (ctx.total, ctx.progress(), ctx.running) == (ctx.total, ctx.total, False), ctx.name
        assert ctx.total, ctx.name
    assert run.contexts["dns-enum"].total == 16 and run.contexts["axfr"].total == 1


def test_usage_errors():
    code, _, err = run_cli(["nosuchfile.txt"])
    assert code == 2 and "error: nosuchfile.txt: no such file" in err
    assert run_cli(["10.0.0.1", "-m", "bogus"])[0] == 2
    code, _, err = run_cli(["10.0.0.0/8"])
    assert code == 2 and "--max-ips" in err


@pytest.mark.allow_exec
def test_interrupt_writes_partial_output(tmp_path):
    port = fakes.free_port()
    output = tmp_path / "out.csv"
    environment = dict(os.environ, PYTHONPATH=SITE_DIR)
    with fakes.FakeNetwork() as network:
        network.tcp(SLOW, port, fakes.silent_handler())
        process = subprocess.Popen(
            [COMMAND, SLOW, "-m", "tls",
             f"--tls-ports={port}", "--timeout", "30", "-o", str(output)],
            stderr=subprocess.PIPE, env=environment)
        time.sleep(1.5)
        process.send_signal(signal.SIGINT)
        _, err = process.communicate(timeout=20)
    assert process.returncode == 130, err
    assert b"interrupted: results incomplete" in err
    assert output.read_text().startswith("ip,fqdn,source")


@pytest.mark.allow_exec
def test_sigterm_exit_code(tmp_path):
    port = fakes.free_port()
    environment = dict(os.environ, PYTHONPATH=SITE_DIR)
    with fakes.FakeNetwork() as network:
        network.tcp(SLOW, port, fakes.silent_handler())
        process = subprocess.Popen(
            [COMMAND, SLOW, "-m", "tls",
             f"--tls-ports={port}", "--timeout", "30"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        time.sleep(1.5)
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=20)
    assert process.returncode == 143, err
    assert out.startswith(b"ip,fqdn,source")


@pytest.mark.allow_exec
def test_second_interrupt_quits_at_once():
    port = fakes.free_port()
    environment = dict(os.environ, PYTHONPATH=SITE_DIR)
    with fakes.FakeNetwork() as network:
        network.tcp(SLOW, port, fakes.silent_handler())
        process = subprocess.Popen(
            [COMMAND, SLOW, "-m", "tls",
             f"--tls-ports={port}", "--timeout", "30"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        time.sleep(1.5)
        process.send_signal(signal.SIGINT)
        process.send_signal(signal.SIGINT)
        process.communicate(timeout=20)
    assert process.returncode == 130
