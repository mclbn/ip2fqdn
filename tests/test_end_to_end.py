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
from helpers import run_cli
from test_active import http_server, rdp_server
from test_windows import smb_server

WINDOWS, WEB, DEAD, SLOW, DNS = "127.0.1.10", "127.0.1.11", "127.0.1.12", "127.0.1.13", \
    "127.0.1.53"
METHOD_PORTS = ("tls", "smb", "rdp", "http", "smtp", "netbios", "http-ntlm")
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


def test_protected_rule_without_named_server(lab):
    argv, fake_dns, _ = lab
    argv = [item for item in argv if not item.startswith("--dns-server")]
    code, out, err = run_cli([WINDOWS, "-m", "smb,ptr", *argv])
    assert code == 0
    assert "internal addresses in the input: DNS methods and checks need" in err
    assert fake_dns.queries == []
    rows = _rows(out)
    assert {row["source"] for row in rows} == {"smb"} and all(not r["dns"] for r in rows)


def test_usage_errors():
    assert run_cli(["nosuchfile.txt"])[0] == 2
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
