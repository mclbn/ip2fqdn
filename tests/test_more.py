import asyncio
import csv
import io
import ipaddress
import json
import os
import re
import struct

import dns.message
import dns.rdatatype
import dns.rrset
import fakes
from conftest import DATA_DIR
from helpers import lookup, make_run, run_cli
from hypothesis import given, settings
from hypothesis import strategies as st
from test_end_to_end import DNS, WEB, WINDOWS, lab  # noqa: F401

from ip2fqdn import cli, dnsclient, nmapxml, ranges
from ip2fqdn.methods import axfr, mdns, onyphe, shodan
from ip2fqdn.proto import certs


def test_mdns_reverse_query_with_cache_flush_bit():
    def respond(data, address):
        query = dns.message.from_wire(data)
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_text(query.question[0].name.to_text().upper(), 10,
                                                "IN", "PTR", "laptop.local."))
        wire = bytearray(reply.to_wire())
        offset = wire.rfind(b"\x00\x0c\x00\x01")
        wire[offset + 2] |= 0x80
        return [bytes(wire)]

    with fakes.FakeNetwork() as network:
        port = network.udp("127.0.1.60", 0, respond)
        found, _ = lookup(mdns, "127.0.1.60", port)
    assert [(f.name, f.detail) for f in found] == [("laptop.local", f"{port} mDNS")]


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=200))
def test_mdns_reply_parser_never_crashes(noise):
    query = dns.message.make_query("1.0.0.10.in-addr.arpa", "PTR")
    assert mdns.ptr_names(noise, query) is None or isinstance(mdns.ptr_names(noise, query),
                                                              list)


def _xfr_server(messages):
    async def handle(reader, writer):
        try:
            (length,) = struct.unpack("!H", await reader.readexactly(2))
            query = dns.message.from_wire(await reader.readexactly(length))
            for build in messages:
                response = dns.message.make_response(query)
                response.answer = build()
                wire = response.to_wire()
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()
            await reader.read(10)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    return handle


def test_transfer_cap_and_garbage():
    soa = lambda: [dns.rrset.from_text("z.test.", 60, "IN", "SOA",
                                       "ns. a. 1 1 1 1 1")]
    records = lambda: [dns.rrset.from_text(f"h{n}.z.test.", 60, "IN", "A",
                                           "127.0.1.10") for n in range(50)]
    outside = lambda: [dns.rrset.from_text("evil.other.", 60, "IN", "A",
                                           "127.0.1.10")]

    async def go(port, host, cap):
        server = dnsclient.DnsServer(host, port)
        return await dnsclient.transfer(server, "z.test", 1, {"127.0.1.10"},
                                        max_records=cap)

    with fakes.FakeNetwork() as network:
        endless = network.tcp("127.0.1.61", 0, _xfr_server([soa] + [records] * 30))
        normal = network.tcp("127.0.1.62", 0, _xfr_server([soa, records, outside, soa]))
        found, status = asyncio.run(go(endless, "127.0.1.61", 200), debug=True)
        assert status == "capped" and len(found) == 200
        found, status = asyncio.run(go(normal, "127.0.1.62", 1000), debug=True)
        assert status == "complete" and len(found) == 50
        assert ("127.0.1.10", "evil.other") not in found


def test_zone_transfer_rules():
    async def go():
        run = make_run(["-m", "axfr"])
        loopback = dnsclient.DnsServer("127.0.0.53", 53, "resolv.conf")
        named = dnsclient.DnsServer("127.0.1.53", 53, "named")
        run.dns = dnsclient.DnsService([loopback, named], run.log)
        run.zones = [("corp.test", False), ("1.0.10.in-addr.arpa", False)]
        ctx = run.contexts["axfr"]
        jobs = await axfr._jobs(ctx)
        return jobs, run.log.stream.getvalue()
    jobs, text = asyncio.run(go(), debug=True)
    assert [(zone, server.ip) for zone, server in jobs] == [("corp.test", "127.0.1.53")]
    assert "no zone transfer through the loopback DNS server" in text


def test_named_zone_also_goes_to_its_own_servers(lab, monkeypatch):  # noqa: F811
    argv, fake_dns, _ = lab
    real = dnsclient.transfer
    targets = []

    async def recorded(server, zone, *args, **kwargs):
        targets.append((zone, server.ip, server.port))
        if server.port == 53:
            return [], "refused"
        return await real(server, zone, *args, **kwargs)

    monkeypatch.setattr(dnsclient, "transfer", recorded)
    code, _, err = run_cli([WINDOWS, "-m", "axfr", "--zones", "corp.test", *argv])
    assert code == 0, err
    assert [target[:2] for target in targets] == [("corp.test", DNS), ("corp.test", DNS)]
    assert targets[1][2] == 53 and targets[0][2] != 53
    assert ("corp.test", "NS") in fake_dns.queries


def test_debug_run_masks_every_value(lab):  # noqa: F811
    argv, _, _ = lab
    code, _, err = run_cli([WINDOWS, WEB, "--debug", "--zones", "corp.test", *argv])
    assert code == 0
    debug = [line for line in err.splitlines() if line.startswith("[debug]")]
    assert len(debug) > 5
    text = "\n".join(debug)
    assert not re.search(r"127\.0\.1\.\d+|corp\.test|dc01|intranet", text, re.IGNORECASE)
    assert "IP4-1" in text


def test_shared_ranges_from_local_samples(tmp_path, monkeypatch):
    with open(os.path.join(DATA_DIR, "cloudflare-ips-v4.txt"), encoding="utf-8") as handle:
        networks = ranges.parse_cloudflare(handle.read())
    with open(os.path.join(DATA_DIR, "cloudflare-ips-v6.txt"), encoding="utf-8") as handle:
        networks += ranges.parse_cloudflare(handle.read())
    with open(os.path.join(DATA_DIR, "aws-ip-ranges-excerpt.json"), encoding="utf-8") as handle:
        aws = ranges.parse_aws(handle.read())
    assert aws and all(isinstance(ipaddress.ip_network(item), ipaddress._BaseNetwork)
                       for item in aws)
    path = str(tmp_path / "shared-ranges.txt")
    assert ranges.write_ranges(path, networks + aws) == len(set(networks + aws))
    shared = ranges.load(path)
    first = ipaddress.ip_network(networks[0])
    assert shared.contains(str(first.network_address + 1))
    assert not shared.contains("10.0.0.1") and not shared.contains("2001:db8::1")
    monkeypatch.setattr(ranges, "RANGES_FILE", path)
    run = make_run(["-m", "tls"], ips=[str(first.network_address + 1)])
    from ip2fqdn.common import Finding
    from ip2fqdn.output import build_rows
    run.finding(run.contexts["tls"], Finding(run.inputs.ips[0], "cdn.site.test", "443 CN"))
    assert build_rows(run, ranges.load())[0]["labels"] == "shared"


@settings(max_examples=200, deadline=None)
@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=20),
                    lambda children: st.lists(children, max_size=4) |
                    st.dictionaries(st.sampled_from(["hostnames", "data", "ssl", "chain",
                                                     "cert", "subject", "CN", "hostname",
                                                     "reverse", "port", "timestamp", "ip"]),
                                    children, max_size=5), max_leaves=20))
def test_api_field_extraction_never_crashes(document):
    if isinstance(document, dict):
        shodan.host_findings("8.8.8.8", document)
        onyphe.document_findings("8.8.8.8", document)
        for banner in document.get("data") or [] if isinstance(document.get("data"),
                                                                list) else []:
            shodan.banner_findings("8.8.8.8", banner)


@settings(max_examples=150, deadline=None)
@given(st.binary(max_size=300), st.integers(min_value=0, max_value=4000))
def test_nmap_reader_never_crashes(noise, cut):
    with open(os.path.join(DATA_DIR, "nmap-windows-domain.xml"), "rb") as handle:
        data = handle.read()
    for sample in (data[:cut], data[:cut] + noise, noise):
        result = nmapxml.read_xml(io.BytesIO(sample))
        assert result.kind in ("nmap", "masscan", "not-nmap", "refused")


def test_certificate_names_hostile():
    assert certs.der_names(b"") is None
    assert certs.der_names(b"\x30\x03\x02\x01\x01") is None
    assert certs.pem_names("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----") \
        is None
    der = fakes.make_cert("a.test", ["b.test", "*.c.test"])[2]
    names = certs.der_names(der)
    assert names == [("a.test", "CN"), ("b.test", "SAN"), ("*.c.test", "SAN")]
    assert certs.matches(names, "x.c.test") and not certs.matches(names, "x.y.c.test")


def test_list_methods_help_and_version():
    code, out, _ = run_cli(["--list-methods"])
    assert code == 0 and len(out.splitlines()) == 21
    assert out.splitlines()[0].startswith("tls         on  active phase 1")
    stream = io.StringIO()
    cli.build_parser().print_help(stream)
    help_text = stream.getvalue()
    assert "--tls-ports LIST" in help_text and "--sni-ports" not in help_text
    assert "--shodan-search" in help_text and "--mdns-ports" in help_text


def test_open_file_limit_lowers_parallel(monkeypatch):
    import resource
    run = make_run(["--parallel", "5000"])
    monkeypatch.setattr(resource, "getrlimit", lambda kind: (1024, 1024))
    monkeypatch.setattr(resource, "setrlimit", lambda kind, value: None)
    cli._raise_file_limit(run.args, None, run.log)
    assert run.args.parallel == 924
    assert "--parallel lowered from 5000 to 924" in run.log.stream.getvalue()


def test_csv_output_parses_back(lab):  # noqa: F811
    argv, _, _ = lab
    code, out, _ = run_cli([WEB, "-m", "tls,http", *argv])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert code == 0 and {row["source"] for row in rows} == {"tls", "http"}
    assert json.dumps(rows)


def test_ipv6_probes_on_loopback():
    from ip2fqdn.methods import tls as tls_method
    cert = fakes.make_cert("v6.corp.test")
    with fakes.FakeNetwork() as network:
        context = fakes.server_context(cert)
        port = network.tcp("::1", 0, fakes.tls_handler(context), context)
        found, _ = lookup(tls_method, "::1", port)
        code, out, _ = run_cli(["::1", "-m", "tls", f"--tls-ports={port}"])
    assert [f.name for f in found] == ["v6.corp.test"]
    assert code == 0 and "::1,v6.corp.test,tls" in out
