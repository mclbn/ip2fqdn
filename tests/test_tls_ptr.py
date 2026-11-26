import asyncio

import fakes
from helpers import lookup, make_run, run_cli

from ip2fqdn import dnsclient
from ip2fqdn.methods import tls


def test_tls_names_without_sni():
    cert = fakes.make_cert("web01.corp.example", ["web01.corp.example", "www.corp.example"])
    seen = []
    with fakes.FakeNetwork() as network:
        context = fakes.server_context(cert, seen=seen)
        port = network.tcp("127.0.1.20", 0, fakes.tls_handler(context), context)
        found, ctx = lookup(tls, "127.0.1.20", port)
    assert seen == [None]
    assert [(f.name, f.detail) for f in found] == [
        ("web01.corp.example", f"{port} CN"), ("web01.corp.example", f"{port} SAN"),
        ("www.corp.example", f"{port} SAN")]
    assert ctx.run.results.tls_ports == {"127.0.1.20": {port}}


def test_tls_unreadable_certificate_counted(monkeypatch):
    from ip2fqdn.proto import certs
    cert = fakes.make_cert("x.example.net")
    monkeypatch.setattr(certs, "der_names", lambda der: None)
    with fakes.FakeNetwork() as network:
        context = fakes.server_context(cert)
        port = network.tcp("127.0.1.21", 0, fakes.tls_handler(context), context)
        found, ctx = lookup(tls, "127.0.1.21", port)
    assert found == [] and ctx.counts["certificates unreadable"] == 1


def test_ptr_every_server_and_forward_confirmation():
    first = fakes.FakeDns({("10.1.0.127.in-addr.arpa", "PTR"): ["dc01.corp.test."],
                           ("dc01.corp.test", "A"): ["127.0.1.10"]})
    second = fakes.FakeDns({("10.1.0.127.in-addr.arpa", "PTR"): ["dc01.corp.test.",
                                                                  "old.corp.test."],
                            ("old.corp.test", "CNAME"): ["other.corp.test."],
                            ("other.corp.test", "A"): ["127.0.1.99"]})
    with fakes.FakeNetwork() as network:
        port = fakes.start_dns(network, "127.0.1.53", first)
        fakes.start_dns(network, "127.0.1.54", second, port)
        code, out, err = run_cli(["127.0.1.10", "-m", "ptr", "--dns-server",
                                  f"127.0.1.53:{port},127.0.1.54:{port}"])
    assert code == 0, err
    lines = out.splitlines()
    assert lines[0] == ("ip,fqdn,source,detail,name_kind,labels,dns,sni,first_seen,last_seen")
    rows = [line.split(",") for line in lines[1:]]
    assert [(r[1], r[3], r[6]) for r in rows] == [
        ("dc01.corp.test", f"PTR @127.0.1.53:{port}; PTR @127.0.1.54:{port}", "match"),
        ("old.corp.test", f"PTR @127.0.1.54:{port}", "other")]
    assert "ptr: 1 IPs, 2 rows" in err


def test_dns_server_dropped_after_unanswered_queries():
    silent = fakes.FakeDns(silent=True)

    async def go(port):
        server = dnsclient.DnsServer("127.0.1.55", port)
        run = make_run(["-m", "ptr"])
        service = dnsclient.DnsService([server], run.log)
        dnsclient.ATTEMPT_TIMEOUT = 0.05
        replies = await asyncio.gather(*(service.query(server, f"n{i}.test", "A")
                                         for i in range(25)))
        return replies, server, run.log.stream.getvalue()

    saved = dnsclient.ATTEMPT_TIMEOUT
    try:
        with fakes.FakeNetwork() as network:
            port = fakes.start_dns(network, "127.0.1.55", silent)
            replies, server, text = asyncio.run(go(port), debug=True)
    finally:
        dnsclient.ATTEMPT_TIMEOUT = saved
    assert replies == [None] * 25
    assert server.dropped and "20 queries in a row unanswered" in text
