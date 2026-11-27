import asyncio
import base64

import fakes
import ntlm_vectors
import pytest
from helpers import lookup
from hypothesis import given, settings
from hypothesis import strategies as st

from ip2fqdn.methods import http, http_ntlm, netbios, rdp, smtp
from ip2fqdn.proto import http as http_proto

NETBIOS_REPLY = bytes.fromhex(
    "13378400000000010000000020434b4141414141414141414141414141414141414141414141414141414141"
    "4100002100010000000000890557494e2d5352563031202020202020000400434f5250202020202020202020"
    "202000840057494e2d5352563031202020202020200400434f525020202020202020202020201c8400434f52"
    "5020202020202020202020201b040000155d0102030000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000")


def _serve(network, host, handler, ssl_context=None):
    return network.tcp(host, 0, handler, ssl_context)


def rdp_server(cert, reply):
    async def handle(reader, writer):
        try:
            await reader.readexactly(19)
            writer.write(reply)
            await writer.drain()
            if reply[11:12] == b"\x02":
                await writer.start_tls(fakes.server_context(cert))
                await reader.read(10)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    return handle


def test_rdp_certificate_after_negotiation():
    cert = fakes.make_cert("TS01.corp.test")
    hybrid = bytes.fromhex("030000130ed00000123400021f080008000000")
    failure = bytes.fromhex("030000130ed000001234000300080002000000")
    with fakes.FakeNetwork() as network:
        good = _serve(network, "127.0.1.40", rdp_server(cert, hybrid))
        bad = _serve(network, "127.0.1.41", rdp_server(cert, failure))
        found, _ = lookup(rdp, "127.0.1.40", good)
        nothing, _ = lookup(rdp, "127.0.1.41", bad)
    assert [(f.name, f.detail) for f in found] == [("TS01.corp.test", f"{good} RDP CN")]
    assert nothing == []
    assert rdp.selected_protocol(bytes.fromhex("030000130ed00000123400020008000000000000")[:19]) \
        == 0
    assert rdp.selected_protocol(bytes.fromhex("0300000b06d00000123400")) == 0
    assert rdp.selected_protocol(b"\x03\x00\x00\x13garbage-garbage") is None


def http_server(head):
    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(head)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    return handle


def test_http_location_names():
    head = (b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
            b"HTTP/1.1 301 Moved\r\nLocation: http://Portal.Corp.Test./login\r\n"
            b"location: //cdn.corp.test/x\r\nX-Folded: a\r\n b\r\n\r\nbody")
    with fakes.FakeNetwork() as network:
        port = _serve(network, "127.0.1.42", http_server(head))
        found, _ = lookup(http, "127.0.1.42", port)
    assert [(f.name, f.detail) for f in found] == [
        ("portal.corp.test", f"{port} Location (301)"),
        ("cdn.corp.test", f"{port} Location (301)")]


def test_location_rules():
    base = "http://192.0.2.10/"
    values = ["/login", "http://user:pw@evil.test/", "http://10.0.0.1/", "ftp://x.test/",
              "http://host.test:99999/", "https://[2001:db8::1]/", "http://ok.test/"]
    assert http.location_names(values, base) == ["host.test", "ok.test"]


def test_http_head_limits():
    async def go(data):
        reader = asyncio.StreamReader(limit=64 * 1024)
        reader.feed_data(data)
        reader.feed_eof()
        return await http_proto.read_response(reader)
    many = b"HTTP/1.1 302 Found\r\n" + b"X: y\r\n" * 150 + b"Location: /late\r\n\r\n"
    status, fields = asyncio.run(go(many), debug=True)
    assert status == 302 and "location" not in fields
    assert asyncio.run(go(b"SSH-2.0-OpenSSH\r\n"), debug=True) is None
    assert asyncio.run(go(b"HTTP/1.0 200 OK\r\n\r\n"), debug=True) == (200, {})


def test_http_ntlm_exchange_paths_stop_at_first_challenge():
    token = base64.b64encode(ntlm_vectors.windows_challenge("EX01")).decode()
    paths = []

    async def handle(reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            path = request.split(b" ")[1].decode()
            paths.append(path)
            if path == "/Autodiscover/Autodiscover.xml":
                writer.write(f"HTTP/1.1 401 x\r\nWWW-Authenticate: NTLM {token}\r\n\r\n"
                             .encode())
            else:
                writer.write(b"HTTP/1.1 404 x\r\n\r\n")
            await writer.drain()
        finally:
            writer.close()

    with fakes.FakeNetwork() as network:
        port = _serve(network, "127.0.1.43", handle)
        found, ctx = lookup(http_ntlm, "127.0.1.43", port)
    assert paths == ["/EWS/", "/Autodiscover/Autodiscover.xml"]
    assert [f.name for f in found] == ["EX01.corp.test", "EX01"]
    assert ctx.run.results.zone_candidates == ["corp.test"]
    assert http_ntlm.requests_for(5985)[0][:2] == ("POST", "/wsman")


smtp_server = fakes.script_server


def test_smtp_full_session_with_starttls():
    cert = fakes.make_cert("mx.corp.test", ["mx.corp.test", "smtp.corp.test"])
    script = [(None, b"220-mx.corp.test ESMTP teaser\r\n"), (None, 0.3),
              (None, b"220 mx.corp.test ESMTP\r\n"),
              (b"EHLO [127.0.0.1]", (b"250-mail.corp.test hello\r\n250-SIZE 1000\r\n"
                                     b"250 STARTTLS\r\n")),
              (b"STARTTLS", b"220 go ahead\r\n"), (None, "TLS"),
              (b"EHLO [127.0.0.1]", b"250-mail.corp.test hello\r\n250 SIZE 1000\r\n"),
              (b"QUIT", b"221 bye\r\n")]
    with fakes.FakeNetwork() as network:
        port = _serve(network, "127.0.1.44", smtp_server(script, cert))
        found, _ = lookup(smtp, "127.0.1.44", port)
    assert [(f.name, f.detail) for f in found] == [
        ("mx.corp.test", f"{port} greeting"), ("mail.corp.test", f"{port} EHLO"),
        ("mx.corp.test", f"{port} STARTTLS CN"), ("mx.corp.test", f"{port} STARTTLS SAN"),
        ("smtp.corp.test", f"{port} STARTTLS SAN")]


def test_smtp_rejecting_greeting_and_limits():
    rejecting = [(None, b"554 mx2.corp.test not accepting messages\r\n"),
                 (b"QUIT", b"221 bye\r\n")]
    flood = [(None, b"220-x.corp.test\r\n" * 150)]
    literal = [(None, b"220 [192.0.2.1] ready\r\n"), (b"EHLO", b"500 no\r\n")]
    with fakes.FakeNetwork() as network:
        first = _serve(network, "127.0.1.45", smtp_server(rejecting))
        second = _serve(network, "127.0.1.46", smtp_server(flood))
        third = _serve(network, "127.0.1.47", smtp_server(literal))
        found, _ = lookup(smtp, "127.0.1.45", first)
        flooded, ctx = lookup(smtp, "127.0.1.46", second)
        none, _ = lookup(smtp, "127.0.1.47", third)
    assert [(f.name, f.detail) for f in found] == [("mx2.corp.test", f"{first} greeting")]
    assert flooded == [] and ctx.counts["sessions over the read limit"] == 1
    assert none == []


def test_netbios_node_status():
    def respond(data, address):
        transaction = data[:2]
        return [transaction + NETBIOS_REPLY[2:]]

    with fakes.FakeNetwork() as network:
        port = network.udp("127.0.1.48", 0, respond)
        found, _ = lookup(netbios, "127.0.1.48", port)
    assert [(f.name, f.detail) for f in found] == [
        ("WIN-SRV01", f"{port} NetBIOS <00>, workgroup or domain CORP, MAC 00:15:5d:01:02:03")]


def test_netbios_closed_port_fails_fast():
    port = fakes.free_port("127.0.1.49")
    with pytest.raises(ConnectionRefusedError):
        lookup(netbios, "127.0.1.49", port)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=300), st.integers(min_value=0, max_value=193))
def test_netbios_parser_never_crashes(noise, cut):
    for data in (noise, NETBIOS_REPLY[:cut], NETBIOS_REPLY[:cut] + noise,
                 NETBIOS_REPLY[:56] + bytes([255]) + noise):
        result = netbios.parse_reply(data, 0x1337)
        assert result is None or isinstance(result, tuple)


def test_netbios_request_bytes():
    assert netbios.request(0x1337).hex() == (
        "13370000000100000000000020434b41414141414141414141414141414141414141414141414141414141"
        "41410000210001")
